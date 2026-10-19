package scan

// Container expansion.
//
// A repack payload rarely sits loose in the game folder — it is packed inside
// an archive that is often several GB and almost always has a nested
// directory layout ("setup/bin/payload.exe"). Two defects are fixed here:
//
//  1. Only TOP-LEVEL files of an extracted archive were scanned, so anything
//     inside a subdirectory of the archive was invisible. The old code used
//     os.ReadDir(dest) and skipped every entry that was not a regular file,
//     which also aborted the whole expansion (n == 0 -> return) before the
//     "container_expanded" finding was ever emitted.
//
//  2. The extraction budget was applied AFTER 7-Zip had already written
//     everything to the temp volume, so a 30 GB repack could fill the disk
//     before any budget check ran. The archive is now listed first and the
//     projected on-disk size is checked before anything is written.
//
// The walk is recursive and every inner finding is reported with its path
// relative to the archive root, so the user sees exactly where inside the
// container the payload was.

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gamecrack-scanner/internal/filetype"
	"gamecrack-scanner/internal/model"
)

const (
	archiveListTimeout    = 180 * time.Second
	archiveExtractTimeout = 900 * time.Second
	// hardCapFactor bounds the on-disk growth of a single container. A
	// container projected above ExtractMaxMB*hardCapFactor is not expanded
	// at all — the user gets an actionable finding instead of a full disk.
	hardCapFactor = 4
	// maxInnerFiles caps how many inner files are scanned per container.
	maxInnerFiles = 3000
	// maxInnerFileMB caps a single inner file.
	maxInnerFileMB = 512
)

// archiveEntry is one extractable file inside a container.
type archiveEntry struct {
	rel  string
	size int64
}

// containerOutcome is what the expansion learned about a container.
type containerOutcome struct {
	Expanded   bool
	Method     string
	FileCount  int
	TotalBytes int64
	MaxScore   int
	MaxVerdict model.Verdict
	TopPath    string
	Truncated  bool
	Reason     string
	Nested     []model.Finding
}

// planArchive lists the container's extractable entries and returns the
// projected on-disk size. ok=false means the container could not be listed
// (encrypted, split volume, unsupported format).
func (s *Scanner) planArchive(path string) (entries []archiveEntry, total int64, ok bool) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".zip" {
		return s.planZip(path)
	}
	return s.plan7z(path)
}

func (s *Scanner) planZip(path string) ([]archiveEntry, int64, bool) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, 0, false
	}
	defer zr.Close()
	var entries []archiveEntry
	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.FileInfo().Size() > maxInnerFileMB*1024*1024 {
			continue
		}
		if !wantExt(f.Name) {
			continue
		}
		entries = append(entries, archiveEntry{rel: f.Name, size: int64(f.FileInfo().Size())})
		total += int64(f.FileInfo().Size())
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].rel < entries[b].rel })
	return entries, total, true
}

// plan7z uses "7z l -slt" to enumerate the archive without extracting it.
//
// NOTE: the -i! include filters are deliberately NOT passed to "l". 7-Zip's
// list and extract commands treat -i! differently: on "x" repeated -i! acts
// as an include-list (only the named extensions are pulled out), but on "l"
// the same switches filter the listing down to nothing. Listing is therefore
// done unfiltered and the extension filter is applied here in Go, which is
// also the only way to get a reliable projected size.
func (s *Scanner) plan7z(path string) ([]archiveEntry, int64, bool) {
	bin := find7z()
	if bin == "" {
		return nil, 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), archiveListTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "l", "-slt", "-y", path).Output()
	if err != nil && len(out) == 0 {
		return nil, 0, false
	}
	abs, _ := filepath.Abs(path)
	var entries []archiveEntry
	var total int64
	var curName string
	var curSize int64
	var curIsDir bool
	flush := func() {
		if curName == "" {
			return
		}
		// Skip the archive header block (its "Path" is the archive itself).
		if !curIsDir && !strings.EqualFold(curName, abs) && !strings.EqualFold(curName, path) {
			if wantExt(curName) && curSize <= maxInnerFileMB*1024*1024 {
				entries = append(entries, archiveEntry{rel: curName, size: curSize})
				total += curSize
			}
		}
		curName, curSize, curIsDir = "", 0, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "Path = "):
			flush()
			curName = strings.TrimPrefix(line, "Path = ")
		case strings.HasPrefix(line, "Size = "):
			curSize, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "Size = ")), 10, 64)
		case strings.HasPrefix(line, "Folder = "):
			curIsDir = strings.Contains(line, "+")
		case strings.HasPrefix(line, "Attributes = "):
			// 7-Zip 26 marks directories with "Attributes = D".
			if strings.Contains(line, " D") {
				curIsDir = true
			}
		}
	}
	flush()
	sort.Slice(entries, func(a, b int) bool { return entries[a].rel < entries[b].rel })
	return entries, total, true
}

// includeFilters returns the 7-Zip include filters for the extractable set.
//
// Two 7-Zip subtleties are encoded here:
//
//  1. The "r" flag is REQUIRED. "-i!*.exe" without it disables recursion, so
//     only the archive's top level is processed and a payload at
//     "setup/bin/payload.exe" is never extracted ("No files to process").
//     "-ir!*.exe" recurses.
//
//  2. On the extract command, repeated -i! switches act as an include-list:
//     only the named extensions are pulled out of the archive. (The list
//     command behaves differently — see plan7z.)
func includeFilters() []string {
	out := make([]string, 0, len(extractableExts))
	for _, e := range extractableExts {
		out = append(out, "-ir!*."+e)
	}
	return out
}

// expandContainer expands one container and merges the result into res.
func (s *Scanner) expandContainer(path string, depth int, res *model.FileResult) {
	out := s.expandContainerInner(path, depth)

	if out.Expanded {
		det := fmt.Sprintf("%s container: scanned %d inner file(s) (%s)", out.Method, out.FileCount, humanMB(out.TotalBytes))
		if out.Truncated {
			det += " — budget reached, scan truncated"
		}
		res.Findings = append(res.Findings, model.Finding{
			Rule: "container_expanded", Category: "container", Severity: 0, Detail: det,
		})
	} else if out.Reason != "" {
		res.Findings = append(res.Findings, model.Finding{
			Rule: "container_not_expanded", Category: "container", Severity: 2, Detail: out.Reason,
		})
	}

	// Every inner finding is reported with its path inside the container.
	res.Findings = append(res.Findings, out.Nested...)

	if out.MaxScore > 0 {
		where := out.TopPath
		if where == "" {
			where = "?"
		}
		res.Findings = append(res.Findings, model.Finding{
			Rule:     "nested_worst",
			Category: "container",
			Severity: 0,
			Detail:   "worst member of container: " + where + " -> " + out.MaxVerdict.String() + " (" + strconv.Itoa(out.MaxScore) + ")",
		})
		// A container is only as clean as its worst member.
		if out.MaxVerdict > res.Verdict || (out.MaxScore > res.Score && out.MaxVerdict == res.Verdict) {
			res.Score = out.MaxScore
			res.Verdict = out.MaxVerdict
		}
	}
}

func (s *Scanner) expandContainerInner(path string, depth int) containerOutcome {
	var out containerOutcome
	if s.tmp == "" {
		out.Reason = "container expansion disabled (no temp dir)"
		return out
	}
	if filetype.IsFreeArc(path) {
		out.Reason = "FreeArc container (repack installer data) — needs the FreeArc CLI or the repack's own setup.exe -extract; the sibling installer is scanned separately"
		return out
	}
	if !filetype.IsContainerExt(path) {
		out.Reason = "not a recognised container format"
		return out
	}

	entries, projected, ok := s.planArchive(path)
	if !ok {
		out.Reason = "container could not be listed (encrypted, split volume, or unsupported format)"
		return out
	}
	if len(entries) == 0 {
		out.Reason = "container holds no extractable files (exe/dll/script/config set)"
		return out
	}

	limit := s.cfg.ExtractMaxMB * 1024 * 1024
	hardCap := limit * hardCapFactor
	if projected > hardCap {
		out.Reason = fmt.Sprintf("container projects to %s of inner files — above the %s budget, not expanded. Raise -extract-mb or point -tmp-dir at a volume with free space",
			humanMB(projected), humanMB(s.cfg.ExtractMaxMB))
		return out
	}
	if projected > limit {
		out.Truncated = true
	}

	dest := filepath.Join(s.tmp, fmt.Sprintf("c%d_%d", depth, atomic.AddInt64(&containerSeq, 1)))
	if err := os.MkdirAll(dest, 0o755); err != nil {
		out.Reason = "temp dir error: " + err.Error()
		return out
	}
	method, err := s.extractTo(path, dest)
	if err != nil {
		out.Reason = method + " extraction failed: " + err.Error()
		return out
	}
	out.Expanded = true
	out.Method = method

	// Recursive walk: this is the fix for nested archive layouts.
	var budget int64
	count := 0
	walkErr := filepath.WalkDir(dest, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if info.Size() > s.cfg.MaxSizeMB*1024*1024 {
			return nil
		}
		rel, rerr := filepath.Rel(dest, p)
		if rerr != nil {
			rel = d.Name()
		}
		rel = filepath.ToSlash(rel)
		budget += info.Size()
		out.TotalBytes += info.Size()
		out.FileCount++
		count++
		if budget > limit || count > maxInnerFiles {
			out.Truncated = true
			return filepath.SkipAll
		}
		sub := s.scanFile(p, depth+1, false)
		if sub.Score > 0 || sub.Verdict != model.VerdictClean {
			out.Nested = append(out.Nested, model.Finding{
				Rule:     "nested_result",
				Category: "container",
				Severity: sub.Score,
				Detail:   rel + " -> " + sub.Verdict.String() + " (" + strconv.Itoa(sub.Score) + ")",
			})
		}
		if sub.Score > out.MaxScore {
			out.MaxScore = sub.Score
			out.MaxVerdict = sub.Verdict
			out.TopPath = rel
		}
		return nil
	})
	if walkErr != nil {
		out.Truncated = true
	}
	return out
}

// extractTo extracts the container into dest and returns the method used.
func (s *Scanner) extractTo(path, dest string) (string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".zip" {
		if err := extractZip(path, dest); err != nil {
			return "zip", err
		}
		return "zip", nil
	}
	bin := find7z()
	if bin == "" {
		return "7z", fmt.Errorf("7-Zip binary not found (needed for %s containers)", ext)
	}
	args := []string{"x", "-y", "-aoa", "-o" + dest}
	args = append(args, includeFilters()...)
	args = append(args, path)
	ctx, cancel := context.WithTimeout(context.Background(), archiveExtractTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "7z", err
	}
	return "7z", nil
}

// extractZip expands a zip with the stdlib reader (no external binary).
func extractZip(path, dest string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.FileInfo().Size() > maxInnerFileMB*1024*1024 {
			continue
		}
		if !wantExt(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		rel := filepath.FromSlash(f.Name)
		// Zip-slip guard: never write outside the destination directory.
		out := filepath.Join(dest, rel)
		if !strings.HasPrefix(strings.ToLower(out), strings.ToLower(dest)+string(os.PathSeparator)) {
			rc.Close()
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			rc.Close()
			continue
		}
		w, err := os.Create(out)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(w, io.LimitReader(rc, 512<<20))
		w.Close()
		rc.Close()
	}
	return nil
}
