package scan

// Container expansion.
//
// A repack payload rarely sits loose in the game folder — it is packed inside
// an archive that is often several GB and almost always has a nested
// directory layout ("setup/bin/payload.exe").
//
// Capabilities:
//   - Recursive walk reporting inner findings with paths relative to the archive
//   - Pre-extract listing and disk-budget enforcement before writing anything
//   - Encrypted/password-protected archive detection (common web-dropper trick)
//   - Decoy web-game archive heuristics (e.g., Ren'Py SDK without game/ + encrypted blob)
//   - Multi-volume archive awareness (.part2.rar, .r00, .z01, .002)
//   - Optional FreeArc (fg-*.bin) shim when Arc.exe / unarc is installed
//   - Magic-byte container support even if renamed to a non-archive extension

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
	"gamecrack-scanner/internal/procutil"
)

const (
	archiveListTimeout    = 180 * time.Second
	archiveExtractTimeout = 900 * time.Second
	hardCapFactor         = 4
	maxInnerFiles         = 3000
	maxInnerFileMB        = 512
)

// archiveEntry is one extractable file inside a container.
type archiveEntry struct {
	rel       string
	size      int64
	encrypted bool
}

// archivePlan summarizes the archive structure learned before extraction.
type archivePlan struct {
	entries    []archiveEntry // filtered extractable entries
	allEntries []archiveEntry // all file entries (for decoy/structural checks)
	total      int64
	encrypted  bool
	ok         bool
}

// containerOutcome is what the expansion learned about a container.
type containerOutcome struct {
	Expanded     bool
	Method       string
	FileCount    int
	TotalBytes   int64
	MaxScore     int
	MaxVerdict   model.Verdict
	TopPath      string
	Truncated    bool
	Reason       string
	MultiVolSkip bool
	Extra        []model.Finding
	Nested       []model.Finding
}

// planArchive lists the container's extractable entries and returns the
// projected on-disk size. ok=false means the container could not be listed.
func (s *Scanner) planArchive(path string) (entries []archiveEntry, total int64, ok bool) {
	p := s.planArchiveFull(path)
	return p.entries, p.total, p.ok
}

func (s *Scanner) planArchiveFull(path string) archivePlan {
	ext := strings.ToLower(filepath.Ext(path))
	fmtMagic := filetype.ArchiveFormat(path)
	if ext == ".zip" || fmtMagic == "zip" {
		if p := s.planZip(path); p.ok {
			return p
		}
	}
	if fmtMagic == "freearc" || filetype.IsFreeArc(path) {
		return s.planFreeArc(path)
	}
	return s.plan7z(path)
}

func (s *Scanner) planZip(path string) archivePlan {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return archivePlan{}
	}
	defer zr.Close()
	var p archivePlan
	p.ok = true
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		enc := (f.Flags & 0x1) != 0
		if enc {
			p.encrypted = true
		}
		sz := int64(f.FileInfo().Size())
		ae := archiveEntry{rel: filepath.ToSlash(f.Name), size: sz, encrypted: enc}
		p.allEntries = append(p.allEntries, ae)
		if sz > maxInnerFileMB*1024*1024 {
			continue
		}
		if !wantExt(f.Name) {
			continue
		}
		p.entries = append(p.entries, ae)
		p.total += sz
	}
	sort.Slice(p.entries, func(a, b int) bool { return p.entries[a].rel < p.entries[b].rel })
	return p
}

// plan7z uses "7z l -slt" to enumerate the archive without extracting it.
func (s *Scanner) plan7z(path string) archivePlan {
	bin := find7z()
	if bin == "" {
		return archivePlan{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), archiveListTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "l", "-slt", "-y", "-p", path)
	procutil.HideWindow(cmd)
	out, err := cmd.CombinedOutput()
	lowOut := strings.ToLower(string(out))
	var p archivePlan
	if strings.Contains(lowOut, "wrong password") || strings.Contains(lowOut, "can not open encrypted archive") || strings.Contains(lowOut, "enter password") {
		p.encrypted = true
	}
	if err != nil && len(out) == 0 {
		return p
	}
	abs, _ := filepath.Abs(path)
	var curName string
	var curSize int64
	var curIsDir bool
	var curEnc bool
	flush := func() {
		if curName == "" {
			return
		}
		if !curIsDir && !strings.EqualFold(curName, abs) && !strings.EqualFold(curName, path) {
			ae := archiveEntry{rel: filepath.ToSlash(curName), size: curSize, encrypted: curEnc}
			p.allEntries = append(p.allEntries, ae)
			if curEnc {
				p.encrypted = true
			}
			if wantExt(curName) && curSize <= maxInnerFileMB*1024*1024 {
				p.entries = append(p.entries, ae)
				p.total += curSize
			}
		}
		curName, curSize, curIsDir, curEnc = "", 0, false, false
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
		case strings.HasPrefix(line, "Encrypted = "):
			if strings.Contains(line, "+") {
				curEnc = true
				p.encrypted = true
			}
		case strings.HasPrefix(line, "Attributes = "):
			if strings.Contains(line, " D") {
				curIsDir = true
			}
		}
	}
	flush()
	if len(p.allEntries) > 0 || err == nil {
		p.ok = true
	}
	sort.Slice(p.entries, func(a, b int) bool { return p.entries[a].rel < p.entries[b].rel })
	return p
}

// planFreeArc lists a FreeArc (.bin / fg-*.bin) container when Arc/unarc CLI is installed.
func (s *Scanner) planFreeArc(path string) archivePlan {
	bin := findFreeArc()
	if bin == "" {
		return archivePlan{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), archiveListTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "lb", path)
	procutil.HideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return archivePlan{}
	}
	var p archivePlan
	p.ok = true
	for _, raw := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(raw)
		if name == "" || strings.HasPrefix(name, "FreeArc") || strings.HasPrefix(name, "Listing") || strings.HasPrefix(name, "-") {
			continue
		}
		ae := archiveEntry{rel: filepath.ToSlash(name)}
		p.allEntries = append(p.allEntries, ae)
		if wantExt(name) {
			p.entries = append(p.entries, ae)
		}
	}
	return p
}

func includeFilters() []string {
	out := make([]string, 0, len(extractableExts))
	for _, e := range extractableExts {
		out = append(out, "-ir!*."+e)
	}
	return out
}

// detectDecoyArchiveEntries checks archive structure for known fake web-game
// dropper templates (notably the ovaGames fake Ren'Py SDK bundle: renpy/ +
// setup.py/librenpython.dll with NO game/ dir + a >500KB random-named blob in data/).
func detectDecoyArchiveEntries(entries []archiveEntry) []model.Finding {
	if len(entries) == 0 {
		return nil
	}
	var (
		hasRenpyDir    bool
		hasRenpyLib    bool
		hasGameDir     bool
		hasSetupPy     bool
		suspiciousBlob string
		blobSize       int64
		hasHiddenKey   bool
	)
	for _, e := range entries {
		low := strings.ToLower(strings.TrimPrefix(e.rel, "./"))
		parts := strings.Split(low, "/")
		// Strip optional single top-level wrapper folder.
		rel := low
		if len(parts) >= 2 && (parts[1] == "renpy" || parts[1] == "game" || parts[1] == "data" || parts[1] == "lib" || parts[1] == "setup.py") {
			rel = strings.Join(parts[1:], "/")
		}
		switch {
		case strings.HasPrefix(rel, "renpy/"):
			hasRenpyDir = true
		case strings.Contains(rel, "librenpython.dll"):
			hasRenpyLib = true
		case strings.HasPrefix(rel, "game/"):
			hasGameDir = true
		case rel == "setup.py":
			hasSetupPy = true
		case strings.HasPrefix(rel, "data/"):
			base := filepath.Base(rel)
			if strings.HasPrefix(base, ".") && e.size > 0 && e.size <= 1024 {
				hasHiddenKey = true
			}
			ext := strings.ToLower(filepath.Ext(base))
			if e.size >= 500*1024 && !normalDataExt[ext] {
				suspiciousBlob = e.rel
				blobSize = e.size
			}
		}
	}
	if (hasRenpyDir || hasRenpyLib) && !hasGameDir && (suspiciousBlob != "" || (hasSetupPy && hasHiddenKey)) {
		detail := fmt.Sprintf("decoy Ren'Py SDK game archive: no game/ directory, carries suspicious encrypted blob %q (%s)",
			suspiciousBlob, humanMB(blobSize))
		if hasHiddenKey {
			detail += " + hidden key file in data/"
		}
		return []model.Finding{{
			Rule:     "decoy_renpy_dropper",
			Category: "dropper",
			Severity: 75,
			Detail:   detail,
		}}
	}
	return nil
}

var normalDataExt = map[string]bool{
	".pak": true, ".rpa": true, ".rpy": true, ".rpyc": true, ".png": true,
	".jpg": true, ".jpeg": true, ".ogg": true, ".wav": true, ".mp3": true,
	".mp4": true, ".webm": true, ".ttf": true, ".otf": true, ".json": true,
	".txt": true, ".xml": true, ".bin": true, ".dat": true, ".zip": true,
}

// expandContainer expands one container and merges the result into res.
func (s *Scanner) expandContainer(path string, depth int, res *model.FileResult) {
	out := s.expandContainerInner(path, depth)

	if out.MultiVolSkip {
		res.Findings = append(res.Findings, model.Finding{
			Rule:     "container_multivolume_part",
			Category: "container",
			Severity: 0,
			Detail:   out.Reason,
		})
		return
	}

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

	// Structural archive findings (encrypted archive, decoy Ren'Py dropper, etc.).
	if len(out.Extra) > 0 {
		res.Findings = append(res.Findings, out.Extra...)
		extraScore := 0
		for _, f := range out.Extra {
			extraScore += f.Severity
		}
		newScore := res.Score + extraScore
		if newScore > 100 {
			newScore = 100
		}
		if newScore > res.Score {
			res.Score = newScore
			if res.Score >= 70 {
				res.Verdict = model.VerdictMalicious
			} else if res.Score >= 30 && res.Verdict == model.VerdictClean {
				res.Verdict = model.VerdictSuspicious
			}
		}
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
	if filetype.IsSecondaryMultiVolume(path) {
		out.MultiVolSkip = true
		out.Reason = "secondary multi-volume archive part — scanned together with volume 1"
		return out
	}
	if s.tmp == "" {
		out.Reason = "container expansion disabled (no temp dir)"
		return out
	}
	isFreeArc := filetype.IsFreeArc(path)
	if isFreeArc && findFreeArc() == "" {
		out.Reason = "FreeArc container (repack installer data) — install FreeArc CLI (Arc.exe) to inspect inside, or scan the sibling setup.exe separately"
		return out
	}
	if !filetype.IsExpandableContainer(path) {
		out.Reason = "not a recognised container format"
		return out
	}

	plan := s.planArchiveFull(path)
	if plan.encrypted {
		out.Extra = append(out.Extra, model.Finding{
			Rule:     "archive_encrypted",
			Category: "evasion",
			Severity: 25,
			Detail:   "password-protected archive — web malware droppers commonly encrypt archives (e.g. pass '1234') to bypass antivirus inspection",
		})
	}
	if len(plan.allEntries) > 0 {
		out.Extra = append(out.Extra, detectDecoyArchiveEntries(plan.allEntries)...)
	}
	if !plan.ok {
		if plan.encrypted {
			out.Reason = "container header is encrypted (password-protected)"
		} else {
			out.Reason = "container could not be listed (encrypted, split volume, or unsupported format)"
		}
		return out
	}
	if len(plan.entries) == 0 {
		out.Reason = "container holds no extractable files (exe/dll/script/config set)"
		return out
	}

	limit := s.cfg.ExtractMaxMB * 1024 * 1024
	hardCap := limit * hardCapFactor
	if plan.total > hardCap {
		out.Reason = fmt.Sprintf("container projects to %s of inner files — above the %s budget, not expanded. Raise -extract-mb or point -tmp-dir at a volume with free space",
			humanMB(plan.total), humanMB(limit))
		return out
	}
	if plan.total > limit {
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

	var budget int64
	count := 0
	walkErr := filepath.WalkDir(dest, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
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
	fmtMagic := filetype.ArchiveFormat(path)
	if ext == ".zip" || fmtMagic == "zip" {
		if err := extractZip(path, dest); err == nil {
			return "zip", nil
		}
		// Fall through to 7z if zip uses unsupported compression method (e.g. Deflate64/LZMA).
	}
	if fmtMagic == "freearc" || filetype.IsFreeArc(path) {
		bin := findFreeArc()
		if bin == "" {
			return "freearc", fmt.Errorf("FreeArc CLI not found")
		}
		ctx, cancel := context.WithTimeout(context.Background(), archiveExtractTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "x", "-y", "-o+", "-dp"+dest, path)
		procutil.HideWindow(cmd)
		if err := cmd.Run(); err != nil {
			return "freearc", err
		}
		return "freearc", nil
	}
	if bin := find7z(); bin != "" {
		args := []string{"x", "-y", "-aoa", "-p", "-o" + dest}
		args = append(args, includeFilters()...)
		args = append(args, path)
		ctx, cancel := context.WithTimeout(context.Background(), archiveExtractTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		procutil.HideWindow(cmd)
		if err := cmd.Run(); err == nil {
			return "7z", nil
		}
		// Fallback to UnRAR for newer RAR5 archives if 7z struggled.
		if ext == ".rar" || fmtMagic == "rar" {
			if unrar := findUnRAR(); unrar != "" {
				ctx2, cancel2 := context.WithTimeout(context.Background(), archiveExtractTimeout)
				defer cancel2()
				cmd2 := exec.CommandContext(ctx2, unrar, "x", "-y", "-o+", "-p-", path, dest+string(os.PathSeparator))
				procutil.HideWindow(cmd2)
				if err2 := cmd2.Run(); err2 == nil {
					return "unrar", nil
				}
			}
		}
		return "7z", fmt.Errorf("7z extraction failed (encrypted or corrupted)")
	}
	if ext == ".rar" || fmtMagic == "rar" {
		if unrar := findUnRAR(); unrar != "" {
			ctx, cancel := context.WithTimeout(context.Background(), archiveExtractTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, unrar, "x", "-y", "-o+", "-p-", path, dest+string(os.PathSeparator))
			procutil.HideWindow(cmd)
			if err := cmd.Run(); err != nil {
				return "unrar", err
			}
			return "unrar", nil
		}
	}
	return "7z", fmt.Errorf("7-Zip binary not found (needed for %s containers)", ext)
}

func findFreeArc() string {
	for _, name := range []string{"Arc", "arc", "unarc", "freearc"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range []string{
		`E:\tools\freearc\Arc.exe`,
		`E:\tools\freearc\unarc.exe`,
		`C:\Program Files (x86)\FreeArc\bin\Arc.exe`,
		`C:\Program Files\FreeArc\bin\Arc.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func findUnRAR() string {
	if p, err := exec.LookPath("unrar"); err == nil {
		return p
	}
	for _, p := range []string{
		`C:\Program Files\WinRAR\UnRAR.exe`,
		`C:\Program Files (x86)\WinRAR\UnRAR.exe`,
		`/usr/bin/unrar`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ExtractorsAvailable reports which external archive extractors are present on this host.
func ExtractorsAvailable() (has7z, hasUnrar, hasFreeArc bool) {
	return find7z() != "", findUnRAR() != "", findFreeArc() != ""
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
		if (f.Flags & 0x1) != 0 {
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
