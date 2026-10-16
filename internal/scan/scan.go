package scan

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gamecrack-scanner/internal/cache"
	"gamecrack-scanner/internal/filetype"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/pe"
	"gamecrack-scanner/internal/rules"
	"gamecrack-scanner/internal/sandbox"
	"gamecrack-scanner/internal/text"
	"gamecrack-scanner/internal/yara"
)

type Config struct {
	Root         string
	Workers      int
	MaxSizeMB    int64
	SkipAssets   bool
	Excludes     []string
	UseCache     bool
	CachePath    string
	Quiet        bool
	FullReadMB   int64
	VerboseHits  bool
	Online       *online.Client
	Yara         *yara.Runner
	ExtractDepth int
	ExtractMaxMB int64
	Detonate     bool
	DetonateMin  int
	DetonatorDir string
	NoUnpack     bool
}

type Scanner struct {
	cfg      Config
	cache    *cache.Cache
	tmp      string
	detMu    sync.Mutex
	detOk    bool
	detFail  bool
	upxMu     sync.Mutex
	upxPath   string
	upxProbed bool
	tmpMu     sync.Mutex
}

var unpackSeq int64

// upxBin resolves the UPX binary once (E:\tools\upx or anywhere in PATH).
func (s *Scanner) upxBin() string {
	s.upxMu.Lock()
	defer s.upxMu.Unlock()
	if !s.upxProbed {
		s.upxProbed = true
		if p, err := exec.LookPath("upx"); err == nil {
			s.upxPath = p
		}
	}
	return s.upxPath
}

func isUPX(packer string) bool {
	return packer == "UPX!" || packer == "UPX0" || packer == "UPX1" ||
		strings.HasPrefix(packer, "UPX")
}

// tryUnpackUPX decompresses a UPX-packed PE to the scanner temp dir.
// Returns "" when upx is missing or decompression fails.
func (s *Scanner) tryUnpackUPX(path string) string {
	bin := s.upxBin()
	if bin == "" {
		return ""
	}
	if s.tmp == "" {
		s.tmpMu.Lock()
		if s.tmp == "" {
			if tmp, err := os.MkdirTemp("", "gc-extract-"); err == nil {
				s.tmp = tmp
			}
		}
		s.tmpMu.Unlock()
		if s.tmp == "" {
			return ""
		}
	}
	out := filepath.Join(s.tmp, fmt.Sprintf("upx%d_%s", atomic.AddInt64(&unpackSeq, 1), filepath.Base(path)))
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-d", "-q", "-o", out, path)
	if err := cmd.Run(); err != nil {
		return ""
	}
	if st, err := os.Stat(out); err != nil || st.Size() == 0 {
		os.Remove(out)
		return ""
	}
	return out
}

func (s *Scanner) detonate(path string) *sandbox.Report {
	s.detMu.Lock()
	defer s.detMu.Unlock()
	if s.detFail {
		return nil
	}
	image := "cracksentinel-detonator"
	if !sandbox.ImageExists(image) {
		dir := s.cfg.DetonatorDir
		if dir == "" {
			dir = "detonator"
		}
		if err := sandbox.BuildImage(image, dir); err != nil {
			s.detFail = true
			fmt.Fprintf(os.Stderr, "warning: detonator image build failed: %v\n", err)
			return nil
		}
	}
	rep, err := sandbox.Detonate(path, image, 150)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: detonation %s: %v\n", path, err)
		return nil
	}
	return rep
}

func behavioralFindings(r *sandbox.Report) []model.Finding {
	var out []model.Finding
	for i, c := range r.Connects {
		if i >= 3 {
			break
		}
		out = append(out, model.Finding{Rule: "behav_network_connect", Category: "behavioral", Severity: 12, Detail: "outbound connect attempt to " + c + " (no external network in sandbox = C2 attempt)"})
	}
	for i, f := range r.FilesDropped {
		if i >= 3 {
			break
		}
		out = append(out, model.Finding{Rule: "behav_file_drop", Category: "behavioral", Severity: 15, Detail: "wrote file: " + f})
	}
	for i, p := range r.ChildProcs {
		if i >= 3 {
			break
		}
		sev := 15
		low := strings.ToLower(p)
		if strings.Contains(low, "powershell") || strings.Contains(low, "cmd") || strings.Contains(low, "wscript") || strings.Contains(low, "cscript") {
			sev = 25
		}
		out = append(out, model.Finding{Rule: "behav_child_process", Category: "behavioral", Severity: sev, Detail: "spawned: " + p})
	}
	if r.StdoutNote != "" {
		out = append(out, model.Finding{Rule: "behav_output", Category: "behavioral", Severity: 0, Detail: r.StdoutNote})
	}
	return out
}

func New(cfg Config) (*Scanner, error) {
	s := &Scanner{cfg: cfg}
	if cfg.ExtractDepth > 0 {
		tmp, err := os.MkdirTemp("", "gc-extract-")
		if err != nil {
			return nil, err
		}
		s.tmp = tmp
	}
	if cfg.UseCache {
		c, err := cache.Open(cfg.CachePath)
		if err != nil {
			return nil, err
		}
		s.cache = c
	}
	return s, nil
}

func (s *Scanner) Close() {
	if s.cache != nil {
		s.cache.Close()
	}
	if s.cfg.Yara != nil {
		s.cfg.Yara.Close()
	}
	if s.tmp != "" {
		os.RemoveAll(s.tmp)
	}
}

func (s *Scanner) Run() (*model.Summary, error) {
	start := time.Now()
	jobs := make(chan string, 1024)
	results := make(chan model.FileResult, 1024)
	var wg sync.WaitGroup

	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				results <- s.scanFile(p, 0, false)
			}
		}()
	}

	var scanned int64
	var walked int64
	done := make(chan struct{})
	var all []model.FileResult

	go func() {
		defer close(done)
		for r := range results {
			all = append(all, r)
			if r.Skipped {
				continue
			}
			atomic.AddInt64(&scanned, 1)
			if !s.cfg.Quiet && r.Verdict != model.VerdictClean {
				fmt.Printf("[%s] %d  %s  %s\n", r.Verdict, r.Score, truncPath(r.Path, 90), topFinding(r))
			}
		}
	}()

	filepath.WalkDir(s.cfg.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != s.cfg.Root && (strings.HasPrefix(d.Name(), ".") || strings.EqualFold(d.Name(), "$RECYCLE.BIN") || strings.EqualFold(d.Name(), "System Volume Information") || strings.EqualFold(d.Name(), quarantineDirName)) {
				return filepath.SkipDir
			}
			return nil
		}
		atomic.AddInt64(&walked, 1)
		if !d.Type().IsRegular() {
			return nil
		}
		if s.skipFile(path) {
			info, _ := d.Info()
			var sz int64
			if info != nil {
				sz = info.Size()
			}
			results <- model.FileResult{Path: path, Size: sz, Verdict: model.VerdictClean, Skipped: true}
			return nil
		}
		jobs <- path
		return nil
	})
	close(jobs)
	wg.Wait()
	close(results)
	<-done
	sum, _ := s.summarize(all, scanned, walked)
	sum.DurationMs = time.Since(start).Milliseconds()
	return sum, nil
}

const quarantineDirName = ".quarantine"

func (s *Scanner) ScanFiles(paths []string) (*model.Summary, error) {
	start := time.Now()
	jobs := make(chan string, len(paths)+1)
	results := make(chan model.FileResult, len(paths)+1)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				results <- s.scanFile(p, 0, false)
			}
		}()
	}
	var scanned int64
	done := make(chan struct{})
	var all []model.FileResult
	go func() {
		defer close(done)
		for r := range results {
			all = append(all, r)
			if !r.Skipped {
				atomic.AddInt64(&scanned, 1)
				if !s.cfg.Quiet && r.Verdict != model.VerdictClean {
					fmt.Printf("[%s] %d  %s  %s\n", r.Verdict, r.Score, truncPath(r.Path, 90), topFinding(r))
				}
			}
		}
	}()
	for _, p := range paths {
		if s.skipFile(p) {
			continue
		}
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)
	<-done
	sum, _ := s.summarize(all, scanned, int64(len(paths)))
	sum.DurationMs = time.Since(start).Milliseconds()
	return sum, nil
}

func (s *Scanner) summarize(all []model.FileResult, scanned, walked int64) (*model.Summary, error) {
	sort.Slice(all, func(i, j int) bool {
		if all[i].Score != all[j].Score {
			return all[i].Score > all[j].Score
		}
		return all[i].Path < all[j].Path
	})
	sum := &model.Summary{
		FilesScanned: int(scanned),
		FilesSkipped: int(walked) - int(scanned),
		DurationMs:   0,
		Results:      all,
	}
	for _, r := range all {
		if r.Skipped {
			continue
		}
		sum.BytesScanned += r.Size
		switch r.Verdict {
		case model.VerdictClean:
			sum.Clean++
		case model.VerdictSuspicious:
			sum.Suspicious++
		case model.VerdictMalicious:
			sum.Malicious++
		}
	}
	return sum, nil
}

func (s *Scanner) skipFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	if info.Size() > s.cfg.MaxSizeMB*1024*1024 {
		isContainer := s.cfg.ExtractDepth > 0 && (filetype.IsContainerExt(path) || filetype.IsFreeArc(path))
		if !isContainer || info.Size() > 8*1024*1024*1024 {
			return true
		}
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, ex := range s.cfg.Excludes {
		if ex != "" && ext == strings.ToLower(ex) {
			return true
		}
	}
	if s.cfg.SkipAssets && filetype.Classify(path) == filetype.KindAsset {
		return true
	}
	return false
}

func (s *Scanner) scanFile(path string, depth int, sub bool) model.FileResult {
	t0 := time.Now()
	info, err := os.Stat(path)
	if err != nil {
		return model.FileResult{Path: path, Verdict: model.VerdictClean, ScanMs: time.Since(t0).Milliseconds()}
	}
	res := model.FileResult{Path: path, Size: info.Size(), ScanMs: 0}

	sha, readBytes, head := hashAndHead(path, s.cfg.FullReadMB)
	res.SHA256 = sha
	kind := filetype.Classify(path)
	res.Type = kindName(kind)

	onlineOn := s.cfg.Online != nil && s.cfg.Online.Enabled()
	if s.cache != nil && sha != "" && !onlineOn {
		if e, ok := s.cache.Get(sha); ok && e.Verdict != model.VerdictClean.String() {
			res.Verdict = parseVerdict(e.Verdict)
			res.Score = e.Score
			res.Cached = true
			res.ScanMs = time.Since(t0).Milliseconds()
			return res
		}
	}

	var peInfo *pe.Info
	var peErr string
	if kind == filetype.KindPE {
		if pi, err := pe.Analyze(path); err == nil {
			peInfo = pi
			res.Imphash = pi.Imphash
			res.Signed = pi.Signed
			res.Packer = pi.Packer
			for _, sec := range pi.Sections {
				res.Sections = append(res.Sections, sec.Name+":"+strconv.FormatFloat(sec.Entropy, 'f', 2, 64))
			}
		} else {
			peErr = err.Error()
		}
	}

	var strs []string
	if kind == filetype.KindPE {
		strs = dedupCap(text.ExtractASCII(path, 8*1024*1024, 6), 20000)
		strs = append(strs, dedupCap(text.ExtractUTF16(path, 4*1024*1024, 6), 10000)...)
	} else if len(readBytes) > 0 {
		strs = dedupCap(text.ExtractASCIIBytes(readBytes, 6), 20000)
		strs = append(strs, dedupCap(decodeUTF16Bytes(readBytes), 20000)...)
	}

	findings, whitelist := rules.Match(rules.MatchInput{
		Kind:  kind,
		PE:    peInfo,
		Strs:  strs,
		Bytes: readBytes,
	})
	if len(readBytes) == 0 && head != nil {
		f2, _ := rules.Match(rules.MatchInput{Kind: kind, PE: peInfo, Strs: nil, Bytes: head})
		findings = append(findings, f2...)
	}
	if peErr != "" {
		findings = append(findings, model.Finding{Rule: "pe_parse", Category: "info", Severity: 1, Detail: "PE parse failed: " + peErr})
	}
	res.Findings = findings

	// Packer signal when debug/pe itself choked (UPX mangles the symbol
	// table): fall back to raw section-name reading so packed files are
	// still flagged AND still enter the auto-unpack path below.
	packer := ""
	if peInfo != nil {
		packer = peInfo.Packer
		res.Packer = packer
	}
	if packer == "" && kind == filetype.KindPE {
		if p := pe.DetectPackerSections(path); p != "" {
			packer = p
			res.Packer = p
			findings = append(findings, model.Finding{
				Rule: "packer", Category: "packing", Severity: 15,
				Detail: "packer/obfuscation: " + p + " (section names; full PE parse failed)",
			})
			res.Findings = findings
		}
	}

	// Auto-unpack: a UPX-packed PE hides its strings/imports. Decompress to
	// temp and rescan the unpacked image (sub=true: no nested unpack, no
	// online lookups on derived bytes). Unpacked findings merge into the
	// outer result so the final score reflects the real payload.
	if !sub && !s.cfg.NoUnpack && kind == filetype.KindPE && isUPX(packer) {
		if up := s.tryUnpackUPX(path); up != "" {
			inner := s.scanFile(up, depth+1, true)
			findings = append(findings, model.Finding{
				Rule: "auto_unpacked", Category: "packing", Severity: 0,
				Detail: fmt.Sprintf("UPX-packed, unpacked image rescanned (score %d)", inner.Score),
			})
			for _, f := range inner.Findings {
				f.Detail = "[unpacked] " + f.Detail
				findings = append(findings, f)
			}
			res.Findings = findings
		} else if s.upxBin() != "" {
			findings = append(findings, model.Finding{
				Rule: "unpack_failed", Category: "packing", Severity: 2,
				Detail: "UPX section present but upx -d failed (tampered packer?)",
			})
			res.Findings = findings
		}
	}

	if s.cfg.Yara != nil && info.Size() < 200*1024*1024 {
		switch kind {
		case filetype.KindPE, filetype.KindScript, filetype.KindArchive, filetype.KindDoc, filetype.KindShortcut, filetype.KindUnknown:
			if matches, err := s.cfg.Yara.Scan(path); err == nil {
				ys := 0
				for _, m := range matches {
					sev := 20
					if strings.Contains(strings.ToLower(m.Rule), "info") {
						sev = 0
					}
					if ys+sev > 40 {
						continue
					}
					ys += sev
					findings = append(findings, model.Finding{
						Rule:     "yara:" + m.Rule,
						Category: "yara",
						Severity: sev,
						Detail:   "yara rule match: " + m.Rule,
					})
				}
				res.Findings = findings
			}
		}
	}

	var onlineRes *online.Result
	onlineJSON := ""
	if onlineOn && !sub && sha != "" {
		haveCache := false
		if s.cache != nil {
			if e, ok := s.cache.Get(sha); ok && e.Online != "" {
				var r online.Result
				if json.Unmarshal([]byte(e.Online), &r) == nil && (r.Err == "" || r.NotFound) {
					haveCache = true
					onlineJSON = e.Online
					if r.Found {
						onlineRes = &r
					}
				}
			}
		}
		if !haveCache {
			r := s.cfg.Online.LookupHash(sha)
			if r.Err == "" {
				if b, err := json.Marshal(r); err == nil {
					onlineJSON = string(b)
				}
				if r.Found {
					onlineRes = &r
				}
			}
		}
		if onlineRes != nil {
			delta := online.ScoreDelta(*onlineRes)
			if delta != 0 {
				findings = append(findings, model.Finding{
					Rule:     "online_" + onlineRes.Provider,
					Category: "reputation",
					Severity: delta,
					Detail:   online.Describe(*onlineRes),
				})
			}
			res.Findings = findings
		}
	}

	if s.cfg.Detonate && kind == filetype.KindPE && s.cfg.DetonateMin > 0 {
		base := 0
		for _, f := range findings {
			base += f.Severity
		}
		if base >= s.cfg.DetonateMin && base < 70 {
			if rep := s.detonate(path); rep != nil && rep.Error == "" {
				findings = append(findings, behavioralFindings(rep)...)
				res.Findings = findings
			}
		}
	}

	score := 0
	for _, f := range findings {
		score += f.Severity
	}
	if score > 100 {
		score = 100
	}
	if len(whitelist) > 0 && score < 60 {
		score -= 15
		if score < 0 {
			score = 0
		}
	}
	res.Score = score
	res.Verdict = model.VerdictClean
	if score >= 70 {
		res.Verdict = model.VerdictMalicious
	} else if score >= 30 {
		res.Verdict = model.VerdictSuspicious
	}
	if onlineRes != nil && online.ScoreDelta(*onlineRes) >= 40 {
		res.Verdict = model.VerdictMalicious
	}
	if depth < s.cfg.ExtractDepth && (kind == filetype.KindArchive || filetype.IsContainerExt(path)) {
		s.expandContainer(path, depth, &res)
	}
	if s.cache != nil && sha != "" && (score > 0 || onlineJSON != "") {
		s.cache.PutOnline(sha, score, res.Verdict.String(), onlineJSON)
	}
	res.ScanMs = time.Since(t0).Milliseconds()
	return res
}

var containerSeq int64

var extractableExts = []string{"exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "hta", "lnk", "url", "pif", "ini", "nfo", "txt", "md5", "cfg", "com"}

func (s *Scanner) expandContainer(path string, depth int, res *model.FileResult) {
	if s.tmp == "" {
		return
	}
	if filetype.IsFreeArc(path) {
		res.Findings = append(res.Findings, model.Finding{
			Rule: "container_freearc", Category: "container", Severity: 2,
			Detail: "FreeArc container (repack installer data) - extract manually before scanning: run its setup.exe -extract or install FreeArc",
		})
		return
	}
	dest := filepath.Join(s.tmp, fmt.Sprintf("c%d_%d", depth, atomic.AddInt64(&containerSeq, 1)))
	os.MkdirAll(dest, 0o755)
	n, total, method, err := s.extract(path, dest)
	if err != nil {
		res.Findings = append(res.Findings, model.Finding{
			Rule: "container_unextracted", Category: "container", Severity: 1,
			Detail: fmt.Sprintf("container %s: %v", method, err),
		})
		return
	}
	if n == 0 {
		return
	}
	res.Findings = append(res.Findings, model.Finding{
		Rule: "container_expanded", Category: "container", Severity: 0,
		Detail: fmt.Sprintf("%s container: scanned %d inner files (%s)", method, n, humanMB(total)),
	})
	limit := s.cfg.ExtractMaxMB * 1024 * 1024
	budget := total
	entries, _ := os.ReadDir(dest)
	count := 0
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		subPath := filepath.Join(dest, e.Name())
		info, err := os.Stat(subPath)
		if err != nil || info.Size() > s.cfg.MaxSizeMB*1024*1024 {
			continue
		}
		budget += info.Size()
		count++
		if budget > limit || count > 3000 {
			res.Findings = append(res.Findings, model.Finding{
				Rule: "container_truncated", Category: "container", Severity: 0,
				Detail: "inner file scan budget reached",
			})
			break
		}
		sub := s.scanFile(subPath, depth+1, false)
		rel := e.Name()
		if sub.Score > 0 {
			res.Findings = append(res.Findings, model.Finding{
				Rule: "nested_result", Category: "container", Severity: sub.Score,
				Detail: rel + " -> " + sub.Verdict.String() + " (" + strconv.Itoa(sub.Score) + ")",
			})
		}
		if sub.Verdict > res.Verdict || (sub.Score > res.Score && sub.Verdict == res.Verdict) {
			res.Score = sub.Score
			res.Verdict = sub.Verdict
		}
	}
}

func (s *Scanner) extract(path, dest string) (int, int64, string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".zip" {
		n, total, err := extractZip(path, dest)
		return n, total, "zip", err
	}
	sevenz := find7z()
	if sevenz == "" {
		return 0, 0, "7z", fmt.Errorf("7-Zip binary not found (needed for %s containers)", ext)
	}
	args := []string{"x", "-y", "-o" + dest}
	for _, e := range extractableExts {
		args = append(args, "-i!*."+e)
	}
	args = append(args, path)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sevenz, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return 0, 0, "7z", err
	}
	entries, _ := os.ReadDir(dest)
	n := 0
	var total int64
	for _, e := range entries {
		if e.Type().IsRegular() {
			if info, err := e.Info(); err == nil {
				n++
				total += info.Size()
			}
		}
	}
	return n, total, "7z", nil
}

func extractZip(path, dest string) (int, int64, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, 0, err
	}
	defer zr.Close()
	n := 0
	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.FileInfo().Size() > 64*1024*1024 {
			continue
		}
		if !wantExt(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		name := filepath.Base(f.Name)
		if name == "." || name == string(os.PathSeparator) {
			rc.Close()
			continue
		}
		out := filepath.Join(dest, name)
		w, err := os.Create(out)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(w, io.LimitReader(rc, 64<<20))
		w.Close()
		rc.Close()
		n++
		total += f.FileInfo().Size()
	}
	return n, total, nil
}

func wantExt(name string) bool {
	e := strings.ToLower(filepath.Ext(name))
	for _, x := range extractableExts {
		if e == "."+x {
			return true
		}
	}
	return false
}

func find7z() string {
	if p, err := exec.LookPath("7z"); err == nil {
		return p
	}
	for _, p := range []string{
		`C:\Program Files\7-Zip\7z.exe`,
		`C:\Program Files (x86)\7-Zip\7z.exe`,
		`/usr/bin/7z`, `/usr/bin/7za`, `/usr/local/bin/7z`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func humanMB(b int64) string {
	return strconv.FormatFloat(float64(b)/1024/1024, 'f', 1, 64) + " MB"
}

func hashAndHead(path string, fullReadMB int64) (string, []byte, []byte) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, nil
	}
	defer f.Close()
	h := sha256.New()
	limit := fullReadMB * 1024 * 1024
	var whole []byte
	buf := make([]byte, 1<<20)
	var total int64
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			total += int64(n)
			if int64(len(whole)) < limit {
				whole = append(whole, buf[:n]...)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
	sha := fmt.Sprintf("%x", h.Sum(nil))
	if int64(len(whole)) >= limit {
		tail := make([]byte, 1<<20)
		f.Seek(-int64(len(tail)), io.SeekEnd)
		n, _ := f.Read(tail)
		return sha, whole, tail[:n]
	}
	return sha, whole, nil
}

func kindName(k filetype.Kind) string {
	switch k {
	case filetype.KindPE:
		return "pe"
	case filetype.KindScript:
		return "script"
	case filetype.KindArchive:
		return "archive"
	case filetype.KindShortcut:
		return "shortcut"
	case filetype.KindDoc:
		return "document"
	case filetype.KindAsset:
		return "asset"
	}
	return "other"
}

func parseVerdict(s string) model.Verdict {
	switch s {
	case "MALICIOUS":
		return model.VerdictMalicious
	case "SUSPICIOUS":
		return model.VerdictSuspicious
	}
	return model.VerdictClean
}

func dedupCap(in []string, cap2 int) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(s) < 4 {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= cap2 {
			break
		}
	}
	return out
}

func decodeUTF16Bytes(b []byte) []string {
	if len(b) < 8 {
		return nil
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	var out []string
	run := make([]uint16, 0, 256)
	flush := func() {
		if len(run) >= 6 {
			out = append(out, decodeUTF16Runes(run))
		}
		run = run[:0]
	}
	for _, c := range u16 {
		if c == 0 {
			flush()
			continue
		}
		run = append(run, c)
		if len(run) > 4096 {
			run = run[:0]
		}
	}
	flush()
	return dedupCap(out, 10000)
}

func decodeUTF16Runes(u []uint16) string {
	var sb strings.Builder
	for _, c := range u {
		if c < 0x80 {
			sb.WriteByte(byte(c))
		} else {
			sb.WriteRune(rune(c))
		}
	}
	return sb.String()
}

func truncPath(p string, n int) string {
	if len(p) <= n {
		return p
	}
	return "..." + p[len(p)-n:]
}

func topFinding(r model.FileResult) string {
	best := ""
	sev := -1
	for _, f := range r.Findings {
		if f.Severity > sev {
			sev = f.Severity
			best = f.Rule + ": " + truncStr(f.Detail, 70)
		}
	}
	if best == "" {
		return ""
	}
	return best
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
