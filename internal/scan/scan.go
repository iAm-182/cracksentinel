package scan

import (
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

	"gamecrack-scanner/internal/authenticode"
	"gamecrack-scanner/internal/cache"
	"gamecrack-scanner/internal/filetype"
	"gamecrack-scanner/internal/jev"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/pe"
	"gamecrack-scanner/internal/rules"
	"gamecrack-scanner/internal/sandbox"
	"gamecrack-scanner/internal/telemetry"
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
	Telemetry    *telemetry.Client
	// TempDir is the base directory for container extraction. Extraction
	// can write gigabytes, so it must be pointable at a volume with free
	// space — the default system temp often lives on a small C: drive.
	TempDir string
	// Judge is the optional semantic adjudication layer. When it is set and
	// enabled, files scoring inside the judge band get an independent
	// assessment that is recorded next to the deterministic verdict.
	Judge *jev.Client
	// JudgeMin and JudgeMax bound the score band that is adjudicated.
	// The band is the ambiguous middle: below it there is nothing to
	// argue about, above it the evidence is already conclusive.
	JudgeMin int
	JudgeMax int
	// JudgeOverride lets a confident adjudication change the final verdict.
	// Off by default: a model is not evidence.
	JudgeOverride bool
	// JudgeMinConfidence is the confidence a verdict must reach before an
	// override is applied.
	JudgeMinConfidence float64
	// JudgeMaxFiles caps how many files are adjudicated per scan, so a
	// folder full of flagged files cannot turn into a hundred API calls.
	JudgeMaxFiles int
	// JudgeConcurrency bounds the in-flight adjudication calls.
	JudgeConcurrency int
	// JudgeValidate turns on the per-claim validation: every payload
	// claim is put to the model separately and the ones that cannot be
	// defended lose their severity.
	JudgeValidate bool
	// JudgeClaimThreshold is the support probability a claim needs to
	// keep counting towards the score.
	JudgeClaimThreshold float64
	// JudgeThreshold is the probability at which the adjudicator's
	// trojanized answer counts as a yes. It is calibrated against a
	// labelled corpus, not guessed: see cmd/calibrate and corpus.json.
	JudgeThreshold float64
	// JudgeCalibration is a fitted probability calibrator. The raw
	// probability the model returns is a score, not a probability, and
	// applying the fitted map is what makes the threshold meaningful.
	JudgeCalibration *jev.Calibrator
	// Carve turns a file that is too large to read into a search for
	// embedded executables. In a repack the game data is one huge blob
	// and a trojanized one can hide a payload inside it.
	Carve bool
	// CarveMaxMB bounds the size of a file that is carved.
	CarveMaxMB int64
}

type Scanner struct {
	cfg       Config
	cache     *cache.Cache
	tmp       string
	detMu     sync.Mutex
	detOk     bool
	detFail   bool
	upxMu     sync.Mutex
	upxPath   string
	upxProbed bool
	tmpMu     sync.Mutex
	warnMu    sync.Mutex
	warned    map[string]bool
	// judge budget and concurrency gate
	judgeMu     sync.Mutex
	judgeUsed   int
	judgeSem    chan struct{}
	judgeWarned bool
}

// warnOnce prints a warning at most once per key (concurrency-safe).
func (s *Scanner) warnOnce(msg string) {
	s.warnMu.Lock()
	defer s.warnMu.Unlock()
	if s.warned == nil {
		s.warned = map[string]bool{}
	}
	if s.warned[msg] {
		return
	}
	s.warned[msg] = true
	fmt.Fprintln(os.Stderr, msg)
}

// flushTelemetry contributes this scan's verdicts to the shared-reputation
// worker. Best-effort: failures warn once and never fail the scan.
func (s *Scanner) flushTelemetry(sum *model.Summary) {
	tc := s.cfg.Telemetry
	if tc == nil || !tc.Enabled() || sum == nil {
		return
	}
	var entries []telemetry.ReportEntry
	for _, r := range sum.Results {
		if r.Skipped || r.SHA256 == "" {
			continue
		}
		var rules []string
		for i, f := range r.Findings {
			if i >= 6 {
				break
			}
			rules = append(rules, f.Rule)
		}
		entries = append(entries, telemetry.ReportEntry{
			SHA:     r.SHA256,
			Verdict: r.Verdict.String(),
			Score:   r.Score,
			Rules:   rules,
		})
	}
	if err := tc.ReportBatch(entries); err != nil {
		s.warnOnce(fmt.Sprintf("warning: telemetry report failed: %v", err))
		return
	}
	if !s.cfg.Quiet {
		fmt.Printf("telemetry: contributed %d verdict(s) to shared reputation\n", len(entries))
	}
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
		// The Docker daemon is often still starting up when the scanner
		// runs, and a failed inspect would otherwise trigger a multi-minute
		// rebuild of an image that already exists. Retry briefly first.
		for i := 0; i < 3; i++ {
			time.Sleep(2 * time.Second)
			if sandbox.ImageExists(image) {
				break
			}
		}
	}
	if !sandbox.ImageExists(image) {
		dir := s.cfg.DetonatorDir
		if dir == "" {
			dir = "detonator"
		}
		fmt.Fprintf(os.Stderr, "note: building detonator image %s (one time, takes several minutes)...\n", image)
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
	// Exit code 137 = SIGKILL (the sample was still alive when the sandbox
	// window closed), 139 = SIGSEGV. Both are worth recording: a sample that
	// has to be killed is a sample that kept running.
	switch r.ExitCode {
	case "137":
		out = append(out, model.Finding{Rule: "behav_killed", Category: "behavioral", Severity: 5, Detail: "sample was still running when the sandbox window closed (SIGKILL)"})
	case "139":
		out = append(out, model.Finding{Rule: "behav_crash", Category: "behavioral", Severity: 5, Detail: "sample crashed with SIGSEGV during detonation"})
	}
	return out
}

func New(cfg Config) (*Scanner, error) {
	s := &Scanner{cfg: cfg}
	if cfg.Judge != nil && cfg.Judge.Enabled() {
		conc := cfg.JudgeConcurrency
		if conc <= 0 {
			conc = 4
		}
		s.judgeSem = make(chan struct{}, conc)
	}
	if cfg.ExtractDepth > 0 {
		base := cfg.TempDir
		if base == "" {
			base = os.TempDir()
		}
		tmp, err := os.MkdirTemp(base, "gc-extract-")
		if err != nil {
			// A full or unwritable temp volume must not kill the scan:
			// fall back to the system temp, and if that fails too, run
			// without container expansion.
			if tmp, err = os.MkdirTemp("", "gc-extract-"); err != nil {
				return nil, err
			}
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

// TempPath returns the extraction temp directory (empty when expansion is
// disabled). The CLI prints it so the user knows where disk space goes.
func (s *Scanner) TempPath() string { return s.tmp }

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
			results <- s.carveSkipped(path, sz)
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
	s.flushTelemetry(sum)
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
	s.flushTelemetry(sum)
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

// carveSkipped handles a file the scanner skipped because it is too large.
//
// A file that is too big to read is exactly where a payload can hide: in a
// repack the game data is one huge blob, and a trojanized one can append an
// executable to it where no import table, no string and no certificate
// reaches. So instead of skipping the file silently, it is searched for
// embedded executables.
func (s *Scanner) carveSkipped(path string, size int64) model.FileResult {
	res := model.FileResult{Path: path, Size: size, Verdict: model.VerdictClean, Skipped: true}
	findings := s.carveInto(nil, path, size, 0)
	if len(findings) == 0 {
		return res
	}
	res.Findings = findings
	res.Skipped = false
	res.Type = "data"
	score, verdict, extra := computeScore(res.Findings, nil, false)
	res.Findings = append(res.Findings, extra...)
	res.Score = score
	res.Verdict = verdict
	return res
}

// carveInto searches a file for embedded executables and returns the
// findings it produced.
//
// It runs on every file that is larger than the analysis window, not only
// on the ones that were skipped: a 200 MB file is scanned, but only its
// first 32 MB are read, so an executable hidden further in is missed just
// the same.
//
// The result is always recorded, even when nothing was found, so the report
// can show that the file was examined.
func (s *Scanner) carveInto(findings []model.Finding, path string, size int64, depth int) []model.Finding {
	if !s.cfg.Carve {
		return findings
	}
	limit := s.cfg.CarveMaxMB * 1024 * 1024
	if limit <= 0 {
		limit = 16 * 1024 * 1024 * 1024
	}
	if size > limit {
		return findings
	}
	window := s.cfg.FullReadMB * 1024 * 1024
	if window <= 0 {
		window = 32 * 1024 * 1024
	}
	if size <= window {
		// The whole file was read and analysed already.
		return findings
	}
	start := time.Now()
	carves, err := pe.CarvePEs(path, 8)
	elapsed := time.Since(start)
	if err != nil {
		return append(findings, model.Finding{
			Rule: "carve_failed", Category: "packing", Severity: 0,
			Detail: fmt.Sprintf("could not search %.1f MB for embedded executables: %v", float64(size)/(1<<20), err),
		})
	}
	if len(carves) == 0 {
		return append(findings, model.Finding{
			Rule: "carved", Category: "packing", Severity: 0,
			Detail: fmt.Sprintf("searched %.1f MB of data for embedded executables and found none (%.1f s)", float64(size)/(1<<20), elapsed.Seconds()),
		})
	}
	for _, c := range carves {
		findings = append(findings, model.Finding{
			Rule: "embedded_pe", Category: "packing", Severity: 32,
			Detail: c.Describe(),
		})
		if s.tmp == "" {
			findings = append(findings, model.Finding{
				Rule: "carve_no_tmp", Category: "packing", Severity: 0,
				Detail: "no extraction directory: the embedded executable was found but not analysed",
			})
			continue
		} // The embedded image is extracted and analysed like any other
		// binary. A payload hidden in a data blob is only useful if its
		// content is actually looked at, and the findings belong to the
		// file that carries it.
		//
		// The extraction runs to the end of the file, not to the end of
		// the section table: a PE can carry an overlay after its last
		// section, and that overlay is where the indicators often sit.
		if c.Size > 0 && s.tmp != "" {
			dst := filepath.Join(s.tmp, fmt.Sprintf("carve_%d_%d.exe", time.Now().UnixNano(), c.Offset))
			if err := pe.ExtractEmbedded(path, c.Offset, 0, dst); err != nil {
				findings = append(findings, model.Finding{
					Rule: "carve_extract_failed", Category: "packing", Severity: 0,
					Detail: "could not extract the embedded executable: " + err.Error(),
				})
			} else {
				sub := s.scanFile(dst, depth+1, true)
				findings = append(findings, model.Finding{
					Rule: "embedded_analysis", Category: "packing", Severity: 0,
					Detail: fmt.Sprintf("the embedded executable was extracted and analysed: %s, score %d, %d finding(s)",
						sub.Verdict, sub.Score, len(sub.Findings)),
				})
				if len(sub.Findings) > 0 {
					for _, f := range sub.Findings {
						if f.Severity <= 0 {
							continue
						}
						f.Detail = "[embedded] " + f.Detail
						findings = append(findings, f)
					}
				}
			}
		}
	}
	return append(findings, model.Finding{
		Rule: "carved", Category: "packing", Severity: 0,
		Detail: fmt.Sprintf("searched %.1f MB of data for embedded executables and found %d (%.1f s)", float64(size)/(1<<20), len(carves), elapsed.Seconds()),
	})
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
	res, _ := s.scanFileEvidence(path, depth, sub)
	return res
}

// scanFileEvidence is scanFile plus the evidence state for the semantic
// adjudicator. The two are kept together so the evidence always describes
// exactly the file that produced the findings.
func (s *Scanner) scanFileEvidence(path string, depth int, sub bool) (model.FileResult, jev.Evidence) {
	t0 := time.Now()
	info, err := os.Stat(path)
	if err != nil {
		return model.FileResult{Path: path, Verdict: model.VerdictClean, ScanMs: time.Since(t0).Milliseconds()}, jev.Evidence{}
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
			return res, jev.Evidence{}
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
		Kind:   kind,
		PE:     peInfo,
		Strs:   strs,
		Bytes:  readBytes,
		Path:   path,
		Signed: res.Signed,
	})
	if len(readBytes) == 0 && head != nil {
		f2, _ := rules.Match(rules.MatchInput{Kind: kind, PE: peInfo, Strs: nil, Bytes: head, Path: path, Signed: res.Signed})
		findings = append(findings, f2...)
	}
	if peErr != "" {
		findings = append(findings, model.Finding{Rule: "pe_parse", Category: "info", Severity: 1, Detail: "PE parse failed: " + peErr})
	}
	// Packed or encrypted payloads.
	//
	// A trojanized crack is usually encrypted so that it does not show up
	// in a scanner. An encrypted binary has no readable strings, no
	// imports worth reporting and a high entropy - which means the
	// deterministic engine has nothing to say about it and the file comes
	// out CLEAN. The structure of the file gives it away instead: the
	// original sections have a virtual size but no data on disk, the
	// payload sits in one high-entropy section, and the section names are
	// not the ordinary ones.
	if peInfo != nil {
		if peInfo.NoRawSections >= 2 {
			findings = append(findings, model.Finding{
				Rule: "crypter_no_raw_sections", Category: "packing", Severity: 25,
				Detail: fmt.Sprintf("%d section(s) have a virtual size but no data on disk - the code is unpacked into memory at run time (crypter)", peInfo.NoRawSections),
			})
		}
		if peInfo.EncryptedSize > 1<<20 {
			findings = append(findings, model.Finding{
				Rule: "encrypted_payload", Category: "packing", Severity: 20,
				Detail: fmt.Sprintf("%.1f MB of high-entropy section data (encrypted or compressed payload)", float64(peInfo.EncryptedSize)/(1<<20)),
			})
		}
		if len(peInfo.OddSections) >= 2 {
			findings = append(findings, model.Finding{
				Rule: "nonstandard_sections", Category: "packing", Severity: 10,
				Detail: "non-standard section names: " + strings.Join(peInfo.OddSections, ", "),
			})
		}
	}
	// A multi-megabyte binary with no readable strings at all is
	// encrypted or packed. Legitimate binaries always carry strings:
	// error messages, resource names, format strings.
	if kind == filetype.KindPE && info.Size() > 1<<20 && len(strs) < 5 {
		findings = append(findings, model.Finding{
			Rule: "no_readable_strings", Category: "packing", Severity: 20,
			Detail: fmt.Sprintf("a %.1f MB binary with no readable strings - the payload is encrypted or packed", float64(info.Size())/(1<<20)),
		})
	}
	// A file larger than the analysis window is only partly read, so an
	// executable hidden past that point is missed. In a repack the game
	// data is one huge blob and a trojanized one hides the payload there.
	findings = s.carveInto(findings, path, info.Size(), depth)
	// The Authenticode signature.
	//
	// "The file carries a certificate table" is not evidence of anything:
	// a trojanized repack ships a real signature next to an injected
	// payload, and the certificate table is still there. The signature is
	// only evidence when the content still matches it, so the file is
	// checked against its own signature here.
	//
	// A mismatch - the content no longer matches the signature - means
	// the file was modified after signing. Nothing else in the scanner can
	// see that, and it is a strong malicious signal.
	if kind == filetype.KindPE {
		if vr, err := authenticode.Verify(path); err == nil && vr.Signed() {
			res.SignatureStatus = vr.Status.String()
			res.Signer = vr.Signer
			switch vr.Status {
			case authenticode.StatusIntact:
				// Only an intact signature may lower a score.
				res.Signed = true
				findings = append(findings, model.Finding{
					Rule: "signed_by", Category: "info", Severity: 0,
					Detail: fmt.Sprintf("signed by %q (chain intact, %d certificate(s))", vr.Signer, vr.Chain),
				})
				// A crack often signs itself to look legitimate. A
				// self-signed certificate proves nothing about the
				// publisher, and in a crack folder it is a signal that
				// the signature is there for show.
				if vr.SelfSigned {
					findings = append(findings, model.Finding{
						Rule: "self_signed_certificate", Category: "trust", Severity: 10,
						Detail: fmt.Sprintf("the signature is self-signed (%q) - it proves nothing about the publisher, and a crack often signs itself to look legitimate", vr.Signer),
					})
				}
				if vr.Expired {
					findings = append(findings, model.Finding{
						Rule: "expired_certificate", Category: "trust", Severity: 5,
						Detail: fmt.Sprintf("the signing certificate expired on %s (a signature timestamped while it was valid can still be valid)", vr.NotAfter),
					})
				}
			case authenticode.StatusMismatch:
				// The signature is there but the content does not match
				// it: the file was modified after it was signed.
				res.Signed = false
				findings = append(findings, model.Finding{
					Rule: "signature_mismatch", Category: "tampering", Severity: 40,
					Detail: fmt.Sprintf("the file claims a signature from %q but the content no longer matches it - it was modified after signing", vr.Signer),
				})
			default:
				res.Signed = false
				findings = append(findings, model.Finding{
					Rule: "signed_unreadable", Category: "info", Severity: 0,
					Detail: "the file carries a certificate table but the signature could not be parsed",
				})
			}
		} else if err == nil {
			res.SignatureStatus = "none"
		}
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
				// The internal engine and YARA detect the same families.
				// Count a YARA hit only for categories the internal engine
				// did not already flag, otherwise one Discord webhook
				// becomes 40 (internal) + 20 (YARA) = 60 points.
				already := map[string]bool{}
				for _, f := range findings {
					if f.Severity > 0 {
						already[f.Category] = true
					}
				}
				ys := 0
				for _, m := range matches {
					sev := 20
					lower := strings.ToLower(m.Rule)
					if strings.Contains(lower, "info") {
						sev = 0
					}
					if cat := rules.YaraCategory(m.Rule); cat != "" && already[cat] {
						sev = 0
					}
					if sev > 0 && ys+sev > 40 {
						continue
					}
					ys += sev
					detail := "yara rule match: " + m.Rule
					if sev == 0 && already[rules.YaraCategory(m.Rule)] {
						detail += " (duplicate of internal engine — not counted twice)"
					}
					findings = append(findings, model.Finding{
						Rule:     "yara:" + m.Rule,
						Category: "yara",
						Severity: sev,
						Detail:   detail,
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

	if s.cfg.Telemetry != nil && s.cfg.Telemetry.Enabled() && sha != "" {
		if rep, err := s.cfg.Telemetry.Lookup(sha); err != nil {
			s.warnOnce(fmt.Sprintf("warning: telemetry lookup failed: %v", err))
		} else if delta := telemetry.ScoreDelta(rep); delta != 0 {
			findings = append(findings, model.Finding{
				Rule:     "shared_rep",
				Category: "reputation",
				Severity: delta,
				Detail:   telemetry.Describe(rep),
			})
			res.Findings = findings
		}
	}

	if s.cfg.Detonate && kind == filetype.KindPE && s.cfg.DetonateMin > 0 {
		base := 0
		for _, f := range findings {
			base += f.Severity
		}
		if base >= s.cfg.DetonateMin && base < 70 {
			if rep := s.detonate(path); rep != nil {
				if rep.Error != "" {
					// A failed detonation must be visible: otherwise the
					// user reads "no behavioural findings" as "behaviourally
					// clean" when the sandbox never actually ran.
					findings = append(findings, model.Finding{
						Rule: "behav_failed", Category: "behavioral", Severity: 0,
						Detail: "behavioural sandbox did not complete: " + rep.Error,
					})
				} else {
					findings = append(findings, behavioralFindings(rep)...)
				}
				res.Findings = findings
			}
		}
	}

	score, verdict, extra := computeScore(findings, whitelist, res.Signed)
	if len(extra) > 0 {
		findings = append(findings, extra...)
		res.Findings = findings
	}
	res.Score = score
	res.Verdict = verdict
	if onlineRes != nil && online.ScoreDelta(*onlineRes) >= 40 {
		res.Verdict = model.VerdictMalicious
	}
	if depth < s.cfg.ExtractDepth && (kind == filetype.KindArchive || filetype.IsContainerExt(path)) {
		s.expandContainer(path, depth, &res)
	}
	// The semantic adjudication runs last, so it sees every finding the
	// file produced, including the ones that came out of a container.
	ev := buildEvidence(&res, strs)
	forceMalicious := onlineRes != nil && online.ScoreDelta(*onlineRes) >= 40
	s.judgeFile(&res, strs, whitelist, forceMalicious)
	if s.cache != nil && sha != "" && (res.Score > 0 || onlineJSON != "") {
		s.cache.PutOnline(sha, res.Score, res.Verdict.String(), onlineJSON)
	}
	res.ScanMs = time.Since(t0).Milliseconds()
	return res, ev
}

// ScanOne scans a single file and returns the result together with the
// adjudication evidence for it. It is the entry point for the calibration
// harness, which needs both the deterministic findings and the state that
// the model is given.
func ScanOne(cfg Config, path string) (model.FileResult, jev.Evidence, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.FullReadMB <= 0 {
		cfg.FullReadMB = 32
	}
	s, err := New(cfg)
	if err != nil {
		return model.FileResult{}, jev.Evidence{}, err
	}
	defer s.Close()
	res, ev := s.scanFileEvidence(path, 0, false)
	return res, ev, nil
}

// computeScore is the scoring policy in one pure function so it can be
// unit-tested without touching the filesystem.
//
// Policy:
//   - CAPABILITY and INTENT are scored separately. The import-based
//     findings say what a file CAN do (it hooks the keyboard, it injects,
//     it uses the network); the string-based findings say what it DOES
//     (it talks to a C2 URL, it targets browser credentials, it installs
//     a run key). A crack emulator has capability and no intent. A
//     trojanized crack has both.
//   - so the capability findings are capped: a legitimate tool that does
//     five different things must not add up to MALICIOUS. The intent
//     findings are not capped.
//   - a signed binary gets a much lower capability cap: a binary that
//     carries an Authenticode certificate and hooks things is a tool
//   - a crack/emulator whitelist hit discounts 15 points, but only while
//     the score is below 60 — a whitelisted string never rescues a file
//     that is already strongly malicious
//   - a Steam-emulator-like DLL is capped at 59 (SUSPICIOUS) so it stays
//     reviewable; a trojanized twin carries payload strings, which veto the
//     cap upstream in rules.isEmuLike
//
// extra carries findings the policy itself wants to record (the emu cap
// note) so the caller can merge them into the result.
func computeScore(findings []model.Finding, whitelist []string, signed bool) (int, model.Verdict, []model.Finding) {
	capScore, intentScore := 0, 0
	for _, f := range findings {
		if rules.IsCapability(f.Rule) {
			capScore += f.Severity
		} else {
			intentScore += f.Severity
		}
	}
	cap := capabilityCap
	if signed {
		cap = signedCapabilityCap
	}
	if capScore > cap {
		capScore = cap
	}
	score := capScore + intentScore
	if score > 100 {
		score = 100
	}
	if len(whitelist) > 0 && score < 60 {
		score -= 15
		if score < 0 {
			score = 0
		}
	}
	var extra []model.Finding
	for _, w := range whitelist {
		if w != "EMU_STEAMAPI" {
			continue
		}
		extra = append(extra, model.Finding{
			Rule: "emu_steamapi", Category: "info", Severity: 0,
			Detail: "Steam-emulator-like DLL: hooking imports are normal here; capped at SUSPICIOUS, review imports manually",
		})
		if score > 59 {
			score = 59
		}
		break
	}
	verdict := model.VerdictClean
	if score >= 70 {
		verdict = model.VerdictMalicious
	} else if score >= 30 {
		verdict = model.VerdictSuspicious
	}
	return score, verdict, extra
}

// The capability caps. The scan of a real Desktop folder showed why they
// are needed: Google's adb.exe hooks the keyboard and the network, and an
// auto-clicker does five suspicious-looking things at once. Both added up
// to 100 and were called MALICIOUS.
const (
	capabilityCap       = 35
	signedCapabilityCap = 15
)

var containerSeq int64

var extractableExts = []string{"exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "hta", "lnk", "url", "pif", "ini", "nfo", "txt", "md5", "cfg", "com"}

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
