package main

// cmd/batch — Mass batch scanner for CrackSentinel (Gap G5).
//
// Scans N game folders (from -list games.txt, -parent E:\Games, or positional
// arguments) in one invocation and outputs:
//   - structured JSON report (batch-report.json)
//   - concise Markdown summary table (batch-report.md)
//   - disputed "NEEDS A HUMAN" queue (disputed.json) for cmd/label

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gamecrack-scanner/internal/jev"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/scan"
	"gamecrack-scanner/internal/yara"
)

type GameReport struct {
	Name       string            `json:"name"`
	Path       string            `json:"path"`
	Verdict    string            `json:"verdict"`
	MaxScore   int               `json:"max_score"`
	Scanned    int               `json:"files_scanned"`
	Malicious  int               `json:"malicious"`
	Suspicious int               `json:"suspicious"`
	Clean      int               `json:"clean"`
	DurationMs int64             `json:"duration_ms"`
	Flagged    []FlaggedFileInfo `json:"flagged,omitempty"`
}

type FlaggedFileInfo struct {
	Path       string             `json:"path"`
	Score      int                `json:"score"`
	Verdict    string             `json:"verdict"`
	TopRule    string             `json:"top_rule"`
	TopDetail  string             `json:"top_detail"`
	Judge      *model.JudgeResult `json:"judge,omitempty"`
	NeedsHuman bool               `json:"needs_human,omitempty"`
	Reason     string             `json:"reason,omitempty"`
}

type BatchReport struct {
	GeneratedAt string            `json:"generated_at"`
	Games       []GameReport      `json:"games"`
	Disputed    []FlaggedFileInfo `json:"disputed"`
}

func main() {
	var (
		listFile     string
		parentDir    string
		outDir       string
		workers      int
		maxSizeMB    int64
		extractDepth int
		extractMB    int64
		tmpDir       string
		cachePath    string
		noYara       bool
		onlineFlag   bool
		jevOn        bool
		jevCalib     string
	)
	flag.StringVar(&listFile, "list", "", "text file with one game folder/archive path per line")
	flag.StringVar(&parentDir, "parent", "", "scan every subfolder/archive directly inside this directory")
	flag.StringVar(&outDir, "out", "batch-reports", "output directory for JSON, Markdown, and disputed queue")
	flag.IntVar(&workers, "workers", 3, "parallel workers per folder")
	flag.Int64Var(&maxSizeMB, "max-size", 512, "skip files larger than N MB")
	flag.IntVar(&extractDepth, "extract-depth", 2, "archive expansion depth")
	flag.Int64Var(&extractMB, "extract-mb", 500, "max MB per archive extraction")
	flag.StringVar(&tmpDir, "tmp-dir", "", "temp directory for archive extraction")
	flag.StringVar(&cachePath, "cache", ".gamecrack-cache.jsonl", "hash cache file")
	flag.BoolVar(&noYara, "no-yara", false, "disable YARA layer")
	flag.BoolVar(&onlineFlag, "online", false, "enable VT/MB online reputation")
	flag.BoolVar(&jevOn, "jev", false, "enable Jev semantic adjudication")
	flag.StringVar(&jevCalib, "jev-calibration", "", "fitted JevLab calibrator JSON")
	flag.Parse()

	targets, err := collectTargets(listFile, parentDir, flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "usage: batch [-list games.txt | -parent E:\\Games | <folder1> <folder2>...] [-out reports/]")
		os.Exit(1)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "out dir error:", err)
		os.Exit(1)
	}

	var yr *yara.Runner
	if !noYara {
		if r, err := yara.New("", true); err == nil {
			yr = r
			defer yr.Close()
		}
	}
	var oc *online.Client
	if onlineFlag {
		oc = online.New(os.Getenv("VT_API_KEY"), os.Getenv("MB_API_KEY"), 16*time.Second)
	}
	var judge *jev.Client
	if jevOn {
		judge = jev.New("", jev.DefaultBaseURL, jev.DefaultModel)
		if !judge.Enabled() {
			judge = nil
			fmt.Fprintln(os.Stderr, "warning: -jev enabled but TYPESAFE_API_KEY unset")
		}
	}
	var calib *jev.Calibrator
	if jevCalib != "" {
		if c, err := jev.LoadCalibrator(jevCalib); err == nil {
			calib = c
		}
	}

	rep := BatchReport{GeneratedAt: time.Now().Format(time.RFC3339)}
	fmt.Printf("CrackSentinel Batch — %d target(s)\n\n", len(targets))

	for i, target := range targets {
		name := filepath.Base(target)
		fmt.Printf("[%d/%d] %s ... ", i+1, len(targets), name)
		st, err := os.Stat(target)
		if err != nil {
			fmt.Printf("SKIP (%v)\n", err)
			continue
		}
		cfg := scan.Config{
			Root:                target,
			Workers:             workers,
			MaxSizeMB:           maxSizeMB,
			SkipAssets:          true,
			UseCache:            true,
			CachePath:           cachePath,
			Quiet:               true,
			FullReadMB:          32,
			Online:              oc,
			Yara:                yr,
			ExtractDepth:        extractDepth,
			ExtractMaxMB:        extractMB,
			TempDir:             tmpDir,
			Carve:               true,
			CarveMaxMB:          16384,
			Judge:               judge,
			JudgeMin:            30,
			JudgeMax:            100,
			JudgeMaxFiles:       8,
			JudgeConcurrency:    4,
			JudgeValidate:       true,
			JudgeClaimThreshold: 0.5,
			JudgeThreshold:      0.3,
			JudgeCalibration:    calib,
		}
		sc, err := scan.New(cfg)
		if err != nil {
			fmt.Printf("ERR (%v)\n", err)
			continue
		}
		var sum *model.Summary
		if st.IsDir() {
			sum, err = sc.Run()
		} else {
			sum, err = sc.ScanFiles([]string{target})
		}
		sc.Close()
		if err != nil {
			fmt.Printf("ERR (%v)\n", err)
			continue
		}

		gr := buildGameReport(name, target, sum)
		rep.Games = append(rep.Games, gr)
		for _, fl := range gr.Flagged {
			if fl.NeedsHuman {
				rep.Disputed = append(rep.Disputed, fl)
			}
		}
		fmt.Printf("%s (max=%d, mal=%d, sus=%d, clean=%d, %dms)\n",
			gr.Verdict, gr.MaxScore, gr.Malicious, gr.Suspicious, gr.Clean, gr.DurationMs)
	}

	jsonPath := filepath.Join(outDir, "batch-report.json")
	writePrettyJSON(jsonPath, rep)

	disputedPath := filepath.Join(outDir, "disputed.json")
	writePrettyJSON(disputedPath, rep.Disputed)

	mdPath := filepath.Join(outDir, "batch-report.md")
	writeBatchMarkdown(mdPath, rep)

	fmt.Printf("\nDone: %d game(s), %d file(s) need human review\n", len(rep.Games), len(rep.Disputed))
	fmt.Printf("  JSON     : %s\n", jsonPath)
	fmt.Printf("  Markdown : %s\n", mdPath)
	fmt.Printf("  Disputed : %s  (label via: go run ./cmd/label -in %s)\n", disputedPath, disputedPath)
}

func buildGameReport(name, path string, sum *model.Summary) GameReport {
	gr := GameReport{
		Name:       name,
		Path:       path,
		Verdict:    "CLEAN",
		Scanned:    sum.FilesScanned,
		Malicious:  sum.Malicious,
		Suspicious: sum.Suspicious,
		Clean:      sum.Clean,
		DurationMs: sum.DurationMs,
	}
	for _, r := range sum.Results {
		if r.Skipped {
			continue
		}
		if r.Score > gr.MaxScore {
			gr.MaxScore = r.Score
		}
		if r.Verdict == model.VerdictMalicious {
			gr.Verdict = "MALICIOUS"
		} else if r.Verdict == model.VerdictSuspicious && gr.Verdict != "MALICIOUS" {
			gr.Verdict = "SUSPICIOUS"
		}
		if r.Verdict == model.VerdictClean && (r.Judge == nil || r.Judge.Classification != jev.ClassTrojanized) {
			continue
		}
		topR, topD := "", ""
		for _, f := range r.Findings {
			if f.Severity > 0 {
				topR, topD = f.Rule, f.Detail
				break
			}
		}
		needsHuman := false
		reason := ""
		if r.Judge != nil {
			judgeMal := r.Judge.Classification == jev.ClassTrojanized
			if r.Verdict == model.VerdictMalicious && !judgeMal {
				needsHuman = true
				reason = "scanner=MALICIOUS but Jev=" + r.Judge.Classification
			} else if r.Verdict == model.VerdictClean && judgeMal {
				needsHuman = true
				reason = "scanner=CLEAN but Jev=trojanized"
			}
		} else if r.Verdict == model.VerdictSuspicious {
			needsHuman = true
			reason = "ambiguous SUSPICIOUS score — needs ground truth"
		}
		gr.Flagged = append(gr.Flagged, FlaggedFileInfo{
			Path:       r.Path,
			Score:      r.Score,
			Verdict:    r.Verdict.String(),
			TopRule:    topR,
			TopDetail:  topD,
			Judge:      r.Judge,
			NeedsHuman: needsHuman,
			Reason:     reason,
		})
	}
	return gr
}

func collectTargets(listFile, parentDir string, args []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(strings.Trim(p, `"'`))
		if p == "" || strings.HasPrefix(p, "#") {
			return
		}
		abs, err := filepath.Abs(p)
		if err == nil {
			p = abs
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			add(sc.Text())
		}
	}
	if parentDir != "" {
		entries, err := os.ReadDir(parentDir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			add(filepath.Join(parentDir, e.Name()))
		}
	}
	for _, a := range args {
		add(a)
	}
	return out, nil
}

func writePrettyJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	_ = os.WriteFile(path, b, 0o644)
}

func writeBatchMarkdown(path string, rep BatchReport) {
	var sb strings.Builder
	sb.WriteString("# CrackSentinel Batch Report\n\n")
	fmt.Fprintf(&sb, "- Generated: %s\n- Targets: %d\n- Needs human review: %d\n\n", rep.GeneratedAt, len(rep.Games), len(rep.Disputed))
	sb.WriteString("| Game | Verdict | Max Score | Malicious | Suspicious | Clean | Duration |\n")
	sb.WriteString("|---|---|---:|---:|---:|---:|---:|\n")
	for _, g := range rep.Games {
		fmt.Fprintf(&sb, "| `%s` | **%s** | %d | %d | %d | %d | %d ms |\n",
			g.Name, g.Verdict, g.MaxScore, g.Malicious, g.Suspicious, g.Clean, g.DurationMs)
	}
	if len(rep.Disputed) > 0 {
		sb.WriteString("\n## NEEDS A HUMAN\n\n")
		for _, d := range rep.Disputed {
			fmt.Fprintf(&sb, "- `%s` (%s %d) — %s (`%s`)\n", d.Path, d.Verdict, d.Score, d.Reason, d.TopRule)
		}
	}
	_ = os.WriteFile(path, []byte(sb.String()), 0o644)
}
