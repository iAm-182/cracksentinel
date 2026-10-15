package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"gamecrack-scanner/internal/deep"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/report"
	"gamecrack-scanner/internal/scan"
	"gamecrack-scanner/internal/watch"
	"gamecrack-scanner/internal/yara"
)

func escalate(sum *model.Summary, threshold, maxN, budgetSec int) {
	var flagged []int
	for i, r := range sum.Results {
		if r.Skipped || r.Deep != nil || r.Score < threshold || r.Type != "pe" {
			continue
		}
		flagged = append(flagged, i)
	}
	sort.Slice(flagged, func(a, b int) bool {
		return sum.Results[flagged[a]].Score > sum.Results[flagged[b]].Score
	})
	if len(flagged) == 0 {
		return
	}
	fmt.Printf("\nDEEP ESCALATION: %d candidate PE file(s) (threshold=%d max=%d budget=%ds)\n", len(flagged), threshold, maxN, budgetSec)
	start := time.Now()
	done := 0
	for _, idx := range flagged {
		if done >= maxN {
			fmt.Printf("  ... %d more skipped (deep-max reached)\n", len(flagged)-done)
			break
		}
		if time.Since(start).Seconds() > float64(budgetSec) {
			fmt.Printf("  budget exhausted, %d skipped\n", len(flagged)-done)
			break
		}
		r := &sum.Results[idx]
		fmt.Printf("  [%d/%d] %s (score %d)\n", done+1, maxN, r.Path, r.Score)
		rep, err := deep.RunReport(r.Path, 300*time.Second)
		if err != nil {
			r.Deep = &model.DeepReport{Available: false, Errors: []string{err.Error()}}
			fmt.Printf("    FAILED: %v\n", err)
			continue
		}
		r.Deep = rep
		r.Findings = append(r.Findings, model.Finding{
			Rule: "deep_escalated", Category: "analysis", Severity: 0,
			Detail: fmt.Sprintf("REA static: %d procedures, %d IOC string hits, %d suspicious funcs", rep.Procedures, len(rep.StringHits), len(rep.FuncHits)),
		})
		fmt.Printf("    REA: %d tools, %d procedures, %d string hits, %d func hits, %dms\n",
			rep.ServerTools, rep.Procedures, len(rep.StringHits), len(rep.FuncHits), rep.ElapsedMs)
		done++
	}
	fmt.Printf("DEEP ESCALATION done: %d analyzed\n\n", done)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "deep" {
		runDeep(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "watch" {
		runWatch(os.Args[2:])
		return
	}
	runScan(os.Args[1:])
}

func runWatch(args []string) {
	args = reorderArgs(args)
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	var (
		interval    int
		once        bool
		quarantine  bool
		notifyURL   string
		threat      int
		notifyAt    int
		workers     int
		maxSizeMB   int64
		skipAssets  bool
		excludes    string
		noCache     bool
		cachePath   string
		onlineFlag  bool
		vtKey       string
		mbKey       string
		vtIntervalS int
		noYara      bool
		yaraRules   string
		extractDep  int
		extractMB   int64
		quiet       bool
	)
	fs.IntVar(&interval, "interval", 60, "seconds between watch passes")
	fs.BoolVar(&once, "once", false, "single pass then exit")
	fs.BoolVar(&quarantine, "quarantine", false, "move files scoring >= threat into <root>/.quarantine")
	fs.StringVar(&notifyURL, "notify-url", "", "webhook URL (any JSON endpoint: Discord/CF worker/custom) for alerts")
	fs.IntVar(&threat, "threat", 70, "score that triggers quarantine")
	fs.IntVar(&notifyAt, "notify-at", 30, "score that triggers a notification")
	fs.IntVar(&workers, "workers", 3, "parallel workers")
	fs.Int64Var(&maxSizeMB, "max-size", 512, "skip files larger than N MB")
	fs.BoolVar(&skipAssets, "skip-assets", true, "skip game asset extensions")
	fs.StringVar(&excludes, "exclude", "", "comma-separated extra extensions to skip")
	fs.BoolVar(&noCache, "no-cache", false, "disable hash cache")
	fs.StringVar(&cachePath, "cache", ".gamecrack-cache.jsonl", "hash cache file path")
	fs.BoolVar(&onlineFlag, "online", false, "enable online hash reputation")
	fs.StringVar(&vtKey, "vt-key", "", "VirusTotal API key (default from VT_API_KEY env)")
	fs.StringVar(&mbKey, "mb-key", "", "MalwareBazaar Auth-Key (default from MB_API_KEY env)")
	fs.IntVar(&vtIntervalS, "vt-interval", 16, "min seconds between online lookups")
	fs.BoolVar(&noYara, "no-yara", false, "disable YARA scanning")
	fs.StringVar(&yaraRules, "yara-rules", "", "directory of external .yar rules")
	fs.IntVar(&extractDep, "extract-depth", 2, "scan inside containers N levels deep")
	fs.Int64Var(&extractMB, "extract-mb", 500, "max MB of inner files per container")
	fs.BoolVar(&quiet, "quiet", false, "minimal output")
	fs.Parse(args)

	root := fs.Arg(0)
	if root == "" {
		root = "."
	}
	if vtKey == "" {
		vtKey = os.Getenv("VT_API_KEY")
	}
	if mbKey == "" {
		mbKey = os.Getenv("MB_API_KEY")
	}
	var ex []string
	for _, e := range strings.Split(excludes, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			ex = append(ex, e)
		}
	}
	var oc *online.Client
	if onlineFlag {
		oc = online.New(vtKey, mbKey, secondsToDuration(vtIntervalS))
		if !oc.Enabled() {
			fmt.Fprintln(os.Stderr, "warning: -online requested but no API key configured")
		}
	}
	var yr *yara.Runner
	if !noYara {
		if r, err := yara.New(yaraRules, true); err == nil {
			yr = r
		} else if err != yara.ErrYaraMissing && !quiet {
			fmt.Fprintln(os.Stderr, "warning: yara:", err)
		}
	}
	cfg := watch.Config{
		Root:        root,
		IntervalSec: interval,
		Once:        once,
		Quarantine:  quarantine,
		NotifyURL:   notifyURL,
		ThreatScore: threat,
		NotifyScore: notifyAt,
		Quiet:       quiet,
		Scan: scan.Config{
			Root:         root,
			Workers:      workers,
			MaxSizeMB:    maxSizeMB,
			SkipAssets:   skipAssets,
			Excludes:     ex,
			UseCache:     !noCache,
			CachePath:    cachePath,
			Quiet:        quiet,
			FullReadMB:   32,
			Online:       oc,
			Yara:         yr,
			ExtractDepth: extractDep,
			ExtractMaxMB: extractMB,
		},
	}
	if err := watch.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "watch error:", err)
		os.Exit(1)
	}
}

func runScan(args []string) {
	os.Args = append(os.Args[:1], reorderArgs(args)...)
	var (
		workers       int
		maxSizeMB     int64
		skipAssets    bool
		excludes      string
		noCache       bool
		cachePath     string
		quiet         bool
		jsonOut       string
		mdOut         string
		top           int
		onlineFlag    bool
		vtKey         string
		mbKey         string
		vtIntervalS   int
		noYara        bool
		yaraRules     string
		extractDep    int
		extractMB     int64
		deepThreshold int
		deepMax       int
		deepBudget    int
	)
	flag.IntVar(&workers, "workers", 3, "parallel workers (default 3 for low-end CPU)")
	flag.Int64Var(&maxSizeMB, "max-size", 512, "skip files larger than N MB")
	flag.BoolVar(&skipAssets, "skip-assets", true, "skip game asset extensions (.pak/.mp4/.uasset/etc)")
	flag.StringVar(&excludes, "exclude", "", "comma-separated extra extensions to skip (e.g. .bin,.dat)")
	flag.BoolVar(&noCache, "no-cache", false, "disable hash cache")
	flag.StringVar(&cachePath, "cache", ".gamecrack-cache.jsonl", "hash cache file path")
	flag.BoolVar(&quiet, "quiet", false, "only print summary")
	flag.StringVar(&jsonOut, "json", "", "write JSON report to file")
	flag.StringVar(&mdOut, "md", "", "write Markdown report to file")
	flag.IntVar(&top, "top", 50, "max flagged files shown in summary")
	flag.BoolVar(&onlineFlag, "online", false, "enable online hash reputation (VirusTotal/MalwareBazaar); caches results in the hash cache")
	flag.StringVar(&vtKey, "vt-key", "", "VirusTotal API key (default from VT_API_KEY env)")
	flag.StringVar(&mbKey, "mb-key", "", "MalwareBazaar Auth-Key (default from MB_API_KEY env)")
	flag.IntVar(&vtIntervalS, "vt-interval", 16, "min seconds between online lookups (VT free tier = 4/min)")
	flag.BoolVar(&noYara, "no-yara", false, "disable YARA scanning (also off automatically when yara binary is missing)")
	flag.StringVar(&yaraRules, "yara-rules", "", "directory of external .yar rules (builtin rules always run too)")
	flag.IntVar(&extractDep, "extract-depth", 2, "scan inside archive/ISO containers N levels deep (0 = scan container file only)")
	flag.Int64Var(&extractMB, "extract-mb", 500, "max MB of inner files to extract+scan per container")
	flag.IntVar(&deepThreshold, "deep-threshold", 40, "auto-run REA static analysis on PE files scoring >= N (0 = off)")
	flag.IntVar(&deepMax, "deep-max", 3, "max files to auto-escalate per scan")
	flag.IntVar(&deepBudget, "deep-budget", 240, "total seconds budget for auto-escalation")
	flag.Parse()

	if vtKey == "" {
		vtKey = os.Getenv("VT_API_KEY")
	}
	if mbKey == "" {
		mbKey = os.Getenv("MB_API_KEY")
	}

	root := flag.Arg(0)
	if root == "" {
		root = "."
	}
	info, err := os.Stat(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "path error:", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		if i := strings.LastIndexByte(root, os.PathSeparator); i > 0 {
			root = root[:i]
		} else {
			root = "."
		}
	}

	cpu := runtime.NumCPU()
	if workers <= 0 {
		workers = 1
	}
	if workers > cpu {
		fmt.Fprintf(os.Stderr, "warning: %d workers > %d CPUs, capping\n", workers, cpu)
		workers = cpu
	}

	var ex []string
	for _, e := range strings.Split(excludes, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			ex = append(ex, e)
		}
	}

	var oc *online.Client
	if onlineFlag {
		oc = online.New(vtKey, mbKey, secondsToDuration(vtIntervalS))
		if !oc.Enabled() {
			fmt.Fprintln(os.Stderr, "warning: -online requested but no VT_API_KEY/MB_API_KEY or -vt-key/-mb-key given; online lookups disabled")
		}
	}

	var yr *yara.Runner
	if !noYara {
		r, err := yara.New(yaraRules, true)
		switch err {
		case nil:
			yr = r
		case yara.ErrYaraMissing:
			fmt.Fprintln(os.Stderr, "warning: yara binary not in PATH - YARA layer disabled (builtin rules still apply via internal engine)")
		default:
			fmt.Fprintln(os.Stderr, "warning: yara init error:", err)
		}
	}

	cfg := scan.Config{
		Root:         root,
		Workers:      workers,
		MaxSizeMB:    maxSizeMB,
		SkipAssets:   skipAssets,
		Excludes:     ex,
		UseCache:     !noCache,
		CachePath:    cachePath,
		Quiet:        quiet,
		FullReadMB:   32,
		Online:       oc,
		Yara:         yr,
		ExtractDepth: extractDep,
		ExtractMaxMB: extractMB,
	}

	fmt.Printf("GameCrack Scanner  target=%s  workers=%d  max_size=%dMB  skip_assets=%v  yara=%v  online=%v  extract_depth=%d\n",
		root, cfg.Workers, cfg.MaxSizeMB, cfg.SkipAssets, yr != nil, oc != nil && oc.Enabled(), cfg.ExtractDepth)
	s, err := scan.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scanner init error:", err)
		os.Exit(1)
	}
	defer s.Close()

	sum, err := s.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		os.Exit(1)
	}

	if deepThreshold > 0 {
		escalate(sum, deepThreshold, deepMax, deepBudget)
	}

	report.PrintSummary(sum, top)
	if oc != nil {
		fmt.Printf("online lookups this run: %d (cached results skip API)\n", oc.Lookups())
	}
	if jsonOut != "" {
		if err := report.WriteJSON(jsonOut, sum); err != nil {
			fmt.Fprintln(os.Stderr, "json write error:", err)
		} else {
			fmt.Println("JSON report:", jsonOut)
		}
	}
	if mdOut != "" {
		if err := report.WriteMarkdown(mdOut, sum, root); err != nil {
			fmt.Fprintln(os.Stderr, "md write error:", err)
		} else {
			fmt.Println("Markdown report:", mdOut)
		}
	}
}

func runDeep(args []string) {
	fs := flag.NewFlagSet("deep", flag.ExitOnError)
	var (
		outPath  string
		timeoutS int
	)
	fs.StringVar(&outPath, "out", "deep-report.json", "deep report output file")
	fs.IntVar(&timeoutS, "timeout", 300, "REA session timeout in seconds")
	fs.Parse(args)
	target := fs.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: scanner deep [flags] <file>")
		os.Exit(1)
	}
	if err := deep.Run(target, secondsToDuration(timeoutS), outPath); err != nil {
		fmt.Fprintln(os.Stderr, "deep error:", err)
		os.Exit(1)
	}
}

func reorderArgs(args []string) []string {
	boolFlags := map[string]bool{
		"-quiet": true, "--quiet": true,
		"-no-cache": true, "--no-cache": true,
		"-skip-assets": true, "--skip-assets": true,
		"-online": true, "--online": true,
		"-no-yara": true, "--no-yara": true,
	}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && !boolFlags[a] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}

func secondsToDuration(s int) time.Duration {
	if s <= 0 {
		return time.Second
	}
	return time.Duration(s) * time.Second
}
