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
	"gamecrack-scanner/internal/jev"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/report"
	"gamecrack-scanner/internal/scan"
	"gamecrack-scanner/internal/telemetry"
	"gamecrack-scanner/internal/ui"
	"gamecrack-scanner/internal/version"
	"gamecrack-scanner/internal/watch"
	"gamecrack-scanner/internal/yara"
)

func isKnownRuntimeDLL(r model.FileResult) bool {
	for _, f := range r.Findings {
		if f.Rule == "known_runtime_dll" {
			return true
		}
	}
	return false
}

func escalate(sum *model.Summary, threshold, maxN, budgetSec int) {
	var flagged []int
	for i, r := range sum.Results {
		if r.Skipped || r.Deep != nil || r.Score < threshold || r.Type != "pe" || isKnownRuntimeDLL(r) {
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
	for _, a := range os.Args[1:] {
		switch a {
		case "-version", "--version", "-v":
			fmt.Println(version.String())
			return
		case "-help", "--help", "-h":
			usage()
			return
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "deep" {
		runDeep(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "watch" {
		runWatch(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "ui" {
		runUI(os.Args[2:])
		return
	}
	runScan(os.Args[1:])
}

func usage() {
	fmt.Printf(`CrackSentinel — defensive malware scanner for cracked-game folders

usage:
  scanner.exe ui [flags]                 launch Drag & Drop Web UI + extension bridge
  scanner.exe <path...> [flags]          scan one or more folders/files (single or mass)
  scanner.exe deep <file> [flags]        REA/Ghidra static deep-dive
  scanner.exe watch <folder> [flags]     real-time download guard + quarantine + toast
  scanner.exe -version                   print build identity

scan flags:
  -workers N        parallel workers (default 3)
  -max-size MB      skip files larger than N MB (default 512)
  -skip-assets      skip game asset extensions (default true)
  -exclude LIST     comma-separated extra extensions to skip
  -online           VirusTotal / MalwareBazaar hash reputation
  -vt-key K         VirusTotal API key (or VT_API_KEY env)
  -mb-key K         MalwareBazaar key (or MB_API_KEY env)
  -vt-interval S    min seconds between online lookups (default 16)
  -no-cache         disable the SHA-256 cache
  -cache PATH       cache file path
  -yara-rules DIR   directory of external .yar rules
  -no-yara          disable the YARA layer
  -extract-depth N  scan inside containers N levels deep (default 2, 0 = off)
  -extract-mb MB    max MB of inner files per container (default 500)
  -tmp-dir DIR      where container extraction happens (default: system temp)
  -deep-threshold N auto-run REA static analysis on PEs scoring >= N (default 40, 0 = off)
  -deep-max N       max files to auto-escalate per scan (default 3)
  -deep-budget S    total seconds budget for auto-escalation (default 240)
  -detonate         behavioral detonation of suspicious PEs (docker + wine)
  -detonate-min N   static score that triggers detonation (default 30)
  -detonator-dir D  detonator Dockerfile context (default "detonator")
  -no-unpack        disable UPX auto-unpack
  -telemetry-url U  shared-reputation worker base URL (opt-in)
  -telemetry-key K  shared-reputation ingest key
  -json PATH        write JSON report
  -md PATH          write Markdown report
  -html PATH        write standalone HTML report
  -top N            max flagged files shown in the console summary (default 50)
  -quiet            only print the summary

semantic adjudication (advisory, needs TYPESAFE_API_KEY):
  -jev              ask the model to tell a legit crack from a trojanized one
  -jev-min N        only adjudicate files scoring at least N (default 30)
  -jev-max N        only adjudicate files scoring at most N (default 100)
  -jev-override     let a confident adjudication change the final verdict
  -jev-confidence F minimum confidence for an override (default 0.9)
  -jev-max-files N  max files adjudicated per scan (default 8)
  -jev-concurrency N max concurrent adjudication calls (default 4)
  -jev-model NAME   model id (default jev-latest)
  -jev-url URL      System One endpoint
`)
}

func runWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	var (
		interval          int
		settle            int
		once              bool
		quarantine        bool
		toast             bool
		notifyURL         string
		threat            int
		notifyAt          int
		workers           int
		maxSizeMB         int64
		skipAssets        bool
		excludes          string
		noCache           bool
		cachePath         string
		tmpDir            string
		carve             bool
		noUnpack          bool
		onlineFlag        bool
		vtKey             string
		mbKey             string
		vtIntervalS       int
		noYara            bool
		yaraRules         string
		extractDep        int
		extractMB         int64
		quiet             bool
		telemetryURL      string
		telemetryKey      string
		jevOn             bool
		jevMin            int
		jevMax            int
		jevOverride       bool
		jevConfidence     float64
		jevMaxFiles       int
		jevConc           int
		jevModel          string
		jevURL            string
		jevValidate       bool
		jevClaimThreshold float64
		jevThreshold      float64
	)
	fs.IntVar(&interval, "interval", 5, "seconds between watch passes")
	fs.IntVar(&settle, "settle", 2, "seconds a newly downloaded file must remain unchanged before scanning")
	fs.BoolVar(&once, "once", false, "single pass then exit")
	fs.BoolVar(&quarantine, "quarantine", false, "move files scoring >= threat into <root>/.quarantine")
	fs.BoolVar(&toast, "toast", true, "show Windows desktop toast alert on suspicious/malicious downloads")
	fs.StringVar(&notifyURL, "notify-url", "", "webhook URL (any JSON endpoint: Discord/CF worker/custom) for alerts")
	fs.IntVar(&threat, "threat", 70, "score that triggers quarantine")
	fs.IntVar(&notifyAt, "notify-at", 30, "score that triggers a notification")
	fs.IntVar(&workers, "workers", 3, "parallel workers")
	fs.Int64Var(&maxSizeMB, "max-size", 512, "skip files larger than N MB")
	fs.BoolVar(&skipAssets, "skip-assets", true, "skip game asset extensions")
	fs.StringVar(&excludes, "exclude", "", "comma-separated extra extensions to skip")
	fs.BoolVar(&noCache, "no-cache", false, "disable hash cache")
	fs.StringVar(&cachePath, "cache", ".gamecrack-cache.jsonl", "hash cache file path")
	fs.StringVar(&tmpDir, "tmp-dir", "", "base directory for container extraction (recommended: drive with free space)")
	fs.BoolVar(&carve, "carve", true, "carve large files for embedded executables")
	fs.BoolVar(&noUnpack, "no-unpack", false, "disable UPX auto-unpack")
	fs.BoolVar(&onlineFlag, "online", false, "enable online hash reputation")
	fs.StringVar(&vtKey, "vt-key", "", "VirusTotal API key (default from VT_API_KEY env)")
	fs.StringVar(&mbKey, "mb-key", "", "MalwareBazaar Auth-Key (default from MB_API_KEY env)")
	fs.IntVar(&vtIntervalS, "vt-interval", 16, "min seconds between online lookups")
	fs.BoolVar(&noYara, "no-yara", false, "disable YARA scanning")
	fs.StringVar(&yaraRules, "yara-rules", "", "directory of external .yar rules")
	fs.IntVar(&extractDep, "extract-depth", 2, "scan inside containers N levels deep")
	fs.Int64Var(&extractMB, "extract-mb", 500, "max MB of inner files per container")
	fs.BoolVar(&quiet, "quiet", false, "minimal output")
	fs.StringVar(&telemetryURL, "telemetry-url", "", "shared-reputation worker base URL (opt-in)")
	fs.StringVar(&telemetryKey, "telemetry-key", "", "shared-reputation ingest key")
	fs.BoolVar(&jevOn, "jev", false, "enable the semantic adjudication layer (needs "+jev.EnvKey+")")
	fs.IntVar(&jevMin, "jev-min", 30, "only adjudicate files scoring at least this much")
	fs.IntVar(&jevMax, "jev-max", 100, "only adjudicate files scoring at most this much")
	fs.BoolVar(&jevOverride, "jev-override", false, "let a confident adjudication change the final verdict")
	fs.Float64Var(&jevConfidence, "jev-confidence", 0.9, "minimum confidence for an override to apply")
	fs.IntVar(&jevMaxFiles, "jev-max-files", 8, "max files adjudicated per pass")
	fs.IntVar(&jevConc, "jev-concurrency", 4, "max concurrent adjudication calls")
	fs.StringVar(&jevModel, "jev-model", jev.DefaultModel, "model used for adjudication")
	fs.StringVar(&jevURL, "jev-url", jev.DefaultBaseURL, "TypeSafe System One endpoint")
	fs.BoolVar(&jevValidate, "jev-validate", true, "validate every payload claim individually")
	fs.Float64Var(&jevClaimThreshold, "jev-claim-threshold", 0.5, "support probability a claim needs to keep counting")
	fs.Float64Var(&jevThreshold, "jev-threshold", 0.3, "trojanized probability that counts as a yes (calibrated)")
	args = reorderArgs(args, boolFlagSet(fs))
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
	if telemetryURL == "" {
		telemetryURL = os.Getenv("TELEMETRY_URL")
	}
	if telemetryKey == "" {
		telemetryKey = os.Getenv("TELEMETRY_KEY")
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
	var judge *jev.Client
	if jevOn {
		judge = jev.New("", jevURL, jevModel)
		if !judge.Enabled() {
			judge = nil
			fmt.Fprintf(os.Stderr, "warning: -jev requested but no API key (set %s); adjudication disabled\n", jev.EnvKey)
		}
	}
	cfg := watch.Config{
		Root:        root,
		IntervalSec: interval,
		SettleSec:   settle,
		Once:        once,
		Quarantine:  quarantine,
		Toast:       toast,
		NotifyURL:   notifyURL,
		ThreatScore: threat,
		NotifyScore: notifyAt,
		Quiet:       quiet,
		Scan: scan.Config{
			Root:                root,
			Workers:             workers,
			MaxSizeMB:           maxSizeMB,
			SkipAssets:          skipAssets,
			Excludes:            ex,
			UseCache:            !noCache,
			CachePath:           cachePath,
			TempDir:             tmpDir,
			Carve:               carve,
			CarveMaxMB:          16384,
			NoUnpack:            noUnpack,
			Quiet:               quiet,
			FullReadMB:          32,
			Online:              oc,
			Yara:                yr,
			ExtractDepth:        extractDep,
			ExtractMaxMB:        extractMB,
			Telemetry:           telemetry.New(telemetryURL, telemetryKey),
			Judge:               judge,
			JudgeMin:            jevMin,
			JudgeMax:            jevMax,
			JudgeOverride:       jevOverride,
			JudgeMinConfidence:  jevConfidence,
			JudgeMaxFiles:       jevMaxFiles,
			JudgeConcurrency:    jevConc,
			JudgeValidate:       jevValidate,
			JudgeClaimThreshold: jevClaimThreshold,
			JudgeThreshold:      jevThreshold,
		},
	}
	if err := watch.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "watch error:", err)
		os.Exit(1)
	}
}

func runScan(args []string) {
	var (
		workers           int
		maxSizeMB         int64
		skipAssets        bool
		excludes          string
		noCache           bool
		cachePath         string
		quiet             bool
		jsonOut           string
		mdOut             string
		htmlOut           string
		top               int
		onlineFlag        bool
		vtKey             string
		mbKey             string
		vtIntervalS       int
		noYara            bool
		yaraRules         string
		extractDep        int
		extractMB         int64
		deepThreshold     int
		deepMax           int
		deepBudget        int
		detonateFlag      bool
		detonateMin       int
		detonatorDir      string
		noUnpack          bool
		telemetryURL      string
		telemetryKey      string
		tmpDir            string
		jevOn             bool
		jevMin            int
		jevMax            int
		jevOverride       bool
		jevConfidence     float64
		jevMaxFiles       int
		jevConc           int
		jevModel          string
		jevURL            string
		jevValidate       bool
		jevClaimThreshold float64
		jevThreshold      float64
		jevCalib          string
		carve             bool
		carveMaxMB        int64
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
	flag.StringVar(&htmlOut, "html", "", "write standalone HTML report to file")
	flag.IntVar(&top, "top", 50, "max flagged files shown in summary")
	flag.BoolVar(&onlineFlag, "online", false, "enable online hash reputation (VirusTotal/MalwareBazaar); caches results in the hash cache")
	flag.StringVar(&vtKey, "vt-key", "", "VirusTotal API key (default from VT_API_KEY env)")
	flag.StringVar(&mbKey, "mb-key", "", "MalwareBazaar Auth-Key (default from MB_API_KEY env)")
	flag.IntVar(&vtIntervalS, "vt-interval", 16, "min seconds between online lookups (VT free tier = 4/min)")
	flag.BoolVar(&noYara, "no-yara", false, "disable YARA scanning (also off automatically when yara binary is missing)")
	flag.StringVar(&yaraRules, "yara-rules", "", "directory of external .yar rules (builtin rules always run too)")
	flag.IntVar(&extractDep, "extract-depth", 2, "scan inside archive/ISO containers N levels deep (0 = scan container file only)")
	flag.Int64Var(&extractMB, "extract-mb", 500, "max MB of inner files to extract+scan per container")
	flag.StringVar(&tmpDir, "tmp-dir", "", "base directory for container extraction (default: system temp)")
	flag.IntVar(&deepThreshold, "deep-threshold", 40, "auto-run REA static analysis on PE files scoring >= N (0 = off)")
	flag.IntVar(&deepMax, "deep-max", 3, "max files to auto-escalate per scan")
	flag.IntVar(&deepBudget, "deep-budget", 240, "total seconds budget for auto-escalation")
	flag.BoolVar(&detonateFlag, "detonate", false, "behavioral detonation of suspicious PEs in an isolated Docker+wine sandbox")
	flag.IntVar(&detonateMin, "detonate-min", 30, "static score that triggers detonation")
	flag.StringVar(&detonatorDir, "detonator-dir", "detonator", "path to detonator Dockerfile context (for image build)")
	flag.BoolVar(&noUnpack, "no-unpack", false, "disable UPX auto-unpack (requires upx binary in PATH)")
	flag.StringVar(&telemetryURL, "telemetry-url", "", "shared-reputation worker base URL (default from TELEMETRY_URL env; opt-in)")
	flag.StringVar(&telemetryKey, "telemetry-key", "", "shared-reputation ingest key (default from TELEMETRY_KEY env)")
	flag.BoolVar(&jevOn, "jev", false, "enable the semantic adjudication layer (needs "+jev.EnvKey+"; advisory, it does not replace the deterministic verdict)")
	flag.IntVar(&jevMin, "jev-min", 30, "only adjudicate files scoring at least this much")
	flag.IntVar(&jevMax, "jev-max", 100, "only adjudicate files scoring at most this much")
	flag.BoolVar(&jevOverride, "jev-override", false, "let a confident adjudication change the final verdict (off by default: a model is not evidence)")
	flag.Float64Var(&jevConfidence, "jev-confidence", 0.9, "minimum confidence for an override to apply")
	flag.IntVar(&jevMaxFiles, "jev-max-files", 8, "max files adjudicated per scan")
	flag.IntVar(&jevConc, "jev-concurrency", 4, "max concurrent adjudication calls")
	flag.StringVar(&jevModel, "jev-model", jev.DefaultModel, "model used for adjudication")
	flag.StringVar(&jevURL, "jev-url", jev.DefaultBaseURL, "TypeSafe System One endpoint")
	flag.BoolVar(&jevValidate, "jev-validate", true, "validate every payload claim individually; a claim that cannot be defended stops counting towards the score")
	flag.Float64Var(&jevClaimThreshold, "jev-claim-threshold", 0.5, "support probability a claim needs to keep counting")
	flag.Float64Var(&jevThreshold, "jev-threshold", 0.3, "trojanized probability that counts as a yes (calibrated, see cmd/calibrate)")
	flag.StringVar(&jevCalib, "jev-calibration", "", "fitted probability calibrator (JSON written by scripts/jevlab_report.py); maps the raw model score onto a calibrated probability")
	flag.BoolVar(&carve, "carve", true, "search files that are too large to read for embedded executables (a repack hides the payload in the game data)")
	flag.Int64Var(&carveMaxMB, "carve-max-mb", 16384, "largest file that is carved, in MB")
	// The flags are registered now, so the boolean set is known and the
	// arguments can be reordered safely.
	os.Args = append(os.Args[:1], reorderArgs(args, boolFlagSet(flag.CommandLine))...)
	flag.Parse()

	if vtKey == "" {
		vtKey = os.Getenv("VT_API_KEY")
	}
	if mbKey == "" {
		mbKey = os.Getenv("MB_API_KEY")
	}
	if telemetryURL == "" {
		telemetryURL = os.Getenv("TELEMETRY_URL")
	}
	if telemetryKey == "" {
		telemetryKey = os.Getenv("TELEMETRY_KEY")
	}

	targets := flag.Args()
	if len(targets) == 0 {
		targets = []string{"."}
	}
	root := targets[0]
	var singleFile bool
	if len(targets) == 1 {
		info, err := os.Stat(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "path error:", err)
			os.Exit(1)
		}
		singleFile = !info.IsDir()
		if singleFile && !info.Mode().IsRegular() {
			fmt.Fprintln(os.Stderr, "path error: not a regular file:", root)
			os.Exit(1)
		}
	} else {
		for _, t := range targets {
			if _, err := os.Stat(t); err != nil {
				fmt.Fprintln(os.Stderr, "path error:", err)
				os.Exit(1)
			}
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

	var tel *telemetry.Client
	if telemetryURL != "" {
		tel = telemetry.New(telemetryURL, telemetryKey)
		if !tel.Enabled() {
			fmt.Fprintln(os.Stderr, "warning: -telemetry-url given but no key (use -telemetry-key or TELEMETRY_KEY env); telemetry disabled")
		}
	}

	var judge *jev.Client
	if jevOn {
		judge = jev.New("", jevURL, jevModel)
		if !judge.Enabled() {
			judge = nil
			fmt.Fprintf(os.Stderr, "warning: -jev requested but no API key (set %s or TYPESAFE_API_KEY); adjudication disabled\n", jev.EnvKey)
		}
	}
	var calib *jev.Calibrator
	if jevCalib != "" {
		c, err := jev.LoadCalibrator(jevCalib)
		if err != nil {
			fmt.Fprintln(os.Stderr, "calibration load error:", err)
			os.Exit(1)
		}
		calib = c
		fmt.Println(c.Describe())
	}

	cfg := scan.Config{
		Root:                root,
		Workers:             workers,
		MaxSizeMB:           maxSizeMB,
		SkipAssets:          skipAssets,
		Excludes:            ex,
		UseCache:            !noCache,
		CachePath:           cachePath,
		Quiet:               quiet,
		FullReadMB:          32,
		Online:              oc,
		Yara:                yr,
		ExtractDepth:        extractDep,
		ExtractMaxMB:        extractMB,
		Detonate:            detonateFlag,
		DetonateMin:         detonateMin,
		DetonatorDir:        detonatorDir,
		NoUnpack:            noUnpack,
		Telemetry:           tel,
		TempDir:             tmpDir,
		Judge:               judge,
		JudgeMin:            jevMin,
		JudgeMax:            jevMax,
		JudgeOverride:       jevOverride,
		JudgeMinConfidence:  jevConfidence,
		JudgeMaxFiles:       jevMaxFiles,
		JudgeConcurrency:    jevConc,
		JudgeValidate:       jevValidate,
		JudgeClaimThreshold: jevClaimThreshold,
		JudgeThreshold:      jevThreshold,
		JudgeCalibration:    calib,
		Carve:               carve,
		CarveMaxMB:          carveMaxMB,
	}

	fmt.Printf("CrackSentinel %s  target=%s  workers=%d  max_size=%dMB  skip_assets=%v  yara=%v  online=%v  extract_depth=%d",
		version.Short(), root, cfg.Workers, cfg.MaxSizeMB, cfg.SkipAssets, yr != nil, oc != nil && oc.Enabled(), cfg.ExtractDepth)
	if tel.Enabled() {
		fmt.Printf("  telemetry=on")
	}
	if judge != nil {
		fmt.Printf("  jev=on")
	}
	fmt.Println()
	s, err := scan.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scanner init error:", err)
		os.Exit(1)
	}
	defer s.Close()
	if tp := s.TempPath(); tp != "" {
		fmt.Println("extraction temp:", tp)
	}

	var sum *model.Summary
	if len(targets) > 1 {
		sum, err = s.ScanPaths(targets)
	} else if singleFile {
		sum, err = s.ScanFiles([]string{root})
	} else {
		sum, err = s.Run()
	}
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
	if htmlOut != "" {
		if err := report.WriteHTML(htmlOut, sum, root, version.String()); err != nil {
			fmt.Fprintln(os.Stderr, "html write error:", err)
		} else {
			fmt.Println("HTML report:", htmlOut)
		}
	}
}

func runUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	var (
		addr           string
		workers        int
		maxSizeMB      int64
		extractDepth   int
		extractMB      int64
		tmpDir         string
		cachePath      string
		corpusPath     string
		noOpen         bool
		watchDir       string
		publicMode     bool
		allowedOrigins string
		accessKey      string
		maxUploadMB    int64
		maxConcurrent  int
		noYara         bool
		yaraRules      string
		onlineFlag     bool
		vtKey          string
		mbKey          string
		vtIntervalS    int
	)
	fs.StringVar(&addr, "addr", "127.0.0.1:8787", "loopback listen address")
	fs.IntVar(&workers, "workers", 3, "parallel workers")
	fs.Int64Var(&maxSizeMB, "max-size", 512, "skip files larger than N MB")
	fs.IntVar(&extractDepth, "extract-depth", 2, "archive expansion depth")
	fs.Int64Var(&extractMB, "extract-mb", 500, "max MB per archive extraction")
	fs.StringVar(&tmpDir, "tmp-dir", "", "temp directory for drag-drop uploads & archive extraction")
	fs.StringVar(&cachePath, "cache", ".gamecrack-cache.jsonl", "hash cache file path")
	fs.StringVar(&corpusPath, "corpus", "corpus.json", "corpus manifest path for UI labeling")
	fs.BoolVar(&noOpen, "no-open", false, "do not auto-open browser window")
	fs.StringVar(&watchDir, "watch", "", "optional folder to monitor automatically with Download Guard")
	fs.BoolVar(&publicMode, "public", false, "public/hosted web mode (disables local filesystem path scanning, picker, quarantine & watch)")
	fs.StringVar(&allowedOrigins, "allowed-origin", "", "comma-separated additional allowed CORS origins (e.g. https://sentinel.breakthematrix.id)")
	fs.StringVar(&accessKey, "access-key", "", "optional access key for private hosted deployments (or SENTINEL_ACCESS_KEY env)")
	fs.Int64Var(&maxUploadMB, "max-upload-mb", 0, "max multipart upload size in MB (default 100 in -public mode, 0 = unlimited local)")
	fs.IntVar(&maxConcurrent, "max-concurrent", 0, "max concurrent web scans (default 2 in -public mode)")
	fs.BoolVar(&noYara, "no-yara", false, "disable YARA layer")
	fs.StringVar(&yaraRules, "yara-rules", "", "directory of external .yar rules")
	fs.BoolVar(&onlineFlag, "online", false, "enable online hash reputation")
	fs.StringVar(&vtKey, "vt-key", "", "VirusTotal API key")
	fs.StringVar(&mbKey, "mb-key", "", "MalwareBazaar API key")
	fs.IntVar(&vtIntervalS, "vt-interval", 16, "min seconds between online lookups")
	fs.Parse(args)

	if vtKey == "" {
		vtKey = os.Getenv("VT_API_KEY")
	}
	if mbKey == "" {
		mbKey = os.Getenv("MB_API_KEY")
	}
	if accessKey == "" {
		accessKey = os.Getenv("SENTINEL_ACCESS_KEY")
	}
	var origins []string
	for _, o := range strings.Split(allowedOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}
	var oc *online.Client
	if onlineFlag || vtKey != "" || mbKey != "" {
		oc = online.New(vtKey, mbKey, secondsToDuration(vtIntervalS))
	}
	var yr *yara.Runner
	if !noYara {
		if r, err := yara.New(yaraRules, true); err == nil {
			yr = r
		}
	}
	srv := ui.New(ui.Options{
		Addr:           addr,
		Workers:        workers,
		MaxSizeMB:      maxSizeMB,
		ExtractDepth:   extractDepth,
		ExtractMaxMB:   extractMB,
		TempDir:        tmpDir,
		CachePath:      cachePath,
		CorpusPath:     corpusPath,
		Online:         oc,
		Yara:           yr,
		OpenBrowser:    !noOpen && !publicMode,
		WatchDir:       watchDir,
		PublicMode:     publicMode,
		AllowedOrigins: origins,
		AccessKey:      accessKey,
		MaxUploadMB:    maxUploadMB,
		MaxConcurrent:  maxConcurrent,
	})
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "ui server error:", err)
		os.Exit(1)
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

// boolFlagSet collects the registered boolean flags.
//
// The argument reordering has to know which flags take a value and which
// do not, because a boolean flag followed by another flag would otherwise
// swallow it. The list used to be hardcoded, and every boolean flag that
// was added later was silently missing from it: "-jev" ate the flag after
// it, and the value of a completely unrelated flag ended up in the wrong
// place. Deriving the set from the registered flags removes the whole
// class of bug.
func boolFlagSet(fs *flag.FlagSet) map[string]bool {
	out := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			out["-"+f.Name] = true
			out["--"+f.Name] = true
		}
	})
	return out
}

// reorderArgs moves the positional arguments to the end so that a folder
// path can be written first and the flags can be written in any order.
func reorderArgs(args []string, boolFlags map[string]bool) []string {
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
