package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"gamecrack-scanner/internal/deep"
	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/report"
	"gamecrack-scanner/internal/scan"
	"gamecrack-scanner/internal/yara"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "deep" {
		runDeep(os.Args[2:])
		return
	}
	runScan(os.Args[1:])
}

func runScan(args []string) {
	os.Args = append(os.Args[:1], reorderArgs(args)...)
	var (
		workers     int
		maxSizeMB   int64
		skipAssets  bool
		excludes    string
		noCache     bool
		cachePath   string
		quiet       bool
		jsonOut     string
		mdOut       string
		top         int
		onlineFlag  bool
		vtKey       string
		mbKey       string
		vtIntervalS int
		noYara      bool
		yaraRules   string
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
		Root:       root,
		Workers:    workers,
		MaxSizeMB:  maxSizeMB,
		SkipAssets: skipAssets,
		Excludes:   ex,
		UseCache:   !noCache,
		CachePath:  cachePath,
		Quiet:      quiet,
		FullReadMB: 32,
		Online:     oc,
		Yara:       yr,
	}

	fmt.Printf("GameCrack Scanner  target=%s  workers=%d  max_size=%dMB  skip_assets=%v  yara=%v  online=%v\n",
		root, cfg.Workers, cfg.MaxSizeMB, cfg.SkipAssets, yr != nil, oc != nil && oc.Enabled())
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
