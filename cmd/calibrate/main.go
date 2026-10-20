// Command calibrate measures the semantic adjudicator against a labelled
// corpus.
//
//	scanner-calibrate [-manifest corpus.json] [-root .] [-threshold 0.5]
//
// Every case in the manifest names a file, the ground truth, and why. The
// tool scans each file with the deterministic engine, hands the evidence to
// the model, and reports the confusion matrix, precision, recall, F1, the
// threshold that maximises F1 on this corpus, and every case where the
// model and the scanner disagree.
//
// The corpus is meant to grow: every real crack folder that gets triaged
// adds its files here, and the next run measures the tool against the
// user's own data instead of against a guess.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gamecrack-scanner/internal/jev"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/scan"
)

type manifest struct {
	Cases []caseSpec `json:"cases"`
}

type caseSpec struct {
	Path  string `json:"path"`
	Label string `json:"label"`
	Note  string `json:"note"`
}

func main() {
	var (
		manifestPath = flag.String("manifest", "corpus.json", "labelled corpus manifest")
		root         = flag.String("root", ".", "root directory the case paths are relative to")
		threshold    = flag.Float64("threshold", 0.5, "probability threshold to evaluate at")
		jevModel     = flag.String("jev-model", jev.DefaultModel, "model used for adjudication")
		jevURL       = flag.String("jev-url", jev.DefaultBaseURL, "System One endpoint")
		dump         = flag.String("dump", "", "write the full result as JSON to this path")
	)
	flag.Parse()

	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest read error:", err)
		os.Exit(1)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		fmt.Fprintln(os.Stderr, "manifest parse error:", err)
		os.Exit(1)
	}
	if len(m.Cases) == 0 {
		fmt.Fprintln(os.Stderr, "the manifest has no cases")
		os.Exit(1)
	}

	client := jev.New("", *jevURL, *jevModel)
	if !client.Enabled() {
		fmt.Fprintf(os.Stderr, "no API key (set %s)\n", jev.EnvKey)
		os.Exit(1)
	}

	cfg := scan.Config{
		Workers: 2, MaxSizeMB: 512, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 2, ExtractMaxMB: 500,
	}

	var cases []jev.Case
	for _, c := range m.Cases {
		p := c.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(*root, c.Path)
		}
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", c.Path, err)
			continue
		}
		res, ev, err := scan.ScanOne(cfg, p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", c.Path, err)
			continue
		}
		want := jev.LabelLegitimate
		switch c.Label {
		case "malicious", "mal", "bad":
			want = jev.LabelMalicious
		case "legitimate", "legit", "clean", "benign":
			want = jev.LabelLegitimate
		default:
			fmt.Fprintf(os.Stderr, "skipping %s: unknown label %q\n", c.Path, c.Label)
			continue
		}
		ev.Score = res.Score
		ev.Verdict = res.Verdict.String()
		cases = append(cases, jev.Case{
			Name:                   filepath.Base(c.Path),
			Evidence:               ev,
			Want:                   want,
			Note:                   c.Note,
			DeterministicVerdict:   res.Verdict.String(),
			DeterministicMalicious: res.Verdict == model.VerdictMalicious,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cal, err := client.Calibrate(ctx, cases, *threshold)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calibration error:", err)
		os.Exit(1)
	}
	fmt.Println(cal.Summary())

	if *dump != "" {
		b, _ := json.MarshalIndent(cal, "", "  ")
		if err := os.WriteFile(*dump, b, 0o644); err == nil {
			fmt.Println("\nwrote", *dump)
		}
	}
	if cal.F1 < 0.9 && cal.Total > 0 {
		fmt.Fprintln(os.Stderr, "\nwarning: the adjudicator is not calibrated on this corpus yet (F1 below 0.90)")
	}
}
