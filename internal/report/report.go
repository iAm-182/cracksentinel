package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"gamecrack-scanner/internal/model"
)

func PrintSummary(sum *model.Summary, topN int) {
	fmt.Println()
	fmt.Println("================ SCAN SUMMARY ================")
	fmt.Printf("Target files scanned : %d\n", sum.FilesScanned)
	fmt.Printf("Files skipped        : %d\n", sum.FilesSkipped)
	fmt.Printf("Bytes scanned        : %.1f MB\n", float64(sum.BytesScanned)/1024/1024)
	fmt.Printf("Duration             : %d ms\n", sum.DurationMs)
	fmt.Printf("CLEAN                : %d\n", sum.Clean)
	fmt.Printf("SUSPICIOUS           : %d\n", sum.Suspicious)
	fmt.Printf("MALICIOUS            : %d\n", sum.Malicious)
	fmt.Println("----------------------------------------------")

	var flagged []model.FileResult
	for _, r := range sum.Results {
		if r.Skipped {
			continue
		}
		if r.Verdict != model.VerdictClean {
			flagged = append(flagged, r)
		}
	}
	sort.Slice(flagged, func(i, j int) bool { return flagged[i].Score > flagged[j].Score })
	if len(flagged) > topN {
		flagged = flagged[:topN]
	}
	if len(flagged) == 0 {
		fmt.Println("No flagged files.")
		return
	}
	fmt.Printf("Top %d flagged files:\n", len(flagged))
	for _, r := range flagged {
		fmt.Printf("\n[%s] score=%d  %s\n", r.Verdict, r.Score, r.Path)
		if r.Imphash != "" {
			fmt.Printf("    imphash=%s signed=%v packer=%s\n", r.Imphash, r.Signed, r.Packer)
		}
		if r.Judge != nil {
			fmt.Printf("    %s\n", r.Judge.Summary)
		}
		for _, f := range r.Findings {
			if f.Severity <= 0 {
				continue
			}
			fmt.Printf("    - [%s] %s: %s\n", f.Category, f.Rule, f.Detail)
		}
	}
}

func WriteJSON(path string, sum *model.Summary) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(sum)
}

func WriteMarkdown(path string, sum *model.Summary, target string) error {
	var sb strings.Builder
	sb.WriteString("# GameCrack Scanner Report\n\n")
	fmt.Fprintf(&sb, "- Target: `%s`\n", target)
	fmt.Fprintf(&sb, "- Files scanned: %d (skipped %d)\n", sum.FilesScanned, sum.FilesSkipped)
	fmt.Fprintf(&sb, "- Bytes scanned: %.1f MB\n", float64(sum.BytesScanned)/1024/1024)
	fmt.Fprintf(&sb, "- Duration: %d ms\n", sum.DurationMs)
	fmt.Fprintf(&sb, "- Verdict: CLEAN=%d SUSPICIOUS=%d MALICIOUS=%d\n\n", sum.Clean, sum.Suspicious, sum.Malicious)

	var flagged []model.FileResult
	for _, r := range sum.Results {
		if !r.Skipped && r.Verdict != model.VerdictClean {
			flagged = append(flagged, r)
		}
	}
	sort.Slice(flagged, func(i, j int) bool { return flagged[i].Score > flagged[j].Score })
	sb.WriteString("| Verdict | Score | File | Type | Judge | Top rule | Detail |\n")
	sb.WriteString("|---|---|---|---|---|---|---|\n")
	for _, r := range flagged {
		top, det := "-", "-"
		for _, f := range r.Findings {
			if f.Severity > 0 {
				top = f.Rule
				det = f.Detail
				break
			}
		}
		judge := "-"
		if r.Judge != nil {
			judge = fmt.Sprintf("%s (troj %.0f%%, mal %.0f%%, conf %.0f%%)",
				r.Judge.Classification, r.Judge.IsTrojanized*100, r.Judge.IsMalicious*100, r.Judge.Confidence*100)
		}
		fmt.Fprintf(&sb, "| %s | %d | `%s` | %s | %s | %s | %s |\n", r.Verdict, r.Score, r.Path, r.Type, judge, top, strings.ReplaceAll(det, "|", "\\|"))
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}
