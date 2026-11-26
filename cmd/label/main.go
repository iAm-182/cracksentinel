package main

// cmd/label — Interactive ground-truth corpus labeling tool (Gap G6).
//
// Reads a disputed queue (disputed.json or batch-report.json from cmd/batch),
// displays each file's findings and optional Jev advisory proposal, and lets a
// HUMAN accept or correct the label into corpus.json.
//
// Rule: Jev NEVER becomes a label automatically. Only explicit human input
// writes to corpus.json.

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DisputedItem struct {
	Path      string `json:"path"`
	Score     int    `json:"score"`
	Verdict   string `json:"verdict"`
	TopRule   string `json:"top_rule"`
	TopDetail string `json:"top_detail"`
	Reason    string `json:"reason"`
	Judge     *struct {
		Classification string  `json:"classification"`
		IsTrojanized   float64 `json:"is_trojanized"`
		Confidence     float64 `json:"confidence"`
	} `json:"judge,omitempty"`
}

type CorpusCase struct {
	Path  string `json:"path"`
	Root  string `json:"root,omitempty"`
	Label string `json:"label"`
	Note  string `json:"note"`
}

type CorpusDoc struct {
	Comment string       `json:"_comment,omitempty"`
	Cases   []CorpusCase `json:"cases"`
}

func main() {
	var (
		inPath     string
		corpusPath string
	)
	flag.StringVar(&inPath, "in", "batch-reports/disputed.json", "disputed.json or batch-report.json from cmd/batch")
	flag.StringVar(&corpusPath, "corpus", "corpus.json", "corpus manifest to update")
	flag.Parse()

	items, err := loadDisputed(inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read error:", err)
		os.Exit(1)
	}
	if len(items) == 0 {
		fmt.Println("No disputed items to label.")
		return
	}

	doc, err := loadCorpus(corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "corpus error:", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)
	added := 0
	for i, it := range items {
		fmt.Printf("\n[%d/%d] %s\n", i+1, len(items), it.Path)
		fmt.Printf("  Scanner : %s (score=%d)  top=%s: %s\n", it.Verdict, it.Score, it.TopRule, it.TopDetail)
		if it.Reason != "" {
			fmt.Printf("  Why     : %s\n", it.Reason)
		}
		if it.Judge != nil {
			fmt.Printf("  Jev hint: %s (trojanized=%.0f%%, conf=%.0f%%) [advisory only]\n",
				it.Judge.Classification, it.Judge.IsTrojanized*100, it.Judge.Confidence*100)
		}
		fmt.Print("  Label [l=legitimate, m=malicious, s=skip, q=quit]: ")
		line, _ := reader.ReadString('\n')
		choice := strings.ToLower(strings.TrimSpace(line))
		if choice == "q" {
			break
		}
		var label string
		switch choice {
		case "l", "legit", "legitimate":
			label = "legitimate"
		case "m", "mal", "malicious":
			label = "malicious"
		default:
			fmt.Println("  -> skipped")
			continue
		}
		fmt.Print("  Optional note (Enter to auto-fill): ")
		note, _ := reader.ReadString('\n')
		note = strings.TrimSpace(note)
		if note == "" {
			note = fmt.Sprintf("REAL (%s): scanner %s %d (%s)", time.Now().Format("2006-01-02"), it.Verdict, it.Score, it.TopRule)
		}
		upsertCase(&doc, it.Path, label, note)
		added++
		if err := saveCorpus(corpusPath, doc); err != nil {
			fmt.Fprintln(os.Stderr, "save error:", err)
			os.Exit(1)
		}
		fmt.Printf("  -> saved as %s\n", label)
	}
	fmt.Printf("\nDone: %d label(s) saved to %s (total %d cases)\n", added, corpusPath, len(doc.Cases))
}

func loadDisputed(path string) ([]DisputedItem, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []DisputedItem
	if err := json.Unmarshal(b, &list); err == nil {
		return list, nil
	}
	var wrapper struct {
		Disputed []DisputedItem `json:"disputed"`
	}
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Disputed, nil
}

func loadCorpus(path string) (CorpusDoc, error) {
	var doc CorpusDoc
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return doc, nil
	}
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return doc, err
	}
	return doc, nil
}

func upsertCase(doc *CorpusDoc, targetPath, label, note string) {
	root := ""
	rel := filepath.ToSlash(targetPath)
	if filepath.IsAbs(targetPath) {
		root = filepath.ToSlash(filepath.Dir(targetPath))
		rel = filepath.Base(targetPath)
	}
	for i := range doc.Cases {
		if doc.Cases[i].Path == rel && doc.Cases[i].Root == root {
			doc.Cases[i].Label = label
			doc.Cases[i].Note = note
			return
		}
	}
	doc.Cases = append(doc.Cases, CorpusCase{Path: rel, Root: root, Label: label, Note: note})
}

func saveCorpus(path string, doc CorpusDoc) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
