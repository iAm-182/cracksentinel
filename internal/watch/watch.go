package watch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/scan"
)

type FileState struct {
	Size    int64  `json:"size"`
	ModUnix int64  `json:"mtime"`
	Score   int    `json:"score"`
	Verdict string `json:"verdict"`
	SHA256  string `json:"sha256,omitempty"`
}

type Event struct {
	Time    string `json:"time"`
	Path    string `json:"path"`
	Score   int    `json:"score"`
	Verdict string `json:"verdict"`
	Action  string `json:"action"`
}

type State struct {
	Files  map[string]FileState `json:"files"`
	Events []Event              `json:"events"`
}

const stateFileName = ".cracksentinel-watch.json"
const quarantineDir = ".quarantine"

func LoadState(dir string) *State {
	st := &State{Files: map[string]FileState{}}
	b, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err == nil {
		json.Unmarshal(b, st)
		if st.Files == nil {
			st.Files = map[string]FileState{}
		}
	}
	return st
}

func (s *State) Save(dir string) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(filepath.Join(dir, stateFileName), b, 0o644)
}

type Config struct {
	Root        string
	IntervalSec int
	Once        bool
	Quarantine  bool
	NotifyURL   string
	ThreatScore int
	NotifyScore int
	Scan        scan.Config
	Quiet       bool
}

func Run(cfg Config) error {
	if cfg.Root == "" {
		return fmt.Errorf("watch root required")
	}
	abs, err := filepath.Abs(cfg.Root)
	if err != nil {
		return err
	}
	cfg.Root = abs
	cfg.Scan.Root = abs

	st := LoadState(abs)
	if !cfg.Quiet {
		fmt.Printf("WATCH mode: %s (interval %ds, threat>=%d, notify>=%d, quarantine=%v)\n",
			abs, cfg.IntervalSec, cfg.ThreatScore, cfg.NotifyScore, cfg.Quarantine)
	}

	for pass := 1; ; pass++ {
		changed := collectChanged(abs, st)
		if len(changed) > 0 {
			sc, err := scan.New(cfg.Scan)
			if err != nil {
				return err
			}
			sum, err := sc.ScanFiles(changed)
			if err != nil {
				sc.Close()
				return err
			}
			sc.Close()
			for _, r := range sum.Results {
				if r.Skipped {
					continue
				}
				st.Files[r.Path] = FileState{Size: r.Size, ModUnix: modUnix(r.Path), Score: r.Score, Verdict: r.Verdict.String(), SHA256: r.SHA256}
				if r.Score < cfg.NotifyScore {
					continue
				}
				action := "flagged"
				if cfg.Quarantine && r.Score >= cfg.ThreatScore {
					if q, err := quarantine(abs, r); err == nil {
						action = "quarantined"
						delete(st.Files, r.Path)
						if !cfg.Quiet {
							fmt.Printf("  QUARANTINED %s -> %s\n", r.Path, q)
						}
					} else if !cfg.Quiet {
						fmt.Printf("  quarantine failed: %v\n", err)
					}
				} else if !cfg.Quiet {
					fmt.Printf("  [%s] %d %s\n", r.Verdict, r.Score, r.Path)
				}
				st.Events = append(st.Events, Event{Time: time.Now().Format(time.RFC3339), Path: r.Path, Score: r.Score, Verdict: r.Verdict.String(), Action: action})
				if cfg.NotifyURL != "" {
					go notify(cfg.NotifyURL, r)
				}
			}
			if !cfg.Quiet {
				fmt.Printf("  pass %d: %d scanned, %d flagged\n", pass, sum.FilesScanned, sum.Suspicious+sum.Malicious)
			}
		} else if !cfg.Quiet {
			fmt.Printf("  pass %d: no changes\n", pass)
		}
		st.Save(abs)
		if cfg.Once {
			return nil
		}
		time.Sleep(time.Duration(cfg.IntervalSec) * time.Second)
	}
}

func collectChanged(root string, st *State) []string {
	var out []string
	seen := map[string]bool{}
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || strings.EqualFold(name, "$RECYCLE.BIN") || strings.EqualFold(name, "System Volume Information")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasPrefix(name, ".cracksentinel-") {
			return nil
		}
		seen[path] = true
		info, err := d.Info()
		if err != nil {
			return nil
		}
		prev, ok := st.Files[path]
		if !ok || prev.Size != info.Size() || prev.ModUnix != info.ModTime().Unix() {
			out = append(out, path)
		}
		return nil
	})
	for p := range st.Files {
		if !seen[p] {
			delete(st.Files, p)
			st.Events = append(st.Events, Event{Time: time.Now().Format(time.RFC3339), Path: p, Action: "removed"})
		}
	}
	return out
}

func quarantine(root string, r model.FileResult) (string, error) {
	destDir := filepath.Join(root, quarantineDir, time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(destDir, filepath.Base(r.Path))
	if err := os.Rename(r.Path, dest); err != nil {
		if err := copyFile(r.Path, dest); err != nil {
			return "", err
		}
		os.Remove(r.Path)
	}
	meta := map[string]any{
		"original_path":  r.Path,
		"sha256":         r.SHA256,
		"score":          r.Score,
		"verdict":        r.Verdict.String(),
		"findings":       r.Findings,
		"quarantined_at": time.Now().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(dest+".json", b, 0o644)
	return dest, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func notify(url string, r model.FileResult) {
	body := map[string]any{
		"text":    fmt.Sprintf("CrackSentinel: %s scored %d (%s)", filepath.Base(r.Path), r.Score, r.Verdict),
		"path":    r.Path,
		"sha256":  r.SHA256,
		"score":   r.Score,
		"verdict": r.Verdict.String(),
	}
	top := ""
	for _, f := range r.Findings {
		if f.Severity > 0 {
			top = f.Rule + ": " + f.Detail
			break
		}
	}
	body["top_finding"] = top
	b, _ := json.Marshal(body)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(b)))
	if err == nil {
		resp.Body.Close()
	}
}

func modUnix(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.ModTime().Unix()
}
