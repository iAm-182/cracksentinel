package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/procutil"
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
	Time       string `json:"time"`
	Path       string `json:"path"`
	Score      int    `json:"score"`
	Verdict    string `json:"verdict"`
	Action     string `json:"action"`
	OriginURL  string `json:"origin_url,omitempty"`
	TopFinding string `json:"top_finding,omitempty"`
}

type State struct {
	Files  map[string]FileState `json:"files"`
	Events []Event              `json:"events"`
}

const stateFileName = ".cracksentinel-watch.json"
const quarantineDir = ".quarantine"

// partialDownloadExts are temporary extensions created by browsers and
// download managers while a file is still being written to disk.
var partialDownloadExts = map[string]bool{
	".crdownload": true,
	".part":       true,
	".!qb":        true,
	".aria2":      true,
	".download":   true,
	".tmp":        true,
	".opdownload": true,
	".bc!":        true,
	".filepart":   true,
	".utpart":     true,
}

// IsPartialDownload reports whether path looks like an unfinished browser or
// torrent download that should be skipped until transfer completes.
func IsPartialDownload(path string) bool {
	low := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(low)
	if partialDownloadExts[ext] {
		return true
	}
	if strings.HasSuffix(low, ".!qb") || strings.HasSuffix(low, ".crdownload") || strings.HasSuffix(low, ".part") {
		return true
	}
	return false
}

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
	// Keep the persisted event log bounded so it does not grow indefinitely.
	if len(s.Events) > 500 {
		s.Events = s.Events[len(s.Events)-500:]
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(filepath.Join(dir, stateFileName), b, 0o644)
}

type Config struct {
	Root        string
	IntervalSec int
	Once        bool
	Quarantine  bool
	NotifyURL   string
	Toast       bool
	ThreatScore int
	NotifyScore int
	SettleSec   int // wait N seconds after last mtime before scanning (default 2)
	Scan        scan.Config
	Quiet       bool
	OnEvent     func(Event, model.FileResult)
	OnPass      func(pass, scanned, flagged int)
}

func Run(cfg Config) error {
	return RunContext(context.Background(), cfg)
}

func RunContext(ctx context.Context, cfg Config) error {
	if cfg.Root == "" {
		return fmt.Errorf("watch root required")
	}
	abs, err := filepath.Abs(cfg.Root)
	if err != nil {
		return err
	}
	cfg.Root = abs
	cfg.Scan.Root = abs
	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = 5
	}
	if cfg.SettleSec <= 0 {
		cfg.SettleSec = 2
	}

	st := LoadState(abs)
	if !cfg.Quiet {
		fmt.Printf("WATCH mode: %s (interval %ds, threat>=%d, notify>=%d, quarantine=%v, toast=%v)\n",
			abs, cfg.IntervalSec, cfg.ThreatScore, cfg.NotifyScore, cfg.Quarantine, cfg.Toast)
	}

	for pass := 1; ; pass++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		changed := collectChanged(abs, st, time.Duration(cfg.SettleSec)*time.Second)
		if len(changed) > 0 {
			sc, err := scan.New(cfg.Scan)
			if err != nil {
				return err
			}
			sum, err := sc.ScanFiles(changed)
			sc.Close()
			if err != nil {
				return err
			}
			for _, r := range sum.Results {
				if r.Skipped {
					continue
				}
				st.Files[r.Path] = FileState{Size: r.Size, ModUnix: modUnix(r.Path), Score: r.Score, Verdict: r.Verdict.String(), SHA256: r.SHA256}
				origin := ""
				if r.DownloadSource != nil {
					if r.DownloadSource.HostURL != "" {
						origin = r.DownloadSource.HostURL
					} else {
						origin = r.DownloadSource.ReferrerURL
					}
				}
				top := topFindingLine(r)
				if r.Score < cfg.NotifyScore {
					if cfg.OnEvent != nil {
						cfg.OnEvent(Event{
							Time:       time.Now().Format(time.RFC3339),
							Path:       r.Path,
							Score:      r.Score,
							Verdict:    r.Verdict.String(),
							Action:     "clean",
							OriginURL:  origin,
							TopFinding: top,
						}, r)
					}
					continue
				}
				action := "flagged"
				if cfg.Quarantine && r.Score >= cfg.ThreatScore {
					if q, err := QuarantineFile(abs, r); err == nil {
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
				ev := Event{
					Time:       time.Now().Format(time.RFC3339),
					Path:       r.Path,
					Score:      r.Score,
					Verdict:    r.Verdict.String(),
					Action:     action,
					OriginURL:  origin,
					TopFinding: top,
				}
				st.Events = append(st.Events, ev)
				if cfg.OnEvent != nil {
					cfg.OnEvent(ev, r)
				}
				if cfg.NotifyURL != "" {
					go notify(cfg.NotifyURL, r)
				}
				if cfg.Toast {
					go sendToast(ev)
				}
			}
			if cfg.OnPass != nil {
				cfg.OnPass(pass, sum.FilesScanned, sum.Suspicious+sum.Malicious)
			}
			if !cfg.Quiet {
				fmt.Printf("  pass %d: %d scanned, %d flagged\n", pass, sum.FilesScanned, sum.Suspicious+sum.Malicious)
			}
		} else {
			if cfg.OnPass != nil {
				cfg.OnPass(pass, 0, 0)
			}
			if !cfg.Quiet {
				fmt.Printf("  pass %d: no changes\n", pass)
			}
		}
		st.Save(abs)
		if cfg.Once {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(cfg.IntervalSec) * time.Second):
		}
	}
}

func collectChanged(root string, st *State, settle time.Duration) []string {
	var out []string
	seen := map[string]bool{}
	now := time.Now()
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
		if IsPartialDownload(path) {
			return nil
		}
		seen[path] = true
		info, err := d.Info()
		if err != nil {
			return nil
		}
		// Wait until freshly-written downloads settle so we don't scan half a file.
		if settle > 0 && now.Sub(info.ModTime()) < settle {
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

// QuarantineFile moves a flagged file into <root>/.quarantine/<timestamp>/ and
// writes its JSON metadata sidecar. Exported so the Web UI can invoke it too.
func QuarantineFile(root string, r model.FileResult) (string, error) {
	if root == "" {
		root = filepath.Dir(r.Path)
	}
	return QuarantineToDir(filepath.Join(root, quarantineDir), r)
}

// QuarantineToDir moves a flagged file into <vaultDir>/<timestamp>/ and writes
// its JSON metadata sidecar so the Desktop Quarantine Vault can list, restore,
// or permanently delete it.
func QuarantineToDir(vaultDir string, r model.FileResult) (string, error) {
	if vaultDir == "" {
		vaultDir = filepath.Join(filepath.Dir(r.Path), quarantineDir)
	}
	destDir := filepath.Join(vaultDir, time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(destDir, filepath.Base(r.Path)+".quarantined")
	if err := os.Rename(r.Path, dest); err != nil {
		if err := copyFile(r.Path, dest); err != nil {
			return "", err
		}
		os.Remove(r.Path)
	}
	meta := map[string]any{
		"original_path":   r.Path,
		"sha256":          r.SHA256,
		"score":           r.Score,
		"verdict":         r.Verdict.String(),
		"findings":        r.Findings,
		"download_source": r.DownloadSource,
		"quarantined_at":  time.Now().Format(time.RFC3339),
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

func topFindingLine(r model.FileResult) string {
	best := ""
	sev := -1
	for _, f := range r.Findings {
		if f.Severity > sev {
			sev = f.Severity
			best = f.Rule + ": " + f.Detail
		}
	}
	if len(best) > 140 {
		best = best[:140] + "..."
	}
	return best
}

func notify(url string, r model.FileResult) {
	body := map[string]any{
		"text":            fmt.Sprintf("CrackSentinel: %s scored %d (%s)", filepath.Base(r.Path), r.Score, r.Verdict),
		"path":            r.Path,
		"sha256":          r.SHA256,
		"score":           r.Score,
		"verdict":         r.Verdict.String(),
		"top_finding":     topFindingLine(r),
		"download_source": r.DownloadSource,
	}
	b, _ := json.Marshal(body)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(b)))
	if err == nil {
		resp.Body.Close()
	}
}

// NotifyToast displays a non-blocking native Windows notification (no-op on Linux/macOS).
func NotifyToast(title, msg string) {
	if runtime.GOOS != "windows" {
		return
	}
	ps := `Add-Type -AssemblyName System.Windows.Forms; $n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Warning; $n.Visible=$true; $n.ShowBalloonTip(7000, $env:CS_TOAST_TITLE, $env:CS_TOAST_MSG, [System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep -Seconds 7; $n.Dispose()`
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
	procutil.HideWindow(cmd)
	cmd.Env = append(os.Environ(), "CS_TOAST_TITLE="+title, "CS_TOAST_MSG="+msg)
	_ = cmd.Run()
}

// sendToast shows a non-blocking native Windows desktop notification without
// requiring any third-party packages. Values are passed via environment
// variables so untrusted filenames can never inject PowerShell syntax.
func sendToast(ev Event) {
	title := fmt.Sprintf("CrackSentinel [%s %d]", ev.Verdict, ev.Score)
	msg := filepath.Base(ev.Path)
	if ev.Action == "quarantined" {
		msg += " (QUARANTINED)"
	}
	if ev.TopFinding != "" {
		msg += " — " + ev.TopFinding
	}
	NotifyToast(title, msg)
}

func modUnix(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.ModTime().Unix()
}
