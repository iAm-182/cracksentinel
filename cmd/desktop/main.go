package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/ui"
	"gamecrack-scanner/internal/updater"
	"gamecrack-scanner/internal/yara"
)

const defaultAddr = "127.0.0.1:8787"

func main() {
	exe, err := os.Executable()
	if err != nil {
		exe = "."
	}
	updater.CleanupOldBinary(exe)
	appDir := filepath.Dir(exe)
	dataDir := filepath.Join(appDir, "data")
	tmpDir := filepath.Join(appDir, "tmp")
	quarDir := filepath.Join(appDir, "quarantine")
	profileDir := filepath.Join(appDir, ".appdata")
	cachePath := filepath.Join(appDir, ".gamecrack-cache.jsonl")
	corpusPath := filepath.Join(appDir, "corpus.json")

	_ = os.MkdirAll(dataDir, 0o755)
	_ = os.MkdirAll(tmpDir, 0o755)
	_ = os.MkdirAll(quarDir, 0o755)

	// Collect any paths dragged onto CrackSentinel.exe.
	var dropArgs []string
	for _, a := range os.Args[1:] {
		a = strings.TrimSpace(a)
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		if _, err := os.Stat(a); err == nil {
			dropArgs = append(dropArgs, a)
		}
	}

	// Single-instance check: if CrackSentinel is already listening on 8787,
	// open/focus the app window directly without spawning a duplicate server.
	existingURL := "http://" + defaultAddr
	if isCrackSentinelAlive(existingURL) {
		launchURL := buildLaunchURL(existingURL, dropArgs)
		_, _ = launchAppWindow(launchURL, profileDir)
		return
	}

	var oc *online.Client
	vtKey := os.Getenv("VT_API_KEY")
	mbKey := os.Getenv("MB_API_KEY")
	if vtKey != "" || mbKey != "" {
		oc = online.New(vtKey, mbKey, 16*time.Second)
	}

	var yr *yara.Runner
	if r, err := yara.New("", true); err == nil {
		yr = r
		defer yr.Close()
	}

	quitCh := make(chan struct{})
	var quitOnce sync.Once
	requestQuit := func() {
		quitOnce.Do(func() { close(quitCh) })
	}

	opts := ui.Options{
		Addr:          defaultAddr,
		Workers:       3,
		MaxSizeMB:     512,
		ExtractDepth:  2,
		ExtractMaxMB:  500,
		TempDir:       tmpDir,
		DataDir:       dataDir,
		QuarantineDir: quarDir,
		CachePath:     cachePath,
		CorpusPath:    corpusPath,
		Online:        oc,
		Yara:          yr,
		OpenBrowser:   false,
		DesktopMode:   true,
		OnQuit:        requestQuit,
	}

	srv := ui.New(opts)
	ln, baseURL, err := srv.StartListener()
	if err != nil {
		// Port 8787 busy by another app — fall back cleanly to an ephemeral loopback port.
		opts.Addr = "127.0.0.1:0"
		srv = ui.New(opts)
		ln, baseURL, err = srv.StartListener()
		if err != nil {
			os.Exit(1)
		}
	}
	defer ln.Close()

	go func() {
		_ = srv.ServeListener(ln)
	}()

	// Wait briefly until the loopback HTTP server answers /api/health.
	for i := 0; i < 30; i++ {
		if isCrackSentinelAlive(baseURL) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	launchURL := buildLaunchURL(baseURL, dropArgs)
	appCmd, isAppMode := launchAppWindow(launchURL, profileDir)

	winExited := make(chan struct{})
	if appCmd != nil && isAppMode {
		go func() {
			_ = appCmd.Wait()
			close(winExited)
		}()
	}

	// Lifecycle management (SSE stream + process monitor):
	// - Explicit "Tutup Aplikasi" button exits immediately.
	// - While ANY UI window SSE stream is open (ActiveClients > 0), NEVER exit
	//   (even if minimized for hours or Edge handed off to an existing profile).
	// - While a scan job is running (ActiveJobs > 0) or Download Guard is ON
	//   (WatchActive == true), NEVER exit.
	// - Once a window has connected and then all windows close (ActiveClients == 0
	//   for > 3 seconds), shut down cleanly with zero orphan processes.
	startedAt := time.Now()
	windowClosed := false
	zeroSince := time.Time{}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-quitCh:
			return
		case <-winExited:
			windowClosed = true
			winExited = nil
		case <-ticker.C:
			if srv.WatchActive() || srv.ActiveJobs() > 0 {
				zeroSince = time.Time{}
				continue
			}
			if srv.ActiveClients() > 0 {
				zeroSince = time.Time{}
				continue
			}
			if srv.SeenClient() {
				if zeroSince.IsZero() {
					zeroSince = time.Now()
				}
				// 3s grace covers page reloads (F5) while exiting promptly on window close.
				if time.Since(zeroSince) > 3*time.Second {
					return
				}
				continue
			}
			// Before the first client connects, allow generous startup time (60s)
			// for cold Edge profile initialization on older CPUs.
			if windowClosed && time.Since(startedAt) > 15*time.Second {
				return
			}
			if time.Since(startedAt) > 60*time.Second {
				return
			}
		}
	}
}

func buildLaunchURL(base string, paths []string) string {
	if len(paths) == 0 {
		return base
	}
	q := url.Values{}
	for _, p := range paths {
		q.Add("autopath", p)
	}
	return base + "/?" + q.Encode()
}

func isCrackSentinelAlive(baseURL string) bool {
	c := &http.Client{Timeout: 600 * time.Millisecond}
	resp, err := c.Get(baseURL + "/api/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false
	}
	return body.Status == "ok"
}

func findAppBrowser() string {
	if runtime.GOOS == "windows" {
		candidates := []string{
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
		}
		if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
			candidates = append(candidates,
				filepath.Join(localApp, `Microsoft\Edge\Application\msedge.exe`),
				filepath.Join(localApp, `Google\Chrome\Application\chrome.exe`),
				filepath.Join(localApp, `BraveSoftware\Brave-Browser\Application\brave.exe`),
			)
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		for _, name := range []string{"msedge", "chrome", "brave"} {
			if p, err := exec.LookPath(name); err == nil {
				return p
			}
		}
		return ""
	}
	for _, name := range []string{"microsoft-edge", "google-chrome", "chromium", "chromium-browser", "brave-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// launchAppWindow opens a chromeless desktop app window (no address bar or tabs)
// using an isolated user-data-dir so CrackSentinel behaves like standalone desktop software.
func launchAppWindow(targetURL, profileDir string) (*exec.Cmd, bool) {
	browser := findAppBrowser()
	if browser != "" {
		_ = os.MkdirAll(profileDir, 0o755)
		args := []string{
			"--app=" + targetURL,
			"--user-data-dir=" + profileDir,
			"--window-size=1360,860",
			"--no-first-run",
			"--no-default-browser-check",
			"--new-window",
			"--disable-features=msEdgeSidebarV2",
		}
		cmd := exec.Command(browser, args...)
		if err := cmd.Start(); err == nil {
			return cmd, true
		}
	}
	// Fallback to system default browser if no Chromium browser is installed.
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	case "darwin":
		cmd = exec.Command("open", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	_ = cmd.Start()
	fmt.Print("") // keep fmt referenced for future diagnostics
	return cmd, false
}
