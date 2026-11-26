package ui

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/motw"
	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/procutil"
	"gamecrack-scanner/internal/report"
	"gamecrack-scanner/internal/scan"
	"gamecrack-scanner/internal/sigfeed"
	"gamecrack-scanner/internal/updater"
	"gamecrack-scanner/internal/version"
	"gamecrack-scanner/internal/watch"
	"gamecrack-scanner/internal/yara"
)

//go:embed web/index.html web/favicon.png web/favicon.ico
var webFS embed.FS

// Options configures the local CrackSentinel Web UI & Extension Bridge server.
type Options struct {
	Addr           string // e.g. "127.0.0.1:8787"
	Workers        int
	MaxSizeMB      int64
	ExtractDepth   int
	ExtractMaxMB   int64
	TempDir        string
	DataDir        string // persistent desktop data dir (history.json, settings.json); empty disables persistence
	QuarantineDir  string // central quarantine vault dir (default <exeDir>/quarantine in local mode)
	CachePath      string
	CorpusPath     string
	Online         *online.Client
	Yara           *yara.Runner
	OpenBrowser    bool
	DesktopMode    bool     // true when launched via CrackSentinel.exe desktop app
	OnQuit         func()   // optional callback triggered by /api/app/quit
	WatchDir       string   // optional auto-start download guard folder
	PublicMode     bool     // hosted web mode: disables local disk paths/picker/quarantine/watch/corpus
	AllowedOrigins []string // additional allowed Origin URLs (e.g. https://sentinel.breakthematrix.id)
	AccessKey      string   // optional shared secret for private hosted deployments
	MaxUploadMB    int64    // max multipart upload size in MB (default 100 in PublicMode, 0 = unlimited local)
	MaxConcurrent  int      // max concurrent scan requests in PublicMode (default 2)
}

type HistoryItem struct {
	ID         string         `json:"id"`
	Time       string         `json:"time"`
	Source     string         `json:"source"` // "drag-drop", "paths", "extension", "watch"
	Target     string         `json:"target"`
	OriginURL  string         `json:"origin_url,omitempty"`
	Summary    *model.Summary `json:"summary"`
	TopVerdict string         `json:"top_verdict"`
	MaxScore   int            `json:"max_score"`
}

type Server struct {
	opts Options

	mu            sync.RWMutex
	history       []HistoryItem
	flaggedPath   map[string]model.FileResult
	seq           int64
	scanSem       chan struct{}
	settings      DesktopSettings
	jobs          map[string]*ScanJob
	jobOrder      []string
	lastHeartbeat int64
	activeClients int64
	seenClient    int64
	updateMu      sync.Mutex
	cachedUpdate  *updater.ReleaseInfo
	updateAt      time.Time

	watchMu     sync.Mutex
	watchCancel context.CancelFunc
	watchActive bool
	watchDir    string
	watchQuar   bool
	watchToast  bool
	watchEvents []watch.Event
}

func New(opts Options) *Server {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8787"
	}
	if opts.Workers <= 0 {
		opts.Workers = 3
	}
	if opts.MaxSizeMB <= 0 {
		opts.MaxSizeMB = 512
	}
	if opts.ExtractDepth <= 0 {
		opts.ExtractDepth = 2
	}
	if opts.ExtractMaxMB <= 0 {
		opts.ExtractMaxMB = 500
	}
	if opts.TempDir == "" {
		if exe, err := os.Executable(); err == nil {
			opts.TempDir = filepath.Join(filepath.Dir(exe), "tmp")
		}
	}
	if opts.QuarantineDir == "" && !opts.PublicMode {
		if opts.DataDir != "" {
			opts.QuarantineDir = filepath.Join(filepath.Dir(opts.DataDir), "quarantine")
		} else if exe, err := os.Executable(); err == nil {
			opts.QuarantineDir = filepath.Join(filepath.Dir(exe), "quarantine")
		}
	}
	if opts.CachePath == "" {
		opts.CachePath = ".gamecrack-cache.jsonl"
	}
	if opts.CorpusPath == "" {
		opts.CorpusPath = "corpus.json"
	}
	if opts.PublicMode {
		if opts.MaxUploadMB <= 0 {
			opts.MaxUploadMB = 100
		}
		if opts.MaxConcurrent <= 0 {
			opts.MaxConcurrent = 2
		}
	}
	var sem chan struct{}
	if opts.MaxConcurrent > 0 {
		sem = make(chan struct{}, opts.MaxConcurrent)
	}
	s := &Server{
		opts:          opts,
		flaggedPath:   map[string]model.FileResult{},
		scanSem:       sem,
		jobs:          map[string]*ScanJob{},
		lastHeartbeat: time.Now().Unix(),
	}
	s.initDesktopState()
	return s
}

// Handler returns the HTTP handler with local-origin protection.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/dashboard", s.handleDashboard)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/scan-paths", s.handleScanPaths)
	mux.HandleFunc("/api/jobs", s.handleJobsList)
	mux.HandleFunc("/api/jobs/scan-paths", s.handleJobStartScanPaths)
	mux.HandleFunc("/api/jobs/", s.handleJobByID)
	mux.HandleFunc("/api/check-url", s.handleCheckURL)
	mux.HandleFunc("/api/pick", s.handlePick)
	mux.HandleFunc("/api/quarantine", s.handleQuarantine)
	mux.HandleFunc("/api/quarantine/list", s.handleQuarantineList)
	mux.HandleFunc("/api/quarantine/restore", s.handleQuarantineRestore)
	mux.HandleFunc("/api/quarantine/delete", s.handleQuarantineDelete)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/history/clear", s.handleHistoryClear)
	mux.HandleFunc("/api/history/", s.handleHistoryDetail)
	mux.HandleFunc("/api/report/", s.handleReportDownload)
	mux.HandleFunc("/api/watch/status", s.handleWatchStatus)
	mux.HandleFunc("/api/watch/start", s.handleWatchStart)
	mux.HandleFunc("/api/watch/stop", s.handleWatchStop)
	mux.HandleFunc("/api/corpus/label", s.handleCorpusLabel)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/cache/clear", s.handleCacheClear)
	mux.HandleFunc("/api/open-explorer", s.handleOpenExplorer)
	mux.HandleFunc("/api/desktop/shortcut", s.handleDesktopShortcut)
	mux.HandleFunc("/api/app/heartbeat", s.handleAppHeartbeat)
	mux.HandleFunc("/api/app/stream", s.handleAppStream)
	mux.HandleFunc("/api/app/quit", s.handleAppQuit)
	mux.HandleFunc("/api/update/check", s.handleUpdateCheck)
	mux.HandleFunc("/api/update/apply", s.handleUpdateApply)
	mux.HandleFunc("/api/signatures/status", s.handleSignaturesStatus)
	mux.HandleFunc("/api/signatures/sync", s.handleSignaturesSync)
	return s.originGuard(mux)
}

// StartListener validates loopback binding and starts listening on s.opts.Addr.
func (s *Server) StartListener() (net.Listener, string, error) {
	host, _, err := net.SplitHostPort(s.opts.Addr)
	if err == nil && host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return nil, "", fmt.Errorf("refusing to bind UI server to non-loopback address %q (use 127.0.0.1)", s.opts.Addr)
	}
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return nil, "", err
	}
	return ln, "http://" + ln.Addr().String(), nil
}

// ServeListener serves HTTP traffic on an existing listener and auto-starts
// Download Guard when configured.
func (s *Server) ServeListener(ln net.Listener) error {
	if s.opts.WatchDir != "" {
		_ = s.startWatch(s.opts.WatchDir, 4, false, true)
	} else if !s.opts.PublicMode {
		s.mu.RLock()
		autoStart := s.settings.WatchAutoStart
		wdir := s.settings.WatchDir
		wint := s.settings.WatchInterval
		wquar := s.settings.WatchQuarantine
		wtoast := s.settings.WatchToast
		s.mu.RUnlock()
		if autoStart && wdir != "" {
			_ = s.startWatch(wdir, wint, wquar, wtoast)
		}
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
	}
	return srv.Serve(ln)
}

// ListenAndServe starts the server bound strictly to loopback.
func (s *Server) ListenAndServe() error {
	ln, url, err := s.StartListener()
	if err != nil {
		return err
	}
	fmt.Printf("CrackSentinel UI %s listening on %s\n", version.Short(), url)
	fmt.Printf("  temp dir : %s\n", s.opts.TempDir)
	fmt.Printf("  press Ctrl+C to stop\n")

	if s.opts.OpenBrowser {
		go func() {
			time.Sleep(350 * time.Millisecond)
			openBrowser(url)
		}()
	}
	return s.ServeListener(ln)
}

// originGuard blocks cross-origin calls from arbitrary internet websites while
// permitting same-origin UI traffic, configured public domains, and browser
// extensions, and enforces AccessKey when configured.
func (s *Server) originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowed := strings.HasPrefix(origin, "http://127.0.0.1") ||
				strings.HasPrefix(origin, "http://localhost") ||
				strings.HasPrefix(origin, "chrome-extension://") ||
				strings.HasPrefix(origin, "edge-extension://") ||
				strings.HasPrefix(origin, "moz-extension://")
			if !allowed && r.Host != "" {
				if origin == "https://"+r.Host || origin == "http://"+r.Host {
					allowed = true
				}
			}
			if !allowed {
				for _, ao := range s.opts.AllowedOrigins {
					if strings.EqualFold(strings.TrimRight(origin, "/"), strings.TrimRight(ao, "/")) {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				http.Error(w, "forbidden cross-origin request", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Access-Key")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if s.opts.AccessKey != "" && strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/health" {
			got := r.Header.Get("X-Access-Key")
			if got == "" {
				got = r.URL.Query().Get("key")
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.opts.AccessKey)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "access key required"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) acquireScanSlot() (func(), bool) {
	if s.scanSem == nil {
		return func() {}, true
	}
	select {
	case s.scanSem <- struct{}{}:
		return func() { <-s.scanSem }, true
	default:
		return nil, false
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		data, err := webFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "UI asset missing", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	case "/favicon.png":
		data, err := webFS.ReadFile("web/favicon.png")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data)
	case "/favicon.ico":
		data, err := webFS.ReadFile("web/favicon.ico")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.watchMu.Lock()
	watching, wdir, wq, wt := s.watchActive, s.watchDir, s.watchQuar, s.watchToast
	s.watchMu.Unlock()
	s.mu.RLock()
	workers := s.opts.Workers
	onlineEnabled := s.opts.Online != nil && s.opts.Online.Enabled()
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"version":       version.Short(),
		"sig_db":        sigfeed.Global().Status().Version,
		"workers":       workers,
		"public_mode":   s.opts.PublicMode,
		"desktop_mode":  s.opts.DesktopMode,
		"auth_required": s.opts.AccessKey != "",
		"max_upload_mb": s.opts.MaxUploadMB,
		"yara":          s.opts.Yara != nil,
		"online":        onlineEnabled,
		"watching":      watching,
		"watch_dir": func() string {
			if s.opts.PublicMode {
				return ""
			}
			return wdir
		}(),
		"watch_quarantine": wq,
		"watch_toast":      wt,
		"default_downloads": func() string {
			if s.opts.PublicMode {
				return ""
			}
			return defaultDownloadsDir()
		}(),
	})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	release, ok := s.acquireScanSlot()
	if !ok {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "server sedang sibuk scan file lain, coba beberapa detik lagi"})
		return
	}
	defer release()

	if s.opts.MaxUploadMB > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxUploadMB*1024*1024)
	}
	// Stream multipart files directly to disk on TempDir (never hold huge files in RAM).
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid multipart upload: " + err.Error()})
		return
	}
	if s.opts.TempDir != "" {
		_ = os.MkdirAll(s.opts.TempDir, 0o755)
	}
	staging, err := os.MkdirTemp(s.opts.TempDir, "cs-drop-")
	if err != nil {
		staging, err = os.MkdirTemp("", "cs-drop-")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "temp dir error: " + err.Error()})
			return
		}
	}
	defer os.RemoveAll(staging)

	extractDepth := s.opts.ExtractDepth
	useOnline := false
	carve := true
	var relPaths []string
	var uploaded []string

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		formName := part.FormName()
		if formName == "extract" {
			v, _ := io.ReadAll(io.LimitReader(part, 32))
			if strings.TrimSpace(string(v)) == "false" || strings.TrimSpace(string(v)) == "0" {
				extractDepth = 0
			}
			part.Close()
			continue
		}
		if formName == "online" {
			v, _ := io.ReadAll(io.LimitReader(part, 32))
			useOnline = strings.TrimSpace(string(v)) == "true" || strings.TrimSpace(string(v)) == "1"
			part.Close()
			continue
		}
		if formName == "carve" {
			v, _ := io.ReadAll(io.LimitReader(part, 32))
			carve = strings.TrimSpace(string(v)) != "false" && strings.TrimSpace(string(v)) != "0"
			part.Close()
			continue
		}
		if formName == "paths" {
			v, _ := io.ReadAll(io.LimitReader(part, 1<<20))
			_ = json.Unmarshal(v, &relPaths)
			part.Close()
			continue
		}
		fn := part.FileName()
		if fn == "" {
			part.Close()
			continue
		}
		// Use optional relative path if browser supplied webkitRelativePath.
		rel := fn
		if len(uploaded) < len(relPaths) && relPaths[len(uploaded)] != "" {
			rel = relPaths[len(uploaded)]
		}
		cleanRel := sanitizeRelPath(rel)
		dst := filepath.Join(staging, cleanRel)
		if !strings.HasPrefix(strings.ToLower(dst), strings.ToLower(staging)+string(os.PathSeparator)) {
			dst = filepath.Join(staging, filepath.Base(cleanRel))
		}
		_ = os.MkdirAll(filepath.Dir(dst), 0o755)
		out, err := os.Create(dst)
		if err != nil {
			part.Close()
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_, copyErr := io.Copy(out, part)
		out.Close()
		part.Close()
		if copyErr != nil {
			if strings.Contains(copyErr.Error(), "request body too large") {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("ukuran upload melebihi batas %d MB", s.opts.MaxUploadMB)})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": copyErr.Error()})
			return
		}
		uploaded = append(uploaded, dst)
	}

	if len(uploaded) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no files uploaded"})
		return
	}

	cfg := s.baseScanConfig(staging, extractDepth, useOnline, carve)
	sc, err := scan.New(cfg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer sc.Close()

	sum, err := sc.Run()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Strip temporary staging prefix so displayed paths are clean relative names.
	for i := range sum.Results {
		if rel, err := filepath.Rel(staging, sum.Results[i].Path); err == nil {
			sum.Results[i].Path = filepath.ToSlash(rel)
		}
	}
	label := fmt.Sprintf("Drop (%d file)", len(uploaded))
	if len(uploaded) == 1 {
		label = filepath.Base(uploaded[0])
	}
	item := s.recordHistory("drag-drop", label, "", sum)
	writeJSON(w, http.StatusOK, item)
}

type scanPathsRequest struct {
	Paths        []string `json:"paths"`
	ExtractDepth *int     `json:"extract_depth,omitempty"`
	Online       bool     `json:"online,omitempty"`
	Carve        *bool    `json:"carve,omitempty"`
	Source       string   `json:"source,omitempty"`
	SourceURL    string   `json:"source_url,omitempty"`
	Referrer     string   `json:"referrer,omitempty"`
}

func (s *Server) handleScanPaths(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local disk path scanning is disabled in public web mode; use drag-and-drop upload"})
		return
	}
	var req scanPathsRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	var cleanPaths []string
	for _, p := range req.Paths {
		p = strings.TrimSpace(strings.Trim(p, `"'`))
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			cleanPaths = append(cleanPaths, p)
		}
	}
	if len(cleanPaths) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid existing paths provided"})
		return
	}
	depth := s.opts.ExtractDepth
	if req.ExtractDepth != nil {
		depth = *req.ExtractDepth
	}
	carve := true
	if req.Carve != nil {
		carve = *req.Carve
	}
	cfg := s.baseScanConfig(cleanPaths[0], depth, req.Online, carve)
	sc, err := scan.New(cfg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer sc.Close()

	sum, err := sc.ScanPaths(cleanPaths)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// If browser extension supplied download URL/referrer, enrich results with URL risk analysis.
	if req.SourceURL != "" || req.Referrer != "" {
		for i := range sum.Results {
			res := &sum.Results[i]
			if res.DownloadSource == nil {
				res.DownloadSource = &model.DownloadSource{
					ZoneID:      3,
					ZoneName:    "Internet",
					HostURL:     req.SourceURL,
					ReferrerURL: req.Referrer,
				}
			}
			ua := motw.AnalyzeURL(req.SourceURL, req.Referrer, filepath.Base(res.Path), res.Size)
			added := 0
			for _, f := range ua.Findings {
				if f.Severity <= 0 || hasFindingRule(res.Findings, f.Rule) {
					continue
				}
				res.Findings = append(res.Findings, f)
				added += f.Severity
			}
			if added > 0 {
				res.Score += added
				if res.Score > 100 {
					res.Score = 100
				}
				if res.Score >= 70 {
					res.Verdict = model.VerdictMalicious
				} else if res.Score >= 30 && res.Verdict == model.VerdictClean {
					res.Verdict = model.VerdictSuspicious
				}
			}
		}
		recountSummary(sum)
	}

	src := req.Source
	if src == "" {
		src = "paths"
	}
	label := cleanPaths[0]
	if len(cleanPaths) > 1 {
		label = fmt.Sprintf("%s (+%d more)", filepath.Base(cleanPaths[0]), len(cleanPaths)-1)
	}
	item := s.recordHistory(src, label, req.SourceURL, sum)
	writeJSON(w, http.StatusOK, item)
}

type checkURLRequest struct {
	URL      string `json:"url"`
	Referrer string `json:"referrer,omitempty"`
	Filename string `json:"filename,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Probe    bool   `json:"probe,omitempty"`
}

func (s *Server) handleCheckURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req checkURLRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}
	var res motw.URLAssessment
	if req.Probe {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		res = motw.ProbeURL(ctx, req.URL, req.Referrer)
	} else {
		res = motw.AnalyzeURL(req.URL, req.Referrer, req.Filename, req.Size)
	}
	writeJSON(w, http.StatusOK, res)
}

type pickRequest struct {
	Mode string `json:"mode"` // "folder" or "files"
}

// handlePick invokes a native Windows FolderBrowserDialog / OpenFileDialog so
// users can pick huge game folders or multiple files directly on disk without
// copying gigabytes through the browser.
func (s *Server) handlePick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "native picker is disabled in public web mode"})
		return
	}
	if runtime.GOOS != "windows" {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "native picker is Windows-only; paste paths directly"})
		return
	}
	var req pickRequest
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)

	var ps string
	if req.Mode == "files" {
		ps = `Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.Form; $f.TopMost = $true; $f.ShowInTaskbar = $false; $f.StartPosition = 'CenterScreen'; $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Title = 'CrackSentinel — Pilih File Game / Archive (bisa pilih banyak)'; $d.Multiselect = $true; $d.Filter = 'All files (*.*)|*.*'; if ($d.ShowDialog($f) -eq 'OK') { $d.FileNames -join [Environment]::NewLine }; $f.Dispose()`
	} else {
		ps = `Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.Form; $f.TopMost = $true; $f.ShowInTaskbar = $false; $f.StartPosition = 'CenterScreen'; $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description = 'CrackSentinel — Pilih Folder Game untuk Di-scan Langsung'; $d.UseDescriptionForTitle = $true; if ($d.ShowDialog($f) -eq 'OK') { $d.SelectedPath }; $f.Dispose()`
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-STA", "-WindowStyle", "Hidden", "-Command", ps)
	procutil.HideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "picker canceled or failed"})
		return
	}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(line)
		if p != "" {
			paths = append(paths, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": paths})
}

type quarantineRequest struct {
	Path string `json:"path"`
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "quarantine is disabled in public web mode"})
		return
	}
	var req quarantineRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	s.mu.RLock()
	fr, ok := s.flaggedPath[req.Path]
	vaultDir := s.opts.QuarantineDir
	s.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only flagged files from a local path scan can be quarantined"})
		return
	}
	var (
		dest string
		err  error
	)
	if vaultDir != "" {
		dest, err = watch.QuarantineToDir(vaultDir, fr)
	} else {
		dest, err = watch.QuarantineFile(filepath.Dir(fr.Path), fr)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"quarantined_to": dest})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type lite struct {
		ID         string `json:"id"`
		Time       string `json:"time"`
		Source     string `json:"source"`
		Target     string `json:"target"`
		OriginURL  string `json:"origin_url,omitempty"`
		TopVerdict string `json:"top_verdict"`
		MaxScore   int    `json:"max_score"`
		Scanned    int    `json:"files_scanned"`
		Malicious  int    `json:"malicious"`
		Suspicious int    `json:"suspicious"`
		Clean      int    `json:"clean"`
		DurationMs int64  `json:"duration_ms"`
	}
	out := make([]lite, 0, len(s.history))
	for i := len(s.history) - 1; i >= 0; i-- {
		h := s.history[i]
		out = append(out, lite{
			ID:         h.ID,
			Time:       h.Time,
			Source:     h.Source,
			Target:     h.Target,
			OriginURL:  h.OriginURL,
			TopVerdict: h.TopVerdict,
			MaxScore:   h.MaxScore,
			Scanned:    h.Summary.FilesScanned,
			Malicious:  h.Summary.Malicious,
			Suspicious: h.Summary.Suspicious,
			Clean:      h.Summary.Clean,
			DurationMs: h.Summary.DurationMs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleHistoryDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/history/")
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, h := range s.history {
		if h.ID == id {
			writeJSON(w, http.StatusOK, h)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) handleReportDownload(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimPrefix(r.URL.Path, "/api/report/")
	isJSON := strings.HasSuffix(rawID, ".json")
	id := strings.TrimSuffix(strings.TrimSuffix(rawID, ".html"), ".json")
	s.mu.RLock()
	var found *HistoryItem
	for i := range s.history {
		if s.history[i].ID == id {
			cp := s.history[i]
			found = &cp
			break
		}
	}
	s.mu.RUnlock()
	if found == nil {
		http.NotFound(w, r)
		return
	}
	if isJSON {
		b, err := json.MarshalIndent(found, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cracksentinel-%s.json"`, id))
		w.Write(b)
		return
	}
	tmp, err := os.CreateTemp("", "cs-rep-*.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	if err := report.WriteHTML(tmpPath, found.Summary, found.Target, version.String()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b, _ := os.ReadFile(tmpPath)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cracksentinel-%s.html"`, id))
	w.Write(b)
}

func (s *Server) handleWatchStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local watch mode is disabled in public web mode"})
		return
	}
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	evCopy := append([]watch.Event(nil), s.watchEvents...)
	writeJSON(w, http.StatusOK, map[string]any{
		"active":     s.watchActive,
		"dir":        s.watchDir,
		"quarantine": s.watchQuar,
		"toast":      s.watchToast,
		"events":     evCopy,
	})
}

type watchStartRequest struct {
	Dir        string `json:"dir"`
	Interval   int    `json:"interval"`
	Quarantine bool   `json:"quarantine"`
	Toast      bool   `json:"toast"`
}

func (s *Server) handleWatchStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local watch mode is disabled in public web mode"})
		return
	}
	var req watchStartRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	dir := strings.TrimSpace(req.Dir)
	if dir == "" {
		dir = defaultDownloadsDir()
	}
	if req.Interval <= 0 {
		req.Interval = 4
	}
	if err := s.startWatch(dir, req.Interval, req.Quarantine, req.Toast); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.handleWatchStatus(w, r)
}

func (s *Server) handleWatchStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local watch mode is disabled in public web mode"})
		return
	}
	s.stopWatch()
	s.handleWatchStatus(w, r)
}

func (s *Server) startWatch(dir string, interval int, quarantine, toast bool) error {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("folder not found: %s", dir)
	}
	s.stopWatch()
	ctx, cancel := context.WithCancel(context.Background())
	s.watchMu.Lock()
	s.watchCancel = cancel
	s.watchActive = true
	s.watchDir = dir
	s.watchQuar = quarantine
	s.watchToast = toast
	s.watchMu.Unlock()

	cfg := watch.Config{
		Root:        dir,
		IntervalSec: interval,
		Quarantine:  quarantine,
		Toast:       toast,
		ThreatScore: 70,
		NotifyScore: 30,
		SettleSec:   2,
		Quiet:       true,
		Scan:        s.baseScanConfig(dir, s.opts.ExtractDepth, false, true),
		OnEvent: func(ev watch.Event, fr model.FileResult) {
			s.watchMu.Lock()
			s.watchEvents = append([]watch.Event{ev}, s.watchEvents...)
			if len(s.watchEvents) > 100 {
				s.watchEvents = s.watchEvents[:100]
			}
			s.watchMu.Unlock()
			if fr.Score >= 30 {
				sum := &model.Summary{FilesScanned: 1, BytesScanned: fr.Size, Results: []model.FileResult{fr}}
				recountSummary(sum)
				s.recordHistory("watch", filepath.Base(fr.Path), ev.OriginURL, sum)
			}
		},
	}
	go func() {
		_ = watch.RunContext(ctx, cfg)
		s.watchMu.Lock()
		if s.watchDir == dir {
			s.watchActive = false
		}
		s.watchMu.Unlock()
	}()
	return nil
}

func (s *Server) stopWatch() {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if s.watchCancel != nil {
		s.watchCancel()
		s.watchCancel = nil
	}
	s.watchActive = false
}

type labelRequest struct {
	Path  string `json:"path"`
	Label string `json:"label"` // "legitimate" or "malicious"
	Note  string `json:"note"`
}

func (s *Server) handleCorpusLabel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "corpus labeling is disabled in public web mode"})
		return
	}
	var req labelRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Path == "" || (req.Label != "legitimate" && req.Label != "malicious") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path and label ('legitimate' or 'malicious') required"})
		return
	}
	if err := appendCorpusLabel(s.opts.CorpusPath, req.Path, req.Label, req.Note); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "corpus": s.opts.CorpusPath})
}

func appendCorpusLabel(corpusPath, targetPath, label, note string) error {
	type cCase struct {
		Path  string `json:"path"`
		Root  string `json:"root,omitempty"`
		Label string `json:"label"`
		Note  string `json:"note"`
	}
	type corpusDoc struct {
		Comment string  `json:"_comment,omitempty"`
		Cases   []cCase `json:"cases"`
	}
	var doc corpusDoc
	if b, err := os.ReadFile(corpusPath); err == nil {
		_ = json.Unmarshal(b, &doc)
	}
	cleanTarget := filepath.ToSlash(targetPath)
	root := ""
	rel := cleanTarget
	if filepath.IsAbs(targetPath) {
		root = filepath.ToSlash(filepath.Dir(targetPath))
		rel = filepath.Base(targetPath)
	}
	if note == "" {
		note = "human-labelled via CrackSentinel UI (" + time.Now().Format("2006-01-02") + ")"
	}
	updated := false
	for i := range doc.Cases {
		if doc.Cases[i].Path == rel && doc.Cases[i].Root == root {
			doc.Cases[i].Label = label
			doc.Cases[i].Note = note
			updated = true
			break
		}
	}
	if !updated {
		doc.Cases = append(doc.Cases, cCase{Path: rel, Root: root, Label: label, Note: note})
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(corpusPath, b, 0o644)
}

func (s *Server) baseScanConfig(root string, extractDepth int, useOnline, carve bool) scan.Config {
	s.mu.RLock()
	workers := s.opts.Workers
	maxSizeMB := s.opts.MaxSizeMB
	extractMaxMB := s.opts.ExtractMaxMB
	tempDir := s.opts.TempDir
	cachePath := s.opts.CachePath
	skipAssets := s.settings.SkipAssets
	useCache := s.settings.UseCache
	var oc *online.Client
	if useOnline && s.opts.Online != nil && s.opts.Online.Enabled() {
		oc = s.opts.Online
	}
	yr := s.opts.Yara
	s.mu.RUnlock()
	return scan.Config{
		Root:         root,
		Workers:      workers,
		MaxSizeMB:    maxSizeMB,
		SkipAssets:   skipAssets,
		UseCache:     useCache,
		CachePath:    cachePath,
		Quiet:        true,
		FullReadMB:   32,
		Online:       oc,
		Yara:         yr,
		ExtractDepth: extractDepth,
		ExtractMaxMB: extractMaxMB,
		TempDir:      tempDir,
		Carve:        carve,
		CarveMaxMB:   16384,
	}
}

func (s *Server) recordHistory(source, target, originURL string, sum *model.Summary) HistoryItem {
	id := strconv.FormatInt(time.Now().Unix(), 10) + "-" + strconv.FormatInt(atomic.AddInt64(&s.seq, 1), 10)
	topV := "CLEAN"
	maxS := 0
	for _, r := range sum.Results {
		if r.Skipped {
			continue
		}
		if r.Score > maxS {
			maxS = r.Score
		}
		if r.Verdict == model.VerdictMalicious {
			topV = "MALICIOUS"
		} else if r.Verdict == model.VerdictSuspicious && topV != "MALICIOUS" {
			topV = "SUSPICIOUS"
		}
	}
	item := HistoryItem{
		ID:         id,
		Time:       time.Now().Format("2006-01-02 15:04:05"),
		Source:     source,
		Target:     target,
		OriginURL:  originURL,
		Summary:    sum,
		TopVerdict: topV,
		MaxScore:   maxS,
	}
	s.mu.Lock()
	s.history = append(s.history, item)
	if len(s.history) > 100 {
		s.history = s.history[len(s.history)-100:]
	}
	if source != "drag-drop" {
		for _, r := range sum.Results {
			if !r.Skipped && r.Score >= 30 && filepath.IsAbs(r.Path) {
				s.flaggedPath[r.Path] = r
			}
		}
	}
	s.mu.Unlock()
	s.persistHistory()
	return item
}

func hasFindingRule(fs []model.Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func recountSummary(sum *model.Summary) {
	sum.Clean, sum.Suspicious, sum.Malicious = 0, 0, 0
	for _, r := range sum.Results {
		if r.Skipped {
			continue
		}
		switch r.Verdict {
		case model.VerdictMalicious:
			sum.Malicious++
		case model.VerdictSuspicious:
			sum.Suspicious++
		default:
			sum.Clean++
		}
	}
}

func sanitizeRelPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimLeft(p, "/")
	parts := strings.Split(p, "/")
	var safe []string
	for _, seg := range parts {
		seg = strings.TrimSpace(seg)
		if seg == "" || seg == "." || seg == ".." || strings.Contains(seg, ":") {
			continue
		}
		safe = append(safe, seg)
	}
	if len(safe) == 0 {
		return "dropped_file"
	}
	return filepath.Join(safe...)
}

func defaultDownloadsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dl := filepath.Join(home, "Downloads")
	if st, err := os.Stat(dl); err == nil && st.IsDir() {
		return dl
	}
	return home
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
