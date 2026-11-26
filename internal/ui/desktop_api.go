package ui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/online"
	"gamecrack-scanner/internal/procutil"
	"gamecrack-scanner/internal/scan"
	"gamecrack-scanner/internal/version"
	"gamecrack-scanner/internal/watch"
)

// DesktopSettings persists user preferences in <DataDir>/settings.json.
type DesktopSettings struct {
	Workers         int    `json:"workers"`
	MaxSizeMB       int64  `json:"max_size_mb"`
	ExtractDepth    int    `json:"extract_depth"`
	ExtractMaxMB    int64  `json:"extract_max_mb"`
	TempDir         string `json:"temp_dir"`
	QuarantineDir   string `json:"quarantine_dir"`
	SkipAssets      bool   `json:"skip_assets"`
	Carve           bool   `json:"carve"`
	UseCache        bool   `json:"use_cache"`
	VTKey           string `json:"vt_api_key,omitempty"`
	MBKey           string `json:"mb_api_key,omitempty"`
	WatchAutoStart  bool   `json:"watch_auto_start"`
	WatchDir        string `json:"watch_dir"`
	WatchInterval   int    `json:"watch_interval"`
	WatchQuarantine bool   `json:"watch_quarantine"`
	WatchToast      bool   `json:"watch_toast"`
}

// ScanJob tracks an asynchronous local scan with real-time progress updates.
type ScanJob struct {
	mu            sync.RWMutex
	ID            string   `json:"id"`
	Status        string   `json:"status"` // "running", "done", "canceled", "error"
	Targets       []string `json:"targets"`
	StartedAt     string   `json:"started_at"`
	startTime     time.Time
	ElapsedMs     int64              `json:"elapsed_ms"`
	FilesScanned  int                `json:"files_scanned"`
	BytesScanned  int64              `json:"bytes_scanned"`
	Malicious     int                `json:"malicious"`
	Suspicious    int                `json:"suspicious"`
	Clean         int                `json:"clean"`
	CurrentFile   string             `json:"current_file"`
	RecentFlagged []model.FileResult `json:"recent_flagged,omitempty"`
	HistoryID     string             `json:"history_id,omitempty"`
	Result        *HistoryItem       `json:"result,omitempty"`
	Error         string             `json:"error,omitempty"`
	cancelCh      chan struct{}
	cancelOnce    sync.Once
}

func (j *ScanJob) cancel() {
	j.cancelOnce.Do(func() {
		if j.cancelCh != nil {
			close(j.cancelCh)
		}
	})
}

func (j *ScanJob) snapshot(includeResult bool) map[string]any {
	j.mu.RLock()
	defer j.mu.RUnlock()
	elapsed := j.ElapsedMs
	if j.Status == "running" {
		elapsed = time.Since(j.startTime).Milliseconds()
	}
	flaggedCopy := append([]model.FileResult(nil), j.RecentFlagged...)
	out := map[string]any{
		"id":             j.ID,
		"status":         j.Status,
		"targets":        j.Targets,
		"started_at":     j.StartedAt,
		"elapsed_ms":     elapsed,
		"files_scanned":  j.FilesScanned,
		"bytes_scanned":  j.BytesScanned,
		"malicious":      j.Malicious,
		"suspicious":     j.Suspicious,
		"clean":          j.Clean,
		"current_file":   j.CurrentFile,
		"recent_flagged": flaggedCopy,
		"history_id":     j.HistoryID,
		"error":          j.Error,
	}
	if includeResult && j.Result != nil {
		out["result"] = j.Result
	}
	return out
}

// QuarantineItem represents one quarantined file inside the local vault.
type QuarantineItem struct {
	QuarantinedPath string                `json:"quarantined_path"`
	OriginalPath    string                `json:"original_path"`
	Filename        string                `json:"filename"`
	Size            int64                 `json:"size"`
	SHA256          string                `json:"sha256"`
	Score           int                   `json:"score"`
	Verdict         string                `json:"verdict"`
	QuarantinedAt   string                `json:"quarantined_at"`
	TopFinding      string                `json:"top_finding"`
	Findings        []model.Finding       `json:"findings,omitempty"`
	DownloadSource  *model.DownloadSource `json:"download_source,omitempty"`
}

func (s *Server) initDesktopState() {
	s.settings = DesktopSettings{
		Workers:         s.opts.Workers,
		MaxSizeMB:       s.opts.MaxSizeMB,
		ExtractDepth:    s.opts.ExtractDepth,
		ExtractMaxMB:    s.opts.ExtractMaxMB,
		TempDir:         s.opts.TempDir,
		QuarantineDir:   s.opts.QuarantineDir,
		SkipAssets:      true,
		Carve:           true,
		UseCache:        true,
		WatchDir:        defaultDownloadsDir(),
		WatchInterval:   4,
		WatchQuarantine: false,
		WatchToast:      true,
	}
	if s.opts.PublicMode || s.opts.DataDir == "" {
		return
	}
	_ = os.MkdirAll(s.opts.DataDir, 0o755)
	s.loadSettings()
	s.loadHistory()
}

func (s *Server) settingsPath() string {
	if s.opts.DataDir == "" {
		return ""
	}
	return filepath.Join(s.opts.DataDir, "settings.json")
}

func (s *Server) historyPath() string {
	if s.opts.DataDir == "" {
		return ""
	}
	return filepath.Join(s.opts.DataDir, "history.json")
}

func (s *Server) loadSettings() {
	p := s.settingsPath()
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var st DesktopSettings
	if err := json.Unmarshal(b, &st); err != nil {
		return
	}
	s.applySettingsLocked(st)
}

func (s *Server) applySettingsLocked(st DesktopSettings) {
	if st.Workers < 1 {
		st.Workers = 1
	}
	if st.Workers > 16 {
		st.Workers = 16
	}
	if st.MaxSizeMB < 16 {
		st.MaxSizeMB = 512
	}
	if st.ExtractDepth < 0 {
		st.ExtractDepth = 0
	}
	if st.ExtractDepth > 4 {
		st.ExtractDepth = 4
	}
	if st.ExtractMaxMB < 50 {
		st.ExtractMaxMB = 500
	}
	if strings.TrimSpace(st.TempDir) == "" {
		st.TempDir = s.opts.TempDir
	}
	if strings.TrimSpace(st.QuarantineDir) == "" {
		st.QuarantineDir = s.opts.QuarantineDir
	}
	if st.WatchInterval < 2 {
		st.WatchInterval = 4
	}
	if strings.TrimSpace(st.WatchDir) == "" {
		st.WatchDir = defaultDownloadsDir()
	}
	s.settings = st
	s.opts.Workers = st.Workers
	s.opts.MaxSizeMB = st.MaxSizeMB
	s.opts.ExtractDepth = st.ExtractDepth
	s.opts.ExtractMaxMB = st.ExtractMaxMB
	s.opts.TempDir = st.TempDir
	s.opts.QuarantineDir = st.QuarantineDir
	if st.VTKey != "" || st.MBKey != "" {
		s.opts.Online = online.New(st.VTKey, st.MBKey, 16*time.Second)
	}
}

func (s *Server) saveSettings() error {
	p := s.settingsPath()
	if p == "" || s.opts.PublicMode {
		return nil
	}
	s.mu.RLock()
	st := s.settings
	s.mu.RUnlock()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func (s *Server) loadHistory() {
	p := s.historyPath()
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var items []HistoryItem
	if err := json.Unmarshal(b, &items); err != nil {
		return
	}
	if len(items) > 100 {
		items = items[len(items)-100:]
	}
	s.mu.Lock()
	s.history = items
	for _, it := range items {
		if it.Source == "drag-drop" || it.Summary == nil {
			continue
		}
		for _, r := range it.Summary.Results {
			if !r.Skipped && r.Score >= 30 && filepath.IsAbs(r.Path) {
				s.flaggedPath[r.Path] = r
			}
		}
	}
	s.mu.Unlock()
}

func (s *Server) persistHistory() {
	p := s.historyPath()
	if p == "" || s.opts.PublicMode {
		return
	}
	s.mu.RLock()
	cp := make([]HistoryItem, len(s.history))
	copy(cp, s.history)
	s.mu.RUnlock()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	b, err := json.Marshal(cp)
	if err != nil {
		return
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err == nil {
		_ = os.Rename(tmp, p)
	}
}

// LastHeartbeat returns when the desktop UI last pinged the server.
func (s *Server) LastHeartbeat() time.Time {
	return time.Unix(atomic.LoadInt64(&s.lastHeartbeat), 0)
}

// ActiveClients returns the number of currently open desktop UI window streams.
func (s *Server) ActiveClients() int64 {
	return atomic.LoadInt64(&s.activeClients)
}

// SeenClient reports whether at least one desktop UI window has connected.
func (s *Server) SeenClient() bool {
	return atomic.LoadInt64(&s.seenClient) > 0
}

// ActiveJobs returns how many local scan jobs are currently running.
func (s *Server) ActiveJobs() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, j := range s.jobs {
		j.mu.RLock()
		if j.Status == "running" {
			n++
		}
		j.mu.RUnlock()
	}
	return n
}

// WatchActive reports whether Download Guard is currently monitoring a folder.
func (s *Server) WatchActive() bool {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	return s.watchActive
}

func (s *Server) handleAppHeartbeat(w http.ResponseWriter, r *http.Request) {
	atomic.StoreInt64(&s.lastHeartbeat, time.Now().Unix())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAppStream holds a lightweight Server-Sent Events connection open for as
// long as the desktop app window is open. Unlike setInterval polling, an open
// TCP stream is never throttled when minimized and closes immediately when the
// user clicks the window X button.
func (s *Server) handleAppStream(w http.ResponseWriter, r *http.Request) {
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "disabled in public mode"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	atomic.AddInt64(&s.activeClients, 1)
	atomic.StoreInt64(&s.seenClient, 1)
	atomic.StoreInt64(&s.lastHeartbeat, time.Now().Unix())
	defer func() {
		atomic.AddInt64(&s.activeClients, -1)
		atomic.StoreInt64(&s.lastHeartbeat, time.Now().Unix())
	}()

	fmt.Fprint(w, "event: ready\ndata: ok\n\n")
	flusher.Flush()

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			atomic.StoreInt64(&s.lastHeartbeat, time.Now().Unix())
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleAppQuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "disabled in public mode"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"quitting": true})
	if s.opts.OnQuit != nil {
		go func() {
			time.Sleep(150 * time.Millisecond)
			s.opts.OnQuit()
		}()
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	s.watchMu.Lock()
	watching, wdir := s.watchActive, s.watchDir
	wEvents := append([]watch.Event(nil), s.watchEvents...)
	s.watchMu.Unlock()

	s.mu.RLock()
	totalScans := len(s.history)
	var totalFiles, totalMal, totalSus, totalClean int
	type recentScan struct {
		ID         string `json:"id"`
		Time       string `json:"time"`
		Source     string `json:"source"`
		Target     string `json:"target"`
		TopVerdict string `json:"top_verdict"`
		MaxScore   int    `json:"max_score"`
		Scanned    int    `json:"files_scanned"`
		Malicious  int    `json:"malicious"`
		Suspicious int    `json:"suspicious"`
		DurationMs int64  `json:"duration_ms"`
	}
	var recents []recentScan
	for i := len(s.history) - 1; i >= 0; i-- {
		h := s.history[i]
		if h.Summary != nil {
			totalFiles += h.Summary.FilesScanned
			totalMal += h.Summary.Malicious
			totalSus += h.Summary.Suspicious
			totalClean += h.Summary.Clean
		}
		if len(recents) < 8 {
			var sc, mal, sus int
			var dur int64
			if h.Summary != nil {
				sc = h.Summary.FilesScanned
				mal = h.Summary.Malicious
				sus = h.Summary.Suspicious
				dur = h.Summary.DurationMs
			}
			recents = append(recents, recentScan{
				ID:         h.ID,
				Time:       h.Time,
				Source:     h.Source,
				Target:     h.Target,
				TopVerdict: h.TopVerdict,
				MaxScore:   h.MaxScore,
				Scanned:    sc,
				Malicious:  mal,
				Suspicious: sus,
				DurationMs: dur,
			})
		}
	}
	workers := s.opts.Workers
	tempDir := s.opts.TempDir
	quarDir := s.opts.QuarantineDir
	cachePath := s.opts.CachePath
	onlineEnabled := s.opts.Online != nil && s.opts.Online.Enabled()
	yaraOn := s.opts.Yara != nil
	yaraRules := 0
	if s.opts.Yara != nil {
		yaraRules = s.opts.Yara.RulesLoaded
	}
	activeJobs := 0
	for _, j := range s.jobs {
		j.mu.RLock()
		if j.Status == "running" {
			activeJobs++
		}
		j.mu.RUnlock()
	}
	s.mu.RUnlock()

	has7z, hasUnrar, hasFreeArc := scan.ExtractorsAvailable()
	cacheEntries, cacheBytes := cacheFileStats(cachePath)

	protState := "ready"
	if s.opts.PublicMode {
		protState = "online"
	} else if watching {
		protState = "protected"
	}

	quarCount := 0
	var quickTargets []map[string]string
	if !s.opts.PublicMode {
		quarCount = len(s.collectQuarantineItems())
		quickTargets = detectQuickTargets()
	}
	if len(wEvents) > 8 {
		wEvents = wEvents[:8]
	}

	resp := map[string]any{
		"protection_state":  protState,
		"version":           version.Short(),
		"public_mode":       s.opts.PublicMode,
		"desktop_mode":      s.opts.DesktopMode,
		"watching":          watching,
		"watch_dir":         "",
		"active_jobs":       activeJobs,
		"yara":              yaraOn,
		"yara_rules":        yaraRules,
		"extractor_7z":      has7z,
		"extractor_unrar":   hasUnrar,
		"extractor_freearc": hasFreeArc,
		"online_enabled":    onlineEnabled,
		"cpu_cores":         runtime.NumCPU(),
		"workers":           workers,
		"cache_entries":     cacheEntries,
		"cache_bytes":       cacheBytes,
		"stats": map[string]any{
			"total_scans":      totalScans,
			"total_files":      totalFiles,
			"total_malicious":  totalMal,
			"total_suspicious": totalSus,
			"total_clean":      totalClean,
			"quarantine_count": quarCount,
			"watch_events":     len(wEvents),
		},
		"quick_targets": quickTargets,
		"recent_scans":  recents,
		"recent_watch":  wEvents,
	}
	if !s.opts.PublicMode {
		resp["watch_dir"] = wdir
		resp["temp_dir"] = tempDir
		resp["quarantine_dir"] = quarDir
		resp["cache_path"] = cachePath
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleJobsList(w http.ResponseWriter, r *http.Request) {
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local scan jobs are disabled in public web mode"})
		return
	}
	s.mu.RLock()
	out := make([]map[string]any, 0, len(s.jobOrder))
	for i := len(s.jobOrder) - 1; i >= 0; i-- {
		if j, ok := s.jobs[s.jobOrder[i]]; ok {
			out = append(out, j.snapshot(false))
		}
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

func (s *Server) handleJobStartScanPaths(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local disk path scanning is disabled in public web mode"})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tidak ada folder/file valid yang ditemukan"})
		return
	}

	s.mu.RLock()
	depth := s.opts.ExtractDepth
	carveDefault := s.settings.Carve
	s.mu.RUnlock()
	if req.ExtractDepth != nil {
		depth = *req.ExtractDepth
	}
	carve := carveDefault
	if req.Carve != nil {
		carve = *req.Carve
	}

	jobID := "job-" + strconv.FormatInt(time.Now().Unix(), 10) + "-" + strconv.FormatInt(atomic.AddInt64(&s.seq, 1), 10)
	job := &ScanJob{
		ID:        jobID,
		Status:    "running",
		Targets:   cleanPaths,
		StartedAt: time.Now().Format("2006-01-02 15:04:05"),
		startTime: time.Now(),
		cancelCh:  make(chan struct{}),
	}

	s.mu.Lock()
	s.jobs[jobID] = job
	s.jobOrder = append(s.jobOrder, jobID)
	if len(s.jobOrder) > 25 {
		old := s.jobOrder[0]
		s.jobOrder = s.jobOrder[1:]
		delete(s.jobs, old)
	}
	s.mu.Unlock()

	src := req.Source
	if src == "" {
		if len(cleanPaths) > 1 {
			src = "mass"
		} else {
			src = "paths"
		}
	}

	go func() {
		cfg := s.baseScanConfig(cleanPaths[0], depth, req.Online, carve)
		cfg.Cancel = job.cancelCh
		cfg.OnProgress = func(scanned int, res model.FileResult) {
			job.mu.Lock()
			job.FilesScanned = scanned
			job.BytesScanned += res.Size
			job.CurrentFile = res.Path
			switch res.Verdict {
			case model.VerdictMalicious:
				job.Malicious++
			case model.VerdictSuspicious:
				job.Suspicious++
			default:
				job.Clean++
			}
			if res.Score >= 30 {
				job.RecentFlagged = append([]model.FileResult{res}, job.RecentFlagged...)
				if len(job.RecentFlagged) > 20 {
					job.RecentFlagged = job.RecentFlagged[:20]
				}
			}
			job.mu.Unlock()
		}

		sc, err := scan.New(cfg)
		if err != nil {
			job.mu.Lock()
			job.Status = "error"
			job.Error = err.Error()
			job.ElapsedMs = time.Since(job.startTime).Milliseconds()
			job.mu.Unlock()
			return
		}
		defer sc.Close()

		sum, err := sc.ScanPaths(cleanPaths)
		if err != nil {
			job.mu.Lock()
			job.Status = "error"
			job.Error = err.Error()
			job.ElapsedMs = time.Since(job.startTime).Milliseconds()
			job.mu.Unlock()
			return
		}

		canceled := false
		select {
		case <-job.cancelCh:
			canceled = true
		default:
		}

		label := cleanPaths[0]
		if len(cleanPaths) > 1 {
			label = fmt.Sprintf("%s (+%d target)", filepath.Base(cleanPaths[0]), len(cleanPaths)-1)
		}
		if canceled {
			label += " [Dibatalkan]"
		}
		item := s.recordHistory(src, label, req.SourceURL, sum)

		job.mu.Lock()
		job.ElapsedMs = time.Since(job.startTime).Milliseconds()
		job.FilesScanned = sum.FilesScanned
		job.BytesScanned = sum.BytesScanned
		job.Malicious = sum.Malicious
		job.Suspicious = sum.Suspicious
		job.Clean = sum.Clean
		job.HistoryID = item.ID
		job.Result = &item
		if canceled {
			job.Status = "canceled"
		} else {
			job.Status = "done"
		}
		job.mu.Unlock()
	}()

	writeJSON(w, http.StatusOK, job.snapshot(false))
}

func (s *Server) handleJobByID(w http.ResponseWriter, r *http.Request) {
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local scan jobs are disabled in public web mode"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	if strings.HasSuffix(rest, "/cancel") {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimSuffix(rest, "/cancel")
		s.mu.RLock()
		j, ok := s.jobs[id]
		s.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		j.cancel()
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "canceling": true})
		return
	}
	s.mu.RLock()
	j, ok := s.jobs[rest]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, j.snapshot(true))
}

func (s *Server) quarantineRoots() []string {
	seen := map[string]bool{}
	var roots []string
	add := func(dir string) {
		if dir == "" {
			return
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			abs = dir
		}
		key := strings.ToLower(abs)
		if seen[key] {
			return
		}
		if st, err := os.Stat(abs); err == nil && st.IsDir() {
			seen[key] = true
			roots = append(roots, abs)
		}
	}
	s.mu.RLock()
	qdir := s.opts.QuarantineDir
	s.mu.RUnlock()
	add(qdir)

	s.watchMu.Lock()
	wdir := s.watchDir
	s.watchMu.Unlock()
	if wdir != "" {
		add(filepath.Join(wdir, ".quarantine"))
	}
	if dl := defaultDownloadsDir(); dl != "" {
		add(filepath.Join(dl, ".quarantine"))
	}
	return roots
}

func (s *Server) collectQuarantineItems() []QuarantineItem {
	roots := s.quarantineRoots()
	var items []QuarantineItem
	seen := map[string]bool{}

	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".quarantined.json") {
				return nil
			}
			qPath := strings.TrimSuffix(path, ".json")
			key := strings.ToLower(qPath)
			if seen[key] {
				return nil
			}
			st, err := os.Stat(qPath)
			if err != nil {
				return nil
			}
			seen[key] = true
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			var meta struct {
				OriginalPath   string                `json:"original_path"`
				SHA256         string                `json:"sha256"`
				Score          int                   `json:"score"`
				Verdict        string                `json:"verdict"`
				Findings       []model.Finding       `json:"findings"`
				DownloadSource *model.DownloadSource `json:"download_source"`
				QuarantinedAt  string                `json:"quarantined_at"`
			}
			_ = json.Unmarshal(b, &meta)
			top := ""
			bestSev := -1
			for _, f := range meta.Findings {
				if f.Severity > bestSev {
					bestSev = f.Severity
					top = f.Rule + ": " + f.Detail
				}
			}
			fname := filepath.Base(meta.OriginalPath)
			if fname == "" || fname == "." {
				fname = strings.TrimSuffix(filepath.Base(qPath), ".quarantined")
			}
			items = append(items, QuarantineItem{
				QuarantinedPath: qPath,
				OriginalPath:    meta.OriginalPath,
				Filename:        fname,
				Size:            st.Size(),
				SHA256:          meta.SHA256,
				Score:           meta.Score,
				Verdict:         meta.Verdict,
				QuarantinedAt:   meta.QuarantinedAt,
				TopFinding:      top,
				Findings:        meta.Findings,
				DownloadSource:  meta.DownloadSource,
			})
			return nil
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].QuarantinedAt > items[j].QuarantinedAt
	})
	return items
}

func (s *Server) findQuarantineItem(qPath string) (QuarantineItem, bool) {
	want := strings.ToLower(filepath.Clean(qPath))
	for _, it := range s.collectQuarantineItems() {
		if strings.ToLower(filepath.Clean(it.QuarantinedPath)) == want {
			return it, true
		}
	}
	return QuarantineItem{}, false
}

func (s *Server) handleQuarantineList(w http.ResponseWriter, r *http.Request) {
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "quarantine vault is disabled in public web mode"})
		return
	}
	s.mu.RLock()
	qdir := s.opts.QuarantineDir
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_dir": qdir,
		"items":     s.collectQuarantineItems(),
	})
}

func (s *Server) handleQuarantineRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "quarantine vault is disabled in public web mode"})
		return
	}
	var req struct {
		QuarantinedPath string `json:"quarantined_path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	item, ok := s.findQuarantineItem(req.QuarantinedPath)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "file karantina tidak ditemukan di vault"})
		return
	}
	dst := item.OriginalPath
	if dst == "" {
		dst = filepath.Join(defaultDownloadsDir(), item.Filename)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if _, err := os.Stat(dst); err == nil {
		ext := filepath.Ext(dst)
		base := strings.TrimSuffix(dst, ext)
		dst = fmt.Sprintf("%s.restored-%d%s", base, time.Now().Unix(), ext)
	}
	if err := os.Rename(item.QuarantinedPath, dst); err != nil {
		if err := copySimple(item.QuarantinedPath, dst); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal restore: " + err.Error()})
			return
		}
		_ = os.Remove(item.QuarantinedPath)
	}
	_ = os.Remove(item.QuarantinedPath + ".json")
	writeJSON(w, http.StatusOK, map[string]string{"restored_to": dst})
}

func (s *Server) handleQuarantineDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "quarantine vault is disabled in public web mode"})
		return
	}
	var req struct {
		QuarantinedPath string `json:"quarantined_path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	item, ok := s.findQuarantineItem(req.QuarantinedPath)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "file karantina tidak ditemukan di vault"})
		return
	}
	if err := os.Remove(item.QuarantinedPath); err != nil && !os.IsNotExist(err) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_ = os.Remove(item.QuarantinedPath + ".json")
	writeJSON(w, http.StatusOK, map[string]string{"deleted": item.QuarantinedPath})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "settings are disabled in public web mode"})
		return
	}
	if r.Method == http.MethodGet {
		s.mu.RLock()
		st := s.settings
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"workers":          st.Workers,
			"max_size_mb":      st.MaxSizeMB,
			"extract_depth":    st.ExtractDepth,
			"extract_max_mb":   st.ExtractMaxMB,
			"temp_dir":         st.TempDir,
			"quarantine_dir":   st.QuarantineDir,
			"skip_assets":      st.SkipAssets,
			"carve":            st.Carve,
			"use_cache":        st.UseCache,
			"vt_key_set":       st.VTKey != "",
			"mb_key_set":       st.MBKey != "",
			"watch_auto_start": st.WatchAutoStart,
			"watch_dir":        st.WatchDir,
			"watch_interval":   st.WatchInterval,
			"watch_quarantine": st.WatchQuarantine,
			"watch_toast":      st.WatchToast,
			"cpu_cores":        runtime.NumCPU(),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Workers         *int    `json:"workers"`
		MaxSizeMB       *int64  `json:"max_size_mb"`
		ExtractDepth    *int    `json:"extract_depth"`
		ExtractMaxMB    *int64  `json:"extract_max_mb"`
		TempDir         *string `json:"temp_dir"`
		QuarantineDir   *string `json:"quarantine_dir"`
		SkipAssets      *bool   `json:"skip_assets"`
		Carve           *bool   `json:"carve"`
		UseCache        *bool   `json:"use_cache"`
		VTKey           *string `json:"vt_api_key"`
		MBKey           *string `json:"mb_api_key"`
		ClearVTKey      bool    `json:"clear_vt_key"`
		ClearMBKey      bool    `json:"clear_mb_key"`
		WatchAutoStart  *bool   `json:"watch_auto_start"`
		WatchDir        *string `json:"watch_dir"`
		WatchInterval   *int    `json:"watch_interval"`
		WatchQuarantine *bool   `json:"watch_quarantine"`
		WatchToast      *bool   `json:"watch_toast"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 128*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	s.mu.Lock()
	st := s.settings
	if req.Workers != nil {
		st.Workers = *req.Workers
	}
	if req.MaxSizeMB != nil {
		st.MaxSizeMB = *req.MaxSizeMB
	}
	if req.ExtractDepth != nil {
		st.ExtractDepth = *req.ExtractDepth
	}
	if req.ExtractMaxMB != nil {
		st.ExtractMaxMB = *req.ExtractMaxMB
	}
	if req.TempDir != nil && strings.TrimSpace(*req.TempDir) != "" {
		st.TempDir = strings.TrimSpace(*req.TempDir)
	}
	if req.QuarantineDir != nil && strings.TrimSpace(*req.QuarantineDir) != "" {
		st.QuarantineDir = strings.TrimSpace(*req.QuarantineDir)
	}
	if req.SkipAssets != nil {
		st.SkipAssets = *req.SkipAssets
	}
	if req.Carve != nil {
		st.Carve = *req.Carve
	}
	if req.UseCache != nil {
		st.UseCache = *req.UseCache
	}
	if req.ClearVTKey {
		st.VTKey = ""
	} else if req.VTKey != nil && strings.TrimSpace(*req.VTKey) != "" {
		st.VTKey = strings.TrimSpace(*req.VTKey)
	}
	if req.ClearMBKey {
		st.MBKey = ""
	} else if req.MBKey != nil && strings.TrimSpace(*req.MBKey) != "" {
		st.MBKey = strings.TrimSpace(*req.MBKey)
	}
	if req.WatchAutoStart != nil {
		st.WatchAutoStart = *req.WatchAutoStart
	}
	if req.WatchDir != nil && strings.TrimSpace(*req.WatchDir) != "" {
		st.WatchDir = strings.TrimSpace(*req.WatchDir)
	}
	if req.WatchInterval != nil {
		st.WatchInterval = *req.WatchInterval
	}
	if req.WatchQuarantine != nil {
		st.WatchQuarantine = *req.WatchQuarantine
	}
	if req.WatchToast != nil {
		st.WatchToast = *req.WatchToast
	}
	s.applySettingsLocked(st)
	if st.VTKey == "" && st.MBKey == "" {
		s.opts.Online = nil
	}
	s.mu.Unlock()
	if err := s.saveSettings(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan pengaturan: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "disabled in public web mode"})
		return
	}
	s.mu.RLock()
	cp := s.opts.CachePath
	s.mu.RUnlock()
	if cp != "" {
		_ = os.Remove(cp)
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

func (s *Server) handleHistoryClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "disabled in public web mode"})
		return
	}
	s.mu.Lock()
	s.history = nil
	s.flaggedPath = map[string]model.FileResult{}
	s.mu.Unlock()
	if hp := s.historyPath(); hp != "" {
		_ = os.Remove(hp)
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

func (s *Server) handleOpenExplorer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "disabled in public web mode"})
		return
	}
	if runtime.GOOS != "windows" {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "Windows-only feature"})
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	p := strings.TrimSpace(req.Path)
	st, err := os.Stat(p)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "path tidak ditemukan"})
		return
	}
	if st.IsDir() {
		_ = exec.Command("explorer.exe", p).Start()
	} else {
		_ = exec.Command("explorer.exe", "/select,"+p).Start()
	}
	writeJSON(w, http.StatusOK, map[string]any{"opened": p})
}

func (s *Server) handleDesktopShortcut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PublicMode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "disabled in public web mode"})
		return
	}
	if runtime.GOOS != "windows" {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "Windows-only feature"})
		return
	}
	exe, err := os.Executable()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	dir := filepath.Dir(exe)
	targetExe := filepath.Join(dir, "CrackSentinel.exe")
	if _, err := os.Stat(targetExe); err != nil {
		targetExe = exe
	}
	ps := `$ws = New-Object -ComObject WScript.Shell; $desk = [Environment]::GetFolderPath('Desktop'); $lnk = $ws.CreateShortcut((Join-Path $desk 'CrackSentinel.lnk')); $lnk.TargetPath = $env:CS_EXE; $lnk.WorkingDirectory = $env:CS_DIR; $lnk.IconLocation = "$env:CS_EXE,0"; $lnk.Description = 'CrackSentinel — Game Malware Guard'; $lnk.Save(); Write-Output $lnk.FullName`
	cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
	procutil.HideWindow(cmd)
	cmd.Env = append(os.Environ(), "CS_EXE="+targetExe, "CS_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal membuat shortcut: " + strings.TrimSpace(string(out))})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"shortcut": strings.TrimSpace(string(out))})
}

func cacheFileStats(path string) (entries int, bytes int64) {
	if path == "" {
		return 0, 0
	}
	st, err := os.Stat(path)
	if err != nil {
		return 0, 0
	}
	bytes = st.Size()
	f, err := os.Open(path)
	if err != nil {
		return 0, bytes
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) > 0 {
			entries++
		}
	}
	return entries, bytes
}

func detectQuickTargets() []map[string]string {
	var out []map[string]string
	seen := map[string]bool{}
	add := func(label, kind, path string) {
		if path == "" {
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		key := strings.ToLower(abs)
		if seen[key] {
			return
		}
		if st, err := os.Stat(abs); err == nil && st.IsDir() {
			seen[key] = true
			out = append(out, map[string]string{"label": label, "kind": kind, "path": abs})
		}
	}
	if dl := defaultDownloadsDir(); dl != "" {
		add("Downloads", "downloads", dl)
	}
	if home, err := os.UserHomeDir(); err == nil {
		add("Desktop", "desktop", filepath.Join(home, "Desktop"))
	}
	for _, p := range []string{
		`E:\Games`, `D:\Games`, `C:\Games`,
		`E:\Downloads`, `D:\Downloads`,
		`E:\Game`, `D:\Game`,
	} {
		add(p, "games", p)
	}
	return out
}

func copySimple(src, dst string) error {
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
