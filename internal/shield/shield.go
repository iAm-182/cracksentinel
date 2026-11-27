package shield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gamecrack-scanner/internal/model"
)

// ScanFunc scans a newly spawned executable on disk and returns its FileResult.
type ScanFunc func(exePath string) (model.FileResult, error)

// ToastFunc optionally sends a native desktop toast alert.
type ToastFunc func(title, body string)

// AlertEvent records an active-protection interception (Process Shield, Ransomware Guard, or NetWatch Firewall).
type AlertEvent struct {
	ID       string `json:"id"`
	Time     string `json:"time"`
	Layer    string `json:"layer"`    // "process_shield", "ransom_guard", "netwatch_wfp"
	Severity string `json:"severity"` // "CRITICAL", "HIGH", "INFO"
	PID      uint32 `json:"pid,omitempty"`
	Process  string `json:"process,omitempty"`
	ExePath  string `json:"exe_path,omitempty"`
	Remote   string `json:"remote,omitempty"`
	Score    int    `json:"score,omitempty"`
	Action   string `json:"action"` // "suspended_killed", "suspended", "ransom_frozen", "wfp_blocked", "allowed_clean"
	Summary  string `json:"summary"`
}

// NetConnection represents one live outbound/established TCP connection owned by a local PID.
type NetConnection struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	State      string `json:"state"`
	PID        uint32 `json:"pid"`
	Process    string `json:"process"`
	ExePath    string `json:"exe_path"`
	Risk       string `json:"risk"`   // "HIGH", "MEDIUM", "CLEAN"
	Reason     string `json:"reason"` // Indonesian human-readable explanation
}

// WFPRule represents a CrackSentinel outbound block rule installed in the Windows Filtering Platform (Kernel Firewall).
type WFPRule struct {
	RuleName string `json:"rule_name"`
	ExePath  string `json:"exe_path"`
	AddedAt  string `json:"added_at"`
}

// Status summarizes the real-time state of all 3 active protection layers + Kernel WFP/Defender integration.
type Status struct {
	Supported            bool         `json:"supported"`
	IsAdmin              bool         `json:"is_admin"`
	ProcessShieldOn      bool         `json:"process_shield_on"`
	ProcessAutoKill      bool         `json:"process_auto_kill"`
	WatchedRiskyDirs     []string     `json:"watched_risky_dirs"`
	ProcessesInspected   int64        `json:"processes_inspected"`
	ThreatsBlocked       int64        `json:"threats_blocked"`
	RansomGuardOn        bool         `json:"ransom_guard_on"`
	CanaryPaths          []string     `json:"canary_paths"`
	CanaryIntact         bool         `json:"canary_intact"`
	WFPKernelFirewall    bool         `json:"wfp_kernel_firewall"`
	DefenderMinifilterOn bool         `json:"defender_minifilter_on"`
	DefenderCFAEnabled   bool         `json:"defender_cfa_enabled"`
	BlockedApps          []WFPRule    `json:"blocked_apps"`
	RecentEvents         []AlertEvent `json:"recent_events"`
}

// Config persists the user's Active Protection preferences.
type Config struct {
	ProcessShieldOn bool `json:"process_shield_on"`
	ProcessAutoKill bool `json:"process_auto_kill"`
	RansomGuardOn   bool `json:"ransom_guard_on"`
}

type Manager struct {
	mu      sync.Mutex
	dataDir string
	scanFn  ScanFunc
	toastFn ToastFunc

	cfg     Config
	events  []AlertEvent
	blocked []WFPRule

	procCancel   context.CancelFunc
	ransomCancel context.CancelFunc

	inspectedCount int64
	blockedCount   int64
	cleanCache     map[string]int64  // exePath|size|mtime -> unix timestamp
	canaries       map[string]string // canaryFilePath -> expected sha256
}

func NewManager(dataDir string, scanFn ScanFunc, toastFn ToastFunc) *Manager {
	m := &Manager{
		dataDir:    dataDir,
		scanFn:     scanFn,
		toastFn:    toastFn,
		cfg:        Config{ProcessAutoKill: true},
		cleanCache: map[string]int64{},
		canaries:   map[string]string{},
	}
	m.loadState()
	return m
}

func (m *Manager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.procCancel != nil || m.ransomCancel != nil
}

func (m *Manager) StartConfigured() {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	_ = m.ApplyConfig(cfg)
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	if m.procCancel != nil {
		m.procCancel()
		m.procCancel = nil
	}
	if m.ransomCancel != nil {
		m.ransomCancel()
		m.ransomCancel = nil
	}
	m.mu.Unlock()
}

func (m *Manager) ApplyConfig(cfg Config) error {
	m.mu.Lock()
	m.cfg = cfg

	if cfg.ProcessShieldOn && m.procCancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		m.procCancel = cancel
		go m.runProcessShieldLoop(ctx)
	} else if !cfg.ProcessShieldOn && m.procCancel != nil {
		m.procCancel()
		m.procCancel = nil
	}

	if cfg.RansomGuardOn && m.ransomCancel == nil {
		_ = m.deployCanariesLocked()
		ctx, cancel := context.WithCancel(context.Background())
		m.ransomCancel = cancel
		go m.runRansomGuardLoop(ctx)
	} else if !cfg.RansomGuardOn && m.ransomCancel != nil {
		m.ransomCancel()
		m.ransomCancel = nil
	}
	m.saveStateLocked()
	m.mu.Unlock()
	return nil
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	st := Status{
		Supported:          platformSupported(),
		IsAdmin:            isProcessElevated(),
		ProcessShieldOn:    m.procCancel != nil,
		ProcessAutoKill:    m.cfg.ProcessAutoKill,
		WatchedRiskyDirs:   riskyExecutionDirs(),
		ProcessesInspected: m.inspectedCount,
		ThreatsBlocked:     m.blockedCount,
		RansomGuardOn:      m.ransomCancel != nil,
		CanaryIntact:       true,
		BlockedApps:        append([]WFPRule(nil), m.blocked...),
		RecentEvents:       append([]AlertEvent(nil), m.events...),
	}
	for p, wantHash := range m.canaries {
		st.CanaryPaths = append(st.CanaryPaths, p)
		if st.RansomGuardOn && !verifyFileSHA256(p, wantHash) {
			st.CanaryIntact = false
		}
	}
	m.mu.Unlock()

	wfp, wdFilter, cfa := queryKernelDriversStatus()
	st.WFPKernelFirewall = wfp
	st.DefenderMinifilterOn = wdFilter
	st.DefenderCFAEnabled = cfa
	return st
}

func (m *Manager) recordEvent(ev AlertEvent) {
	if ev.Time == "" {
		ev.Time = time.Now().Format("2006-01-02 15:04:05")
	}
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("sh_%d", time.Now().UnixNano())
	}
	m.mu.Lock()
	m.events = append([]AlertEvent{ev}, m.events...)
	if len(m.events) > 120 {
		m.events = m.events[:120]
	}
	if ev.Severity == "CRITICAL" || ev.Severity == "HIGH" {
		m.blockedCount++
	}
	m.saveStateLocked()
	toast := m.toastFn
	m.mu.Unlock()

	if toast != nil && (ev.Severity == "CRITICAL" || ev.Severity == "HIGH") {
		go toast("CrackSentinel Shield — "+ev.Layer, ev.Summary)
	}
}

func (m *Manager) statePath() string {
	if m.dataDir == "" {
		return ""
	}
	return filepath.Join(m.dataDir, "shield.json")
}

type persistedShield struct {
	Config  Config       `json:"config"`
	Blocked []WFPRule    `json:"blocked"`
	Events  []AlertEvent `json:"events"`
}

func (m *Manager) loadState() {
	p := m.statePath()
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var ps persistedShield
	if json.Unmarshal(b, &ps) == nil {
		m.cfg = ps.Config
		m.blocked = ps.Blocked
		m.events = ps.Events
	}
}

func (m *Manager) saveStateLocked() {
	p := m.statePath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	b, err := json.MarshalIndent(persistedShield{
		Config:  m.cfg,
		Blocked: m.blocked,
		Events:  m.events,
	}, "", "  ")
	if err == nil {
		_ = os.WriteFile(p, b, 0o600)
	}
}

// riskyExecutionDirs returns user-writable / game / temp folders where droppers,
// fake installers, and trojanized cracks execute from. System binaries in
// C:\Windows or C:\Program Files are skipped so CPU overhead stays ~0%.
func riskyExecutionDirs() []string {
	var dirs []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		clean := filepath.Clean(p)
		low := strings.ToLower(clean)
		if !seen[low] {
			seen[low] = true
			dirs = append(dirs, clean)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, "Downloads"))
		add(filepath.Join(home, "Desktop"))
	}
	add(os.TempDir())
	if appData := os.Getenv("APPDATA"); appData != "" {
		add(appData)
	}
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		add(filepath.Join(localApp, "Temp"))
	}
	for _, g := range []string{`C:\Games`, `D:\Games`, `E:\Games`, `F:\Games`} {
		if st, err := os.Stat(g); err == nil && st.IsDir() {
			add(g)
		}
	}
	return dirs
}

func normSlashPath(p string) string {
	p = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(p)), "\\", "/")
	return strings.TrimRight(p, "/")
}

func isInRiskyDir(exePath string, risky []string) bool {
	if exePath == "" {
		return false
	}
	low := normSlashPath(exePath)
	// Never intercept CrackSentinel itself, YARA/7z/UPX helper tools, or trusted browser binaries
	base := low
	if idx := strings.LastIndexByte(low, '/'); idx >= 0 {
		base = low[idx+1:]
	}
	switch base {
	case "cracksentinel.exe", "scanner.exe", "scanner-batch.exe", "scanner-label.exe",
		"7z.exe", "unrar.exe", "yara64.exe", "yara.exe", "upx.exe",
		"chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "code.exe", "git.exe":
		return false
	}
	if strings.HasPrefix(low, "c:/windows/") || strings.HasPrefix(low, "c:/program files/") || strings.HasPrefix(low, "c:/program files (x86)/") {
		return false
	}
	for _, rd := range risky {
		rdLow := normSlashPath(rd)
		if rdLow != "" && (low == rdLow || strings.HasPrefix(low, rdLow+"/")) {
			return true
		}
	}
	return false
}

const canaryBanner = "=== DOKUMEN PROTEKSI ANTI-RANSOMWARE CRACKSENTINEL ===\r\n" +
	"File umpan (Canary Honeypot) ini dijaga oleh CrackSentinel Active Shield.\r\n" +
	"Jangan ubah atau hapus file ini selama Anti-Ransomware Guard aktif.\r\n"

func (m *Manager) deployCanariesLocked() error {
	m.canaries = map[string]string{}
	var roots []string
	if home, err := os.UserHomeDir(); err == nil {
		for _, sub := range []string{"Documents", "Pictures", "Desktop"} {
			d := filepath.Join(home, sub)
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				roots = append(roots, d)
			}
		}
	}
	if len(roots) == 0 && m.dataDir != "" {
		roots = append(roots, m.dataDir)
	}
	sum := sha256.Sum256([]byte(canaryBanner))
	hexHash := hex.EncodeToString(sum[:])

	for _, r := range roots {
		// `!000_` sorts alphabetically near the very top of directory walks, which
		// causes ransomware encryptors walking Documents/Desktop to hit the canary FIRST!
		cp := filepath.Join(r, "!000_CrackSentinel_Canary_Protected.docx.txt")
		if !verifyFileSHA256(cp, hexHash) {
			_ = os.WriteFile(cp, []byte(canaryBanner), 0o644)
			hideCanaryFile(cp)
		}
		m.canaries[cp] = hexHash
	}
	return nil
}

func verifyFileSHA256(path, wantHex string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]) == wantHex
}

// scoreOutboundConnection evaluates whether a live TCP connection looks normal or suspicious (C2/RAT/Tor/Miner).
func scoreOutboundConnection(procName, exePath, remoteIP string, remotePort uint16, riskyDirs []string) (risk, reason string) {
	if remoteIP == "" || remoteIP == "0.0.0.0" || remoteIP == "127.0.0.1" || remoteIP == "::" || remoteIP == "::1" ||
		strings.HasPrefix(remoteIP, "127.") || strings.HasPrefix(remoteIP, "10.") || strings.HasPrefix(remoteIP, "192.168.") {
		return "CLEAN", "Koneksi lokal / LAN internal"
	}
	lowProc := strings.ToLower(procName)
	suspiciousPort := false
	switch remotePort {
	case 4444, 1337, 5555, 6666, 6667, 7777, 9001, 9050, 3333, 14444, 45700:
		suspiciousPort = true
	}

	// LOLBins making direct external connections are classic fileless/ClickFix C2 indicators!
	switch lowProc {
	case "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "cmd.exe":
		return "HIGH", fmt.Sprintf("LOLBin sistem (%s) terhubung langsung ke IP eksternal %s:%d!", procName, remoteIP, remotePort)
	}

	fromRisky := isInRiskyDir(exePath, riskyDirs)
	if suspiciousPort {
		return "HIGH", fmt.Sprintf("Terhubung ke port C2/RAT/Miner berisiko tinggi (:%d)", remotePort)
	}
	if fromRisky {
		return "MEDIUM", "Program dari folder Downloads/Games/Temp sedang mengakses internet keluar"
	}
	return "CLEAN", "Koneksi aplikasi standar"
}
