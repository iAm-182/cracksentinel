package sigfeed

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gamecrack-scanner/internal/model"
)

// DefaultRemoteURL is the official GitHub Raw feed for hot-updating virus signatures
// in <0.5s without restarting or rebuilding CrackSentinel.exe.
const DefaultRemoteURL = "https://raw.githubusercontent.com/iAm-182/cracksentinel/main/signatures/live-signatures.json"

//go:embed default_signatures.json
var embeddedDefaultJSON []byte

type HashIOC struct {
	SHA256   string `json:"sha256"`
	Family   string `json:"family"`
	Severity int    `json:"severity"`
}

type PatternIOC struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

type DatabaseFile struct {
	Version     string       `json:"version"`
	UpdatedAt   string       `json:"updated_at"`
	Description string       `json:"description,omitempty"`
	Hashes      []HashIOC    `json:"hashes"`
	Patterns    []PatternIOC `json:"patterns"`
}

type compiledPattern struct {
	meta PatternIOC
	re   *regexp.Regexp
}

type snapshot struct {
	version   string
	updatedAt string
	source    string // "embedded", "local", "remote"
	syncedAt  string
	hashes    map[string]HashIOC
	patterns  []compiledPattern
}

type Status struct {
	Version      string `json:"version"`
	UpdatedAt    string `json:"updated_at"`
	Source       string `json:"source"`
	SyncedAt     string `json:"synced_at,omitempty"`
	HashCount    int    `json:"hash_count"`
	PatternCount int    `json:"pattern_count"`
}

// Store holds a lock-free atomic snapshot of live threat signatures.
type Store struct {
	cur       atomic.Pointer[snapshot]
	localPath string
	mu        sync.Mutex
}

var (
	defaultOnce  sync.Once
	defaultStore *Store
)

// Global returns the process-wide live signature store initialized with the
// embedded baseline (and upgraded with local disk signatures when InitLocal is called).
func Global() *Store {
	defaultOnce.Do(func() {
		defaultStore = New("")
	})
	return defaultStore
}

// New creates a Store backed by embedded signatures and an optional persistent JSON file.
func New(localPath string) *Store {
	s := &Store{localPath: localPath}
	if snap, err := compileSnapshot(embeddedDefaultJSON, "embedded", ""); err == nil {
		s.cur.Store(snap)
	}
	if localPath != "" {
		_ = s.LoadLocal(localPath)
	}
	return s
}

// LoadLocal loads a persisted live-signatures.json if its version is >= the current snapshot.
func (s *Store) LoadLocal(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path != "" {
		s.localPath = path
	}
	if s.localPath == "" {
		return nil
	}
	b, err := os.ReadFile(s.localPath)
	if err != nil {
		return err
	}
	snap, err := compileSnapshot(b, "local", "")
	if err != nil {
		return err
	}
	cur := s.cur.Load()
	if cur == nil || snap.version >= cur.version {
		s.cur.Store(snap)
	}
	return nil
}

// Status returns metadata about the active signature snapshot.
func (s *Store) Status() Status {
	snap := s.cur.Load()
	if snap == nil {
		return Status{Version: "0", Source: "none"}
	}
	return Status{
		Version:      snap.version,
		UpdatedAt:    snap.updatedAt,
		Source:       snap.source,
		SyncedAt:     snap.syncedAt,
		HashCount:    len(snap.hashes),
		PatternCount: len(snap.patterns),
	}
}

// Sync fetches the latest live-signatures.json from remoteURL, validates all regexes,
// atomically swaps the in-memory snapshot, and persists to localPath.
func (s *Store) Sync(ctx context.Context, remoteURL string) (Status, bool, error) {
	if strings.TrimSpace(remoteURL) == "" {
		remoteURL = DefaultRemoteURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteURL, nil)
	if err != nil {
		return s.Status(), false, err
	}
	req.Header.Set("User-Agent", "CrackSentinel-SigSync/2.1")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return s.Status(), false, fmt.Errorf("gagal menghubungi server database virus: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s.Status(), false, fmt.Errorf("HTTP %d saat mengunduh database virus", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return s.Status(), false, err
	}
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	snap, err := compileSnapshot(raw, "remote", nowStr)
	if err != nil {
		return s.Status(), false, fmt.Errorf("format database tidak valid: %w", err)
	}

	s.mu.Lock()
	prev := s.cur.Load()
	changed := prev == nil || prev.version != snap.version || len(prev.hashes) != len(snap.hashes) || len(prev.patterns) != len(snap.patterns)
	s.cur.Store(snap)
	lp := s.localPath
	s.mu.Unlock()

	if lp != "" {
		_ = os.MkdirAll(filepath.Dir(lp), 0o755)
		tmp := lp + ".tmp"
		if err := os.WriteFile(tmp, raw, 0o644); err == nil {
			_ = os.Rename(tmp, lp)
		}
	}
	return s.Status(), changed, nil
}

// Match evaluates both SHA-256 IOCs and live regex signatures against a file's hash & strings.
func (s *Store) Match(sha256Hex string, strs []string) []model.Finding {
	snap := s.cur.Load()
	if snap == nil {
		return nil
	}
	var out []model.Finding
	if sha256Hex != "" {
		if h, ok := snap.hashes[strings.ToLower(sha256Hex)]; ok {
			sev := h.Severity
			if sev <= 0 {
				sev = 90
			}
			out = append(out, model.Finding{
				Rule:     "live_sha256_blacklist",
				Category: "stealer",
				Severity: sev,
				Detail:   fmt.Sprintf("live threat-intel SHA-256 blacklist match: %s (db %s)", h.Family, snap.version),
			})
		}
	}
	if len(strs) == 0 || len(snap.patterns) == 0 {
		return out
	}
	matched := make([]bool, len(snap.patterns))
	rem := len(snap.patterns)
	for _, line := range strs {
		if rem == 0 {
			break
		}
		for i := range snap.patterns {
			if matched[i] {
				continue
			}
			if snap.patterns[i].re.MatchString(line) {
				matched[i] = true
				rem--
				meta := snap.patterns[i].meta
				sev := meta.Severity
				if sev <= 0 {
					sev = 45
				}
				cat := meta.Category
				if cat == "" {
					cat = "stealer"
				}
				snippet := line
				if len(snippet) > 80 {
					snippet = snippet[:80] + "..."
				}
				out = append(out, model.Finding{
					Rule:     "live_" + meta.ID,
					Category: cat,
					Severity: sev,
					Detail:   meta.Description + ": " + snippet,
				})
			}
		}
	}
	return out
}

func compileSnapshot(raw []byte, source, syncedAt string) (*snapshot, error) {
	var db DatabaseFile
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil, err
	}
	if strings.TrimSpace(db.Version) == "" {
		return nil, fmt.Errorf("missing database version")
	}
	if len(db.Hashes) > 50000 || len(db.Patterns) > 2000 {
		return nil, fmt.Errorf("database exceeds safety limits")
	}
	hm := make(map[string]HashIOC, len(db.Hashes))
	for _, h := range db.Hashes {
		k := strings.ToLower(strings.TrimSpace(h.SHA256))
		if len(k) == 64 {
			hm[k] = h
		}
	}
	var pats []compiledPattern
	for _, p := range db.Patterns {
		id := sanitizeRuleID(p.ID)
		if id == "" || strings.TrimSpace(p.Pattern) == "" || len(p.Pattern) > 2048 {
			continue
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex in %s: %w", id, err)
		}
		p.ID = id
		pats = append(pats, compiledPattern{meta: p, re: re})
	}
	return &snapshot{
		version:   db.Version,
		updatedAt: db.UpdatedAt,
		source:    source,
		syncedAt:  syncedAt,
		hashes:    hm,
		patterns:  pats,
	}, nil
}

func sanitizeRuleID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
