package cache

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"

	"gamecrack-scanner/internal/model"
)

// CurrentVersion is incremented whenever detection rules or scoring semantics
// change materially so stale cached verdicts automatically re-scan.
const CurrentVersion = 2

type Entry struct {
	SHA256          string          `json:"sha256"`
	Version         int             `json:"v,omitempty"`
	Score           int             `json:"score"`
	Verdict         string          `json:"verdict"`
	Type            string          `json:"type,omitempty"`
	Imphash         string          `json:"imphash,omitempty"`
	Packer          string          `json:"packer,omitempty"`
	Signed          bool            `json:"signed,omitempty"`
	Signer          string          `json:"signer,omitempty"`
	SignatureStatus string          `json:"signature_status,omitempty"`
	Findings        []model.Finding `json:"findings,omitempty"`
	Online          string          `json:"online,omitempty"`
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]Entry
	file    *os.File
	writer  *bufio.Writer
	dirty   bool
}

func Open(path string) (*Cache, error) {
	c := &Cache{entries: map[string]Entry{}}
	f, err := os.Open(path)
	if err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 4<<20), 4<<20)
		for sc.Scan() {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) == nil && e.SHA256 != "" {
				c.entries[e.SHA256] = e
			}
		}
		f.Close()
	}
	w, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	c.file = w
	c.writer = bufio.NewWriter(w)
	return c, nil
}

func (c *Cache) Get(key string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	return e, ok
}

func (c *Cache) Put(sha string, score int, verdict string) {
	c.PutOnline(sha, score, verdict, "")
}

func (c *Cache) PutOnline(sha string, score int, verdict, onlineJSON string) {
	c.PutEntry(Entry{
		SHA256:  sha,
		Version: CurrentVersion,
		Score:   score,
		Verdict: verdict,
		Online:  onlineJSON,
	})
}

// PutFull persists a complete FileResult summary (including Findings and
// signature metadata) so cache hits preserve full report details and also
// avoid re-scanning clean or carved files.
func (c *Cache) PutFull(key string, res model.FileResult, onlineJSON string) {
	c.PutEntry(Entry{
		SHA256:          key,
		Version:         CurrentVersion,
		Score:           res.Score,
		Verdict:         res.Verdict.String(),
		Type:            res.Type,
		Imphash:         res.Imphash,
		Packer:          res.Packer,
		Signed:          res.Signed,
		Signer:          res.Signer,
		SignatureStatus: res.SignatureStatus,
		Findings:        res.Findings,
		Online:          onlineJSON,
	})
}

func (c *Cache) PutEntry(e Entry) {
	if e.SHA256 == "" {
		return
	}
	if e.Version == 0 {
		e.Version = CurrentVersion
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[e.SHA256] = e
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	c.writer.Write(b)
	c.writer.WriteByte('\n')
	c.dirty = true
}

func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dirty {
		c.writer.Flush()
		c.dirty = false
	}
}

func (c *Cache) Close() {
	c.Flush()
	if c.file != nil {
		c.file.Close()
	}
}
