package cache

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"sync"
)

type Entry struct {
	SHA256  string `json:"sha256"`
	Score   int    `json:"score"`
	Verdict string `json:"verdict"`
	Online  string `json:"online,omitempty"`
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
		sc.Buffer(make([]byte, 1<<20), 1<<20)
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

func (c *Cache) Get(sha string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[sha]
	return e, ok
}

func (c *Cache) Put(sha string, score int, verdict string) {
	c.PutOnline(sha, score, verdict, "")
}

func (c *Cache) PutOnline(sha string, score int, verdict, onlineJSON string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[sha] = Entry{SHA256: sha, Score: score, Verdict: verdict, Online: onlineJSON}
	e := Entry{SHA256: sha, Score: score, Verdict: verdict}
	if onlineJSON != "" {
		e.Online = onlineJSON
	}
	b, _ := json.Marshal(e)
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

var _ = strconv.Itoa
