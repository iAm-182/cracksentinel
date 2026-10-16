// Package telemetry talks to the CrackSentinel shared-reputation worker
// (worker/): GET /v1/lookup/:sha for community verdicts, POST /v1/report
// to contribute ours. Opt-in only; failures never fail a scan.
package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	base   string
	key    string
	http   *http.Client
	warned bool
}

type SharedRep struct {
	Found   bool   `json:"found"`
	Verdict string `json:"verdict"`
	Score   int    `json:"score"`
	Count   int    `json:"count"`
}

type ReportEntry struct {
	SHA     string   `json:"sha"`
	Verdict string   `json:"verdict"`
	Score   int      `json:"score"`
	Rules   []string `json:"rules,omitempty"`
}

func New(baseURL, key string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		key:  key,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.base != "" && c.key != ""
}

// Lookup returns the community verdict for one sha256. Not-found is a
// non-error (Found=false); transport errors are returned.
func (c *Client) Lookup(sha string) (*SharedRep, error) {
	if !c.Enabled() {
		return &SharedRep{}, nil
	}
	req, err := http.NewRequest("GET", c.base+"/v1/lookup/"+sha, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("lookup status %d", resp.StatusCode)
	}
	var rep SharedRep
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// ReportBatch uploads verdicts in one request (server cap: 500).
func (c *Client) ReportBatch(entries []ReportEntry) error {
	if !c.Enabled() || len(entries) == 0 {
		return nil
	}
	for i := 0; i < len(entries); i += 500 {
		end := i + 500
		if end > len(entries) {
			end = len(entries)
		}
		if err := c.postBatch(entries[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) postBatch(entries []ReportEntry) error {
	body, _ := json.Marshal(map[string]any{"reports": entries})
	req, err := http.NewRequest("POST", c.base+"/v1/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("report status %d", resp.StatusCode)
	}
	return nil
}

// ScoreDelta converts a community verdict into a score bump. Only confident
// community signals (2+ independent reports) move the needle.
func ScoreDelta(rep *SharedRep) int {
	if rep == nil || !rep.Found || rep.Count < 2 {
		return 0
	}
	switch rep.Verdict {
	case "MALICIOUS":
		return 25
	case "SUSPICIOUS":
		return 10
	}
	return 0
}

func Describe(rep *SharedRep) string {
	return fmt.Sprintf("shared telemetry: %d report(s), verdict %s (score %d)",
		rep.Count, rep.Verdict, rep.Score)
}
