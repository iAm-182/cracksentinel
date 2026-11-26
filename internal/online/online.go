package online

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Provider    string `json:"provider"`
	Found       bool   `json:"found"`
	NotFound    bool   `json:"not_found,omitempty"`
	Malicious   int    `json:"malicious"`
	Suspicious  int    `json:"suspicious"`
	Undetected  int    `json:"undetected"`
	Harmless    int    `json:"harmless"`
	Total       int    `json:"total"`
	Label       string `json:"label"`
	Err         string `json:"err,omitempty"`
	QueriedAtMs int64  `json:"queried_at_ms"`
}

type Client struct {
	vtKey       string
	mbKey       string
	minInterval time.Duration
	http        *http.Client
	mu          sync.Mutex
	lastCall    time.Time
	rateLimited bool
	disabled    bool
	lookups     int
	quotaErr    int
}

func New(vtKey, mbKey string, minInterval time.Duration) *Client {
	return &Client{
		vtKey:       strings.TrimSpace(vtKey),
		mbKey:       strings.TrimSpace(mbKey),
		minInterval: minInterval,
		http:        &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && (c.vtKey != "" || c.mbKey != "")
}

func (c *Client) Disabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disabled
}

func (c *Client) Lookups() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lookups
}

func (c *Client) throttle() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return false
	}
	if c.rateLimited {
		if time.Since(c.lastCall) < 90*time.Second {
			return false
		}
		c.rateLimited = false
	}
	if d := time.Since(c.lastCall); d < c.minInterval {
		time.Sleep(c.minInterval - d)
	}
	c.lastCall = time.Now()
	return true
}

func (c *Client) mark429() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rateLimited = true
	c.quotaErr++
	if c.quotaErr >= 3 {
		c.disabled = true
	}
}

func (c *Client) LookupHash(sha string) Result {
	if !c.Enabled() {
		return Result{Err: "no api key configured"}
	}
	if !c.throttle() {
		return Result{Err: "rate-limited"}
	}
	c.mu.Lock()
	c.lookups++
	c.mu.Unlock()
	if c.vtKey != "" {
		r := c.lookupVT(sha)
		if r.Err == "rate limited" {
			c.mark429()
			return r
		}
		if r.Found {
			return r
		}
		if r.Err == "" || r.NotFound {
			if c.mbKey != "" {
				return c.lookupMB(sha)
			}
			return r
		}
		return r
	}
	if c.mbKey != "" {
		return c.lookupMB(sha)
	}
	return Result{Provider: "virustotal", NotFound: true}
}

func (c *Client) lookupVT(sha string) Result {
	req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/files/"+sha, nil)
	if err != nil {
		return Result{Err: err.Error()}
	}
	req.Header.Set("x-apikey", c.vtKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{Provider: "virustotal", Err: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch resp.StatusCode {
	case 200:
	case 404:
		return Result{Provider: "virustotal", NotFound: true, QueriedAtMs: time.Now().UnixMilli()}
	case 429:
		return Result{Provider: "virustotal", Err: "rate limited"}
	default:
		return Result{Provider: "virustotal", Err: fmt.Sprintf("http %d", resp.StatusCode)}
	}
	r, _ := parseVT(body)
	return r
}

func parseVT(body []byte) (Result, error) {
	var doc struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
				Threat            struct {
					Label string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Result{Provider: "virustotal", Err: err.Error()}, err
	}
	st := doc.Data.Attributes.LastAnalysisStats
	r := Result{
		Provider:    "virustotal",
		Found:       true,
		Malicious:   st["malicious"],
		Suspicious:  st["suspicious"],
		Undetected:  st["undetected"],
		Harmless:    st["harmless"],
		Label:       doc.Data.Attributes.Threat.Label,
		QueriedAtMs: time.Now().UnixMilli(),
	}
	r.Total = r.Malicious + r.Suspicious + r.Undetected + r.Harmless
	return r, nil
}

func (c *Client) lookupMB(sha string) Result {
	form := "query=get_info&hash=" + sha
	req, err := http.NewRequest("POST", "https://mb-api.abuse.ch/api/v1/", bytes.NewBufferString(form))
	if err != nil {
		return Result{Provider: "malwarebazaar", Err: err.Error()}
	}
	req.Header.Set("Auth-Key", c.mbKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{Provider: "malwarebazaar", Err: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == 429 {
		return Result{Provider: "malwarebazaar", Err: "rate limited"}
	}
	var doc struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			Signature string `json:"signature"`
			Tags      []string
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Result{Provider: "malwarebazaar", Err: err.Error()}
	}
	if doc.QueryStatus != "ok" || len(doc.Data) == 0 {
		return Result{Provider: "malwarebazaar", NotFound: true, QueriedAtMs: time.Now().UnixMilli()}
	}
	r := Result{
		Provider:    "malwarebazaar",
		Found:       true,
		Malicious:   1,
		Total:       1,
		Label:       doc.Data[0].Signature,
		QueriedAtMs: time.Now().UnixMilli(),
	}
	return r
}

// IsBenignCrackOrPUALabel reports whether a VirusTotal threat label indicates
// a crack, hacktool, keygen, or PUA classification rather than a confirmed
// trojan/stealer/RAT payload.
func IsBenignCrackOrPUALabel(label string) bool {
	l := strings.ToLower(strings.TrimSpace(label))
	if l == "" {
		return false
	}
	for _, kw := range []string{
		"pua", "pup", "hacktool", "gamehack", "crack", "keygen",
		"patcher", "riskware", "not-a-virus", "grayware", "unwanted", "adware",
	} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	return false
}

// IsHighRiskFamilyLabel reports whether a VirusTotal threat label names a
// high-risk malware family or payload class (stealer, RAT, ransomware, miner).
func IsHighRiskFamilyLabel(label string) bool {
	l := strings.ToLower(strings.TrimSpace(label))
	if l == "" || IsBenignCrackOrPUALabel(l) {
		return false
	}
	for _, kw := range []string{
		"lumma", "redline", "stealc", "vidar", "raccoon", "rhadamanthys",
		"mystic", "medusa", "asyncrat", "remcos", "xworm", "njrat", "dcrat",
		"xmrig", "coinminer", "miner", "ransom", "stealer", "infostealer",
		"keylogger", "spyware", "backdoor", "clipper", "banker", "rootkit",
		"botnet", "dropper", "loader", "trojan",
	} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	// Short class names ("rat", "worm") must match as standalone tokens so words
	// like "pirate", "generator", or "migrator" never false-match "rat".
	for _, tok := range strings.FieldsFunc(l, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if tok == "rat" || tok == "worm" {
			return true
		}
	}
	return false
}

// ForceMalicious reports whether online reputation consensus is strong enough
// to independently promote a file to MALICIOUS. Calibrated for cracked-game
// environments so 3/70 AV noise on QuickSFV or TENOKE steam_api64.dll does not
// cause false MALICIOUS verdicts, while real MalwareBazaar hits and strong VT
// stealer/trojan consensus still promote immediately.
func ForceMalicious(r Result, isCrackEmu bool) bool {
	if r.Err != "" || !r.Found {
		return false
	}
	if r.Provider == "malwarebazaar" && r.Malicious >= 1 {
		return true
	}
	if IsBenignCrackOrPUALabel(r.Label) {
		// Crack/PUA labels are common on legit emulators and utilities; only
		// escalate on overwhelming multi-vendor consensus.
		if isCrackEmu {
			return r.Malicious >= 25
		}
		return r.Malicious >= 20
	}
	if IsHighRiskFamilyLabel(r.Label) {
		if isCrackEmu {
			return r.Malicious >= 10
		}
		return r.Malicious >= 6
	}
	if isCrackEmu {
		return r.Malicious >= 15
	}
	return r.Malicious >= 10
}

func ScoreDelta(r Result) int {
	if r.Err != "" || !r.Found {
		return 0
	}
	if r.Provider == "malwarebazaar" && r.Malicious >= 1 {
		return 70
	}
	n := 0
	switch {
	case r.Malicious >= 10:
		n = 60
	case r.Malicious >= 5:
		n = 35
		if IsHighRiskFamilyLabel(r.Label) {
			n = 50
		}
	case r.Malicious >= 3:
		n = 15
		if IsHighRiskFamilyLabel(r.Label) {
			n = 25
		}
	case r.Malicious >= 1:
		n = 6
	case r.Suspicious >= 2:
		n = 8
	}
	if n == 0 && (r.Harmless > 0 || r.Undetected > 0) {
		if r.Harmless+r.Undetected >= 30 {
			n = -10
		} else {
			n = -5
		}
	}
	if IsBenignCrackOrPUALabel(r.Label) && n > 10 {
		n = 10
	}
	return n
}

func Describe(r Result) string {
	if r.Err != "" {
		return ""
	}
	if !r.Found {
		return ""
	}
	if r.Provider == "malwarebazaar" {
		return "MalwareBazaar: known malware signature=" + r.Label
	}
	return fmt.Sprintf("VirusTotal: %d malicious / %d suspicious / %d clean (label: %s)", r.Malicious, r.Suspicious, r.Harmless+r.Undetected, r.Label)
}
