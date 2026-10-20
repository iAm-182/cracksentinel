package jev

// Tests for the System One client. They run against a local httptest server,
// so no API key and no network access is required.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sampleEvidence() Evidence {
	return Evidence{
		Name:    "steam_api64.dll",
		Type:    "pe",
		Signed:  false,
		Score:   100,
		Verdict: "MALICIOUS",
		ExpectedForCrack: []string{
			"imp_keylogger: hooking imports are how an emulator redirects Steam API calls",
		},
		PayloadIndicators: []string{
			"discord_webhook: https://discord.com/api/webhooks/...",
		},
		EmulatorProfile: map[string]int{"steamapi_exports": 1212, "total_strings": 4312},
	}
}

func okResponse() string {
	return `{
	  "model": "jev-1.13.0",
	  "answers": {
	    "is_trojanized": {"type": "noul", "noul": 0.91},
	    "is_malicious": {"type": "noul", "noul": 0.88},
	    "classification": {"type": "choice", "choice": "trojanized",
	      "probabilities": {"legitimate_crack": 0.06, "trojanized": 0.91, "unknown": 0.03},
	      "confidence": 0.87},
	    "risk": {"type": "score", "score": 3.2,
	      "legend": {"0": "no risk", "1": "low risk", "2": "medium risk", "3": "high risk", "4": "critical risk"},
	      "probabilities": {"0": 0.0, "1": 0.0, "2": 0.05, "3": 0.7, "4": 0.25}},
	    "action": {"type": "choice", "choice": "delete",
	      "probabilities": {"safe_to_keep": 0.02, "review_manually": 0.1, "quarantine": 0.15, "delete": 0.73},
	      "confidence": 0.8},
	    "family": {"type": "choice", "choice": "stealer",
	      "probabilities": {"none": 0.1, "stealer": 0.8}, "confidence": 0.75}
	  },
	  "usage": {"input_tokens": 812, "output_tokens": 96}
	}`
}

func TestAdjudicateParsesAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(okResponse()))
	}))
	defer srv.Close()

	c := New("test-key", srv.URL, "jev-latest")
	v, err := c.Adjudicate(context.Background(), sampleEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if v.IsTrojanized != 0.91 {
		t.Errorf("IsTrojanized = %v, want 0.91", v.IsTrojanized)
	}
	if v.IsMalicious != 0.88 {
		t.Errorf("IsMalicious = %v, want 0.88", v.IsMalicious)
	}
	if v.Classification != "trojanized" {
		t.Errorf("Classification = %q", v.Classification)
	}
	if v.Confidence != 0.87 {
		t.Errorf("Confidence = %v, want 0.87", v.Confidence)
	}
	if v.Risk != 3.2 {
		t.Errorf("Risk = %v, want 3.2", v.Risk)
	}
	if v.Action != "delete" {
		t.Errorf("Action = %q", v.Action)
	}
	if v.Family != "stealer" {
		t.Errorf("Family = %q", v.Family)
	}
	if v.InputTokens != 812 || v.OutputTokens != 96 {
		t.Errorf("usage = %d/%d", v.InputTokens, v.OutputTokens)
	}
	if v.Prob(ClassLegitimate) != 0.06 {
		t.Errorf("Prob(legitimate) = %v", v.Prob(ClassLegitimate))
	}
	if !strings.Contains(v.Format(), "trojanized") {
		t.Errorf("Format() = %q", v.Format())
	}
}

// TestRequestShape pins the wire contract: the model id, the question types
// and the separation of expected-for-a-crack from payload indicators.
func TestRequestShape(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("auth header = %q", got)
		}
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(okResponse()))
	}))
	defer srv.Close()

	c := New("test-key", srv.URL, "")
	c.Adjudicate(context.Background(), sampleEvidence())

	if body["model"] != "jev-latest" {
		t.Errorf("model = %v", body["model"])
	}
	qs, _ := body["questions"].(map[string]any)
	if len(qs) != 6 {
		t.Errorf("expected 6 questions, got %d: %v", len(qs), qs)
	}
	wantTypes := map[string]string{
		"is_trojanized":  "noul",
		"is_malicious":   "noul",
		"classification": "choice",
		"risk":           "score",
		"action":         "choice",
		"family":         "choice",
	}
	for id, wantType := range wantTypes {
		q, ok := qs[id].(map[string]any)
		if !ok {
			t.Errorf("question %q missing", id)
			continue
		}
		if q["type"] != wantType {
			t.Errorf("question %q type = %v, want %q", id, q["type"], wantType)
		}
		if q["instructions"] == nil || q["instructions"] == "" {
			t.Errorf("question %q has no instructions", id)
		}
	}
	// A score question must carry its levels as an ordered criteria array.
	risk, _ := qs["risk"].(map[string]any)
	if levels, _ := risk["criteria"].([]any); len(levels) < 2 {
		t.Errorf("risk question has no criteria levels: %v", risk)
	}
	// The state must carry the two evidence classes separately.
	state, _ := body["state"].(map[string]any)
	if _, ok := state["expected_for_a_crack"]; !ok {
		t.Error("state is missing expected_for_a_crack")
	}
	if _, ok := state["payload_indicators"]; !ok {
		t.Error("state is missing payload_indicators")
	}
}

// TestRetriesOnRateLimit checks the backoff path.
func TestRetriesOnRateLimit(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"slow down"}`))
			return
		}
		w.Write([]byte(okResponse()))
	}))
	defer srv.Close()

	c := New("test-key", srv.URL, "jev-latest")
	c.retries = 3
	v, err := c.Adjudicate(context.Background(), sampleEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if v.Classification != "trojanized" {
		t.Errorf("classification = %q", v.Classification)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Errorf("calls = %d, want 2 (one 429 then one success)", calls)
	}
}

// TestDoesNotRetryOnUnauthorized checks that a request error is not retried.
func TestDoesNotRetryOnUnauthorized(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"bad key"}`))
	}))
	defer srv.Close()

	c := New("test-key", srv.URL, "jev-latest")
	c.retries = 3
	if _, err := c.Adjudicate(context.Background(), sampleEvidence()); err == nil {
		t.Fatal("expected an error for 401")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("calls = %d, want 1 (no retry on 401)", calls)
	}
}

func TestDisabledWithoutKey(t *testing.T) {
	c := New("", "http://127.0.0.1:1", "jev-latest")
	c.apiKey = "" // ignore the environment for this test
	if c.Enabled() {
		t.Fatal("client without a key must not be enabled")
	}
	if _, err := c.Adjudicate(context.Background(), sampleEvidence()); err == nil {
		t.Fatal("expected an error from a disabled client")
	}
}

func TestTimeoutIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Write([]byte(okResponse()))
	}))
	defer srv.Close()

	c := New("test-key", srv.URL, "jev-latest")
	c.http.Timeout = 200 * time.Millisecond
	c.retries = 0
	if _, err := c.Adjudicate(context.Background(), sampleEvidence()); err == nil {
		t.Fatal("expected a timeout error")
	}
}
