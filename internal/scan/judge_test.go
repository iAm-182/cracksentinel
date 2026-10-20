package scan

// Tests for the semantic adjudication layer. They run against a local mock
// endpoint, so no API key and no network access is required.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gamecrack-scanner/internal/jev"
	"gamecrack-scanner/internal/model"
)

func mockJev(t *testing.T, classification string, trojanized, malicious, confidence float64) (*httptest.Server, *[]jev.Evidence) {
	t.Helper()
	var seen []jev.Evidence
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State     jev.Evidence        `json:"state"`
			Questions map[string]struct{} `json:"questions"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, body.State)
		resp := map[string]any{
			"model": "jev-test",
			"answers": map[string]any{
				"is_trojanized": map[string]any{"type": "noul", "noul": trojanized},
				"is_malicious":  map[string]any{"type": "noul", "noul": malicious},
				"classification": map[string]any{"type": "choice", "choice": classification,
					"probabilities": map[string]float64{classification: confidence, "other": 1 - confidence},
					"confidence":    confidence},
				"risk": map[string]any{"type": "score", "score": 2.0, "legend": map[string]string{"0": "none", "1": "low", "2": "med"}},
				"action": map[string]any{"type": "choice", "choice": "review_manually",
					"probabilities": map[string]float64{"review_manually": confidence}, "confidence": confidence},
				"family": map[string]any{"type": "choice", "choice": "none",
					"probabilities": map[string]float64{"none": 1}, "confidence": 1},
			},
			"usage": map[string]int{"input_tokens": 10, "output_tokens": 5},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	return srv, &seen
}

// writeScript writes a script file with the given content.
func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestJudgeRunsInBand checks that only the ambiguous middle is adjudicated.
func TestJudgeRunsInBand(t *testing.T) {
	dir := t.TempDir()
	// A file that trips a payload rule: high score, so in band.
	writeScript(t, dir, "bad.ps1", "https://discord.com/api/webhooks/12345678901234567/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	srv, seen := mockJev(t, "trojanized", 0.95, 0.9, 0.9)
	defer srv.Close()

	s, err := New(Config{
		Root: dir, Workers: 1, MaxSizeMB: 64, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 0,
		Judge:    jev.New("k", srv.URL, "jev-test"),
		JudgeMin: 30, JudgeMax: 100, JudgeMaxFiles: 5, JudgeConcurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sum, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 {
		t.Fatalf("expected 1 adjudication, got %d", len(*seen))
	}
	r := sum.Results[0]
	if r.Judge == nil {
		t.Fatal("no judge result recorded")
	}
	if r.Judge.Classification != "trojanized" {
		t.Errorf("classification = %q", r.Judge.Classification)
	}
	var sawRule bool
	for _, f := range r.Findings {
		if f.Rule == "judge_verdict" {
			sawRule = true
		}
	}
	if !sawRule {
		t.Error("no judge_verdict finding was recorded")
	}
}

// TestJudgeSkipsOutOfBand checks the band filter.
func TestJudgeSkipsOutOfBand(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "clean.txt", "hello world")

	srv, seen := mockJev(t, "trojanized", 0.9, 0.9, 0.9)
	defer srv.Close()

	s, _ := New(Config{
		Root: dir, Workers: 1, MaxSizeMB: 64, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 0,
		Judge:    jev.New("k", srv.URL, "jev-test"),
		JudgeMin: 30, JudgeMax: 100, JudgeMaxFiles: 5,
	})
	defer s.Close()
	s.Run()
	if len(*seen) != 0 {
		t.Errorf("a clean file was adjudicated: %d calls", len(*seen))
	}
}

// TestJudgeBudget checks the per-scan cap.
func TestJudgeBudget(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		writeScript(t, dir, "bad"+string(rune('a'+i))+".ps1",
			"https://discord.com/api/webhooks/12345678901234567/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}
	srv, seen := mockJev(t, "trojanized", 0.9, 0.9, 0.9)
	defer srv.Close()

	s, _ := New(Config{
		Root: dir, Workers: 3, MaxSizeMB: 64, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 0,
		Judge:    jev.New("k", srv.URL, "jev-test"),
		JudgeMin: 30, JudgeMax: 100, JudgeMaxFiles: 2, JudgeConcurrency: 1,
	})
	defer s.Close()
	s.Run()
	if len(*seen) != 2 {
		t.Errorf("expected the budget to cap the calls at 2, got %d", len(*seen))
	}
}

// TestJudgeEvidenceBuckets is the important one: the state handed to the
// model must separate behaviour that is normal for a crack from behaviour
// that never is. Without that split the model calls every emulator a trojan.
func TestJudgeEvidenceBuckets(t *testing.T) {
	res := model.FileResult{
		Path: `C:\Games\SomeGame\steam_api64.dll`,
		Type: "pe", Score: 100, Verdict: model.VerdictMalicious,
		Findings: []model.Finding{
			{Rule: "imp_keylogger", Category: "keylogger", Severity: 30, Detail: "hooking API"},
			{Rule: "imp_injection", Category: "injection", Severity: 30, Detail: "emu hook"},
			{Rule: "crack_whitelist", Category: "info", Severity: 0, Detail: "SmartSteamEmu"},
			{Rule: "discord_webhook", Category: "c2", Severity: 40, Detail: "webhook URL"},
			{Rule: "imp_clipboard", Category: "stealer", Severity: 15, Detail: "clipboard"},
		},
	}
	ev := buildEvidence(&res, []string{"SteamAPI_Init1", "SteamAPI_Init2"})

	if len(ev.ExpectedForCrack) != 3 {
		t.Errorf("expected_for_a_crack = %v, want the 3 crack-expected rules", ev.ExpectedForCrack)
	}
	if len(ev.PayloadIndicators) != 1 {
		t.Errorf("payload_indicators = %v, want only the webhook", ev.PayloadIndicators)
	}
	if !strings.Contains(ev.PayloadIndicators[0], "discord_webhook") {
		t.Errorf("payload_indicators[0] = %q", ev.PayloadIndicators[0])
	}
	if len(ev.OtherFindings) != 1 {
		t.Errorf("other_findings = %v, want only the neutral clipboard rule", ev.OtherFindings)
	}
	if ev.EmulatorProfile["steamapi_exports"] != 2 {
		t.Errorf("steamapi_exports = %d, want 2", ev.EmulatorProfile["steamapi_exports"])
	}
	if ev.Verdict != "MALICIOUS" {
		t.Errorf("verdict = %q", ev.Verdict)
	}
}

// TestJudgeOverrideDowngrades checks the opt-in override path.
func TestJudgeOverrideDowngrades(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "emu.ps1", "https://discord.com/api/webhooks/12345678901234567/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	srv, _ := mockJev(t, "legitimate_utility", 0.05, 0.1, 0.9)
	defer srv.Close()

	s, _ := New(Config{
		Root: dir, Workers: 1, MaxSizeMB: 64, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 0,
		Judge:    jev.New("k", srv.URL, "jev-test"),
		JudgeMin: 30, JudgeMax: 100, JudgeMaxFiles: 5,
		JudgeOverride: true, JudgeMinConfidence: 0.7,
	})
	defer s.Close()
	sum, _ := s.Run()
	r := sum.Results[0]
	if r.Verdict != model.VerdictSuspicious {
		t.Errorf("verdict = %v, want SUSPICIOUS after the override", r.Verdict)
	}
}

// TestJudgeWithoutOverrideKeepsVerdict checks that the advisory default
// never changes the deterministic verdict, even when the model is confident
// and disagrees.
func TestJudgeWithoutOverrideKeepsVerdict(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "emu.ps1", "https://discord.com/api/webhooks/12345678901234567/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	srv, _ := mockJev(t, "legitimate_utility", 0.05, 0.1, 0.95)
	defer srv.Close()

	s, _ := New(Config{
		Root: dir, Workers: 1, MaxSizeMB: 64, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 0,
		Judge:    jev.New("k", srv.URL, "jev-test"),
		JudgeMin: 30, JudgeMax: 100, JudgeMaxFiles: 5,
	})
	defer s.Close()
	sum, _ := s.Run()
	r := sum.Results[0]
	if r.Judge == nil {
		t.Fatal("the judge result should still be recorded")
	}
	// The deterministic verdict is SUSPICIOUS here (the webhook alone
	// scores 40), and it must stay exactly that.
	if r.Verdict != model.VerdictSuspicious {
		t.Errorf("verdict = %v, want the deterministic SUSPICIOUS", r.Verdict)
	}
	for _, f := range r.Findings {
		if f.Rule == "judge_override" {
			t.Error("an override was applied even though the override is off")
		}
	}
}
