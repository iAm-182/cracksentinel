package jev

// Tests for the calibration harness and the claim validation gate.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// scriptedJev serves a fixed answer per case, based on the marker in the
// state, so the calibration can be exercised without a network.
func scriptedJev(t *testing.T, table map[string][2]float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State Evidence `json:"state"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		p, ok := table[body.State.Name]
		if !ok {
			p = [2]float64{0.1, 0.1}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"model": "jev-test",
			"answers": map[string]any{
				"is_trojanized":     map[string]any{"type": "noul", "noul": p[0]},
				"is_trojanized_alt": map[string]any{"type": "noul", "noul": p[1]},
				"is_malicious":      map[string]any{"type": "noul", "noul": p[0]},
				"classification": map[string]any{"type": "choice", "choice": "trojanized",
					"probabilities": map[string]float64{"trojanized": p[0]}, "confidence": 0.9},
				"risk":   map[string]any{"type": "score", "score": 1.0, "legend": map[string]string{"0": "none", "1": "low"}},
				"action": map[string]any{"type": "choice", "choice": "review_manually", "probabilities": map[string]float64{"review_manually": 1.0}, "confidence": 1.0},
				"family": map[string]any{"type": "choice", "choice": "none", "probabilities": map[string]float64{"none": 1.0}, "confidence": 1.0},
			},
			"usage": map[string]int{"input_tokens": 10, "output_tokens": 5},
		})
	}))
}

func corpusCases() []Case {
	return []Case{
		{Name: "clean.txt", Evidence: Evidence{Name: "clean.txt"}, Want: LabelLegitimate,
			DeterministicVerdict: "CLEAN", DeterministicMalicious: false},
		{Name: "emu.dll", Evidence: Evidence{Name: "emu.dll"}, Want: LabelLegitimate,
			DeterministicVerdict: "SUSPICIOUS", DeterministicMalicious: false},
		{Name: "stealer.ps1", Evidence: Evidence{Name: "stealer.ps1"}, Want: LabelMalicious,
			DeterministicVerdict: "MALICIOUS", DeterministicMalicious: true},
		{Name: "dropper.exe", Evidence: Evidence{Name: "dropper.exe"}, Want: LabelMalicious,
			DeterministicVerdict: "MALICIOUS", DeterministicMalicious: true},
	}
}

// TestCalibrateSeparatesClasses checks the confusion matrix on a clean
// separation.
func TestCalibrateSeparatesClasses(t *testing.T) {
	srv := scriptedJev(t, map[string][2]float64{
		"clean.txt":   {0.02, 0.05},
		"emu.dll":     {0.06, 0.11},
		"stealer.ps1": {0.80, 0.95},
		"dropper.exe": {0.70, 0.90},
	})
	defer srv.Close()

	c := New("k", srv.URL, "jev-test")
	cal, err := c.Calibrate(context.Background(), corpusCases(), 0.3)
	if err != nil {
		t.Fatal(err)
	}
	if cal.Total != 4 {
		t.Fatalf("Total = %d, want 4", cal.Total)
	}
	if cal.Correct != 4 {
		t.Errorf("Correct = %d, want 4 (confusion %+v)", cal.Correct, cal)
	}
	if cal.TP != 2 || cal.FP != 0 || cal.TN != 2 || cal.FN != 0 {
		t.Errorf("confusion = TP%d FP%d TN%d FN%d, want 2/0/2/0", cal.TP, cal.FP, cal.TN, cal.FN)
	}
	if cal.Precision != 1.0 || cal.Recall != 1.0 {
		t.Errorf("precision %.2f recall %.2f, want 1.00/1.00", cal.Precision, cal.Recall)
	}
	if cal.F1 != 1.0 {
		t.Errorf("F1 = %.2f, want 1.00", cal.F1)
	}
	m, ok := cal.Margin()
	if !ok {
		t.Fatal("no margin reported")
	}
	if m <= 0 {
		t.Errorf("margin = %+.2f, want a positive separation", m)
	}
}

// TestCalibrateDetectsOverlap checks that overlapping classes are reported
// as overlapping rather than hidden behind a good-looking F1.
func TestCalibrateDetectsOverlap(t *testing.T) {
	// The malicious file scores LOWER than the legitimate one: the two
	// classes overlap and no threshold can separate them.
	srv := scriptedJev(t, map[string][2]float64{
		"clean.txt":   {0.60, 0.60},
		"emu.dll":     {0.55, 0.55},
		"stealer.ps1": {0.20, 0.20},
		"dropper.exe": {0.25, 0.25},
	})
	defer srv.Close()

	c := New("k", srv.URL, "jev-test")
	cal, err := c.Calibrate(context.Background(), corpusCases(), 0.5)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := cal.Margin()
	if !ok {
		t.Fatal("no margin reported")
	}
	if m >= 0 {
		t.Errorf("margin = %+.2f, want a negative margin for overlapping classes", m)
	}
}

// TestCalibrateSweepUsesRecomputedLabels is a regression test: the
// threshold sweep used to recount a frozen label matrix, so it always
// reported the same F1 for every threshold and recommended 0.00.
func TestCalibrateSweepUsesRecomputedLabels(t *testing.T) {
	srv := scriptedJev(t, map[string][2]float64{
		"clean.txt":   {0.02, 0.05},
		"emu.dll":     {0.06, 0.11},
		"stealer.ps1": {0.45, 0.90},
		"dropper.exe": {0.80, 0.95},
	})
	defer srv.Close()

	c := New("k", srv.URL, "jev-test")
	cal, err := c.Calibrate(context.Background(), corpusCases(), 0.5)
	if err != nil {
		t.Fatal(err)
	}
	// A threshold of 0.3 separates the classes; 0.5 does not.
	if cal.BestThreshold > 0.35 {
		t.Errorf("BestThreshold = %.2f, want a threshold that separates the classes", cal.BestThreshold)
	}
	if cal.BestF1 < 0.99 {
		t.Errorf("BestF1 = %.2f, want 1.00", cal.BestF1)
	}
}

// TestValidateClaims checks the report gate: each claim is judged on its
// own and the weak ones are identified.
func TestValidateClaims(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Questions map[string]json.RawMessage `json:"questions"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		answers := map[string]any{}
		for id := range body.Questions {
			switch id {
			case "claim_0":
				answers[id] = map[string]any{"type": "noul", "noul": 0.9} // supported
			case "claim_1":
				answers[id] = map[string]any{"type": "noul", "noul": 0.1} // not supported
			default:
				answers[id] = map[string]any{"type": "noul", "noul": 0.5}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"model":   "jev-test",
			"answers": answers,
			"usage":   map[string]int{"input_tokens": 5, "output_tokens": 5},
		})
	}))
	defer srv.Close()

	c := New("k", srv.URL, "jev-test")
	claims := []Claim{
		{Rule: "discord_webhook", Category: "c2", Severity: 40, Detail: "Discord webhook URL: https://discord.com/api/webhooks/..."},
		{Rule: "imp_clipboard", Category: "stealer", Severity: 15, Detail: "clipboard access API: GetClipboardData"},
	}
	cv, err := c.ValidateClaims(context.Background(), Evidence{Name: "x.exe"}, claims, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if len(cv.Support) != 2 {
		t.Fatalf("Support = %v, want 2 entries", cv.Support)
	}
	if cv.Support[0] != 0.9 || cv.Support[1] != 0.1 {
		t.Errorf("Support = %v", cv.Support)
	}
	if cv.IsWeak(0, 0.5) {
		t.Error("the supported claim must not be weak")
	}
	if !cv.IsWeak(1, 0.5) {
		t.Error("the unsupported claim must be weak")
	}
	if cv.WeakCount() != 1 {
		t.Errorf("WeakCount = %d, want 1", cv.WeakCount())
	}
}

func TestValidateClaimsEmpty(t *testing.T) {
	c := New("k", "http://127.0.0.1:1", "jev-test")
	cv, err := c.ValidateClaims(context.Background(), Evidence{}, nil, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if cv.WeakCount() != 0 {
		t.Errorf("WeakCount = %d, want 0", cv.WeakCount())
	}
}
