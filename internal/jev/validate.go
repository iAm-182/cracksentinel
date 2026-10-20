package jev

// Claim validation — the report gate.
//
// The scanner produces findings. A finding is a CLAIM: "this file does X".
// Before a claim goes into a report, someone should ask whether the evidence
// actually supports it, because a report that overstates its evidence is
// worse than no report.
//
// The deterministic engine is a pattern matcher. It can tell that a file
// imports GetClipboardData; it cannot tell whether that import is a
// keylogger or a checksum utility that copies the result to the clipboard.
// The claim "this file contains a keylogger" may therefore be true of the
// evidence and still be wrong as a conclusion.
//
// Each claim is put to the model as its own question, with the file's
// evidence as the state. The answers are probabilities, and a claim whose
// support probability is low is flagged as WEAK: the evidence for it is
// present, but the conclusion drawn from it does not hold.
//
// The claims are independent questions in a single request, so they run in
// parallel and cost one round trip.

import (
	"context"
	"encoding/json"
	"fmt"
)

// Claim is a finding the scanner wants to report.
type Claim struct {
	Rule     string
	Category string
	Severity int
	Detail   string
}

// ClaimValidation is the model's opinion about a set of claims.
type ClaimValidation struct {
	// Support holds one probability per claim, in the same order.
	Support []float64
	// Weak holds the indices of the claims that are not defensible.
	Weak []int
	// Stable is false when the model was not stable on the evidence.
	Stable bool
}

// IsWeak reports whether claim i failed the support threshold.
func (cv *ClaimValidation) IsWeak(i int, threshold float64) bool {
	if cv == nil || i < 0 || i >= len(cv.Support) {
		return false
	}
	return cv.Support[i] < threshold
}

// WeakCount returns how many claims were not defensible.
func (cv *ClaimValidation) WeakCount() int {
	if cv == nil {
		return 0
	}
	return len(cv.Weak)
}

// ValidateClaims puts every claim to the model separately and returns the
// support probability for each. Claims whose support probability is below
// the threshold are listed in Weak.
func (c *Client) ValidateClaims(ctx context.Context, ev Evidence, claims []Claim, threshold float64) (*ClaimValidation, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("jev: no API key (set %s)", EnvKey)
	}
	if threshold <= 0 {
		threshold = 0.5
	}
	if len(claims) == 0 {
		return &ClaimValidation{Stable: true}, nil
	}

	questions := map[string]question{}
	order := make([]int, 0, len(claims))
	for i, cl := range claims {
		id := fmt.Sprintf("claim_%d", i)
		order = append(order, i)
		questions[id] = question{
			Type: "noul",
			Instructions: untrustedState + fmt.Sprintf(
				"Is the claim \"%s: %s\" supported by the evidence for this file? "+
					"Accept the claim only if the file really does what the claim says. "+
					"A behaviour that is normal for this kind of program does not support a claim of malicious intent.",
				cl.Rule, truncate(cl.Detail, 180)),
			Criteria: map[string]any{
				"true":  "The evidence shows the file does this, and it means what the claim says it means.",
				"false": "The evidence does not show this, or the behaviour is normal for this kind of program, so the claim does not hold.",
			},
		}
	}

	body, err := json.Marshal(request{State: ev, Model: c.model, Questions: questions})
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, body)
	if err != nil {
		return nil, err
	}
	cv := &ClaimValidation{Support: make([]float64, len(claims)), Stable: true}
	for i := range claims {
		id := fmt.Sprintf("claim_%d", i)
		if a, ok := resp.Answers[id]; ok {
			cv.Support[i] = a.Noul
		}
		if cv.Support[i] < threshold {
			cv.Weak = append(cv.Weak, i)
		}
	}
	// The trojanized question is asked in the same request, so the
	// stability of the model on this file is known for free.
	if a, ok := resp.Answers["is_trojanized"]; ok {
		if b, ok2 := resp.Answers["is_trojanized_alt"]; ok2 {
			cv.Stable = absf(a.Noul-b.Noul) <= StabilityThreshold
		}
	}
	return cv, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
