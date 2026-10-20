package jev

// A fitted probability calibrator.
//
// The raw probability the model returns is not a probability of anything.
// It is a score, and it is systematically miscalibrated: on the reference
// corpus the expected Calibrator error of the raw answer was 0.195, which
// means that when the model said "0.6" the file was malicious every single
// time, and when it said "0.06" it was clean every single time. The
// RANKING is good; the NUMBERS are not.
//
// Platt scaling fits a two-parameter map on a labelled corpus:
//
//	p' = sigmoid(a * logit(p) + b)
//
// and the fitted parameters are then applied to every future probability.
// The point of the fit/holdout discipline is that a and b are chosen on one
// set of labelled cases and scored on another, so the improvement is a
// measurement and not a fit to the same data it is evaluated on.
//
// The parameters are produced by JevLab (or any equivalent fit) and loaded
// at runtime with -jev-Calibrator.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
)

// Calibrator is a fitted calibrator plus the decision threshold that goes
// with it.
type Calibrator struct {
	// Method names the Calibrator: "platt", "temperature" or "none".
	Method string `json:"method"`
	// A and B are the fitted parameters.
	A float64 `json:"a"`
	B float64 `json:"b"`
	// Temperature is the fitted temperature for the temperature method.
	Temperature float64 `json:"temperature,omitempty"`
	// Threshold is the decision threshold in CALIBRATED probability space.
	Threshold float64 `json:"threshold"`
	// Metrics recorded at fit time, for the record.
	ECE   float64 `json:"ece,omitempty"`
	MCE   float64 `json:"mce,omitempty"`
	Brier float64 `json:"brier,omitempty"`
	// Margin is the class separation measured on the fit corpus.
	Margin float64 `json:"margin,omitempty"`
	// CorpusSize is the number of labelled cases the fit used.
	CorpusSize int `json:"corpus_size,omitempty"`
	// HoldoutSize is the number of cases the fit was scored on.
	HoldoutSize int `json:"holdout_size,omitempty"`
	// FittedAt records when the parameters were produced.
	FittedAt string `json:"fitted_at,omitempty"`
}

// LoadCalibrator reads a fitted calibrator from a JSON file.
func LoadCalibrator(path string) (*Calibrator, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Calibrator
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("jev: parse Calibrator %s: %w", path, err)
	}
	if c.Method == "" {
		c.Method = "platt"
	}
	if c.Method == "platt" && c.A == 0 && c.B == 0 {
		return nil, fmt.Errorf("jev: Calibrator %s has no fitted parameters", path)
	}
	return &c, nil
}

// Apply maps a raw probability to a calibrated one.
func (c *Calibrator) Apply(p float64) float64 {
	if c == nil {
		return p
	}
	switch c.Method {
	case "platt":
		return sigmoid(c.A*logit(p) + c.B)
	case "temperature":
		t := c.Temperature
		if t <= 0 {
			t = 1
		}
		return sigmoid(logit(p) / t)
	}
	return p
}

// Describe renders the calibrator for the console.
func (c *Calibrator) Describe() string {
	if c == nil {
		return "jev: no calibrator (raw probabilities)"
	}
	return fmt.Sprintf("jev: %s calibrator (a=%.3f b=%.3f), threshold %.2f, ECE %.3f, Brier %.3f, corpus %d/%d",
		c.Method, c.A, c.B, c.Threshold, c.ECE, c.Brier, c.CorpusSize, c.HoldoutSize)
}

func logit(p float64) float64 {
	// Clip away from 0 and 1 so the logit stays finite.
	const eps = 1e-6
	if p < eps {
		p = eps
	}
	if p > 1-eps {
		p = 1 - eps
	}
	return math.Log(p / (1 - p))
}

func sigmoid(x float64) float64 {
	// Numerically stable logistic function.
	if x >= 0 {
		return 1 / (1 + math.Exp(-x))
	}
	e := math.Exp(x)
	return e / (1 + e)
}
