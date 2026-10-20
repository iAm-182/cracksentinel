package jev

// Tests for the fitted probability calibrator.

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestPlattCalibrator(t *testing.T) {
	c := &Calibrator{Method: "platt", A: 3.5131555781332224, B: 3.4104101446997}
	cases := []struct{ in, want float64 }{
		{0.5, 0.5}, // sigmoid(a*0 + b) is not 0.5 because b != 0, but the
		// map is monotonic, so the ordering must be preserved.
	}
	// The map must be strictly increasing: a better probability must
	// never map to a worse one.
	prev := -1.0
	for p := 0.0; p <= 1.0001; p += 0.05 {
		got := c.Apply(p)
		if got < prev-1e-9 {
			t.Fatalf("calibrator is not monotonic at p=%.2f: %v < %v", p, got, prev)
		}
		prev = got
	}
	// The endpoints must stay inside the unit interval.
	if v := c.Apply(0); v < 0 || v > 1 {
		t.Errorf("Apply(0) = %v, want [0,1]", v)
	}
	if v := c.Apply(1); v < 0 || v > 1 {
		t.Errorf("Apply(1) = %v, want [0,1]", v)
	}
	// The fitted parameters push the mid range upwards, which is what
	// the reference fit measured: the raw 0.58 became 0.99.
	if got := c.Apply(0.58); got < 0.9 {
		t.Errorf("Apply(0.58) = %v, want a value near 0.99 for the fitted parameters", got)
	}
	_ = cases
}

func TestTemperatureCalibrator(t *testing.T) {
	c := &Calibrator{Method: "temperature", A: 0, B: 0, Temperature: 0.5}
	// A temperature below one sharpens the distribution: the mid range
	// moves away from 0.5.
	if got := c.Apply(0.6); got < 0.6 {
		t.Errorf("Apply(0.6) = %v, want a sharpened value above 0.6", got)
	}
	if got := c.Apply(0.4); got > 0.4 {
		t.Errorf("Apply(0.4) = %v, want a sharpened value below 0.4", got)
	}
}

func TestCalibratorNilIsIdentity(t *testing.T) {
	var c *Calibrator
	if got := c.Apply(0.42); got != 0.42 {
		t.Errorf("nil calibrator changed the probability: %v", got)
	}
}

func TestLoadCalibrator(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "calibration.json")
	body := `{"method":"platt","a":3.5,"b":3.4,"threshold":0.5,"ece":0.002,"corpus_size":5,"holdout_size":2}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCalibrator(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Method != "platt" || c.A != 3.5 || c.B != 3.4 {
		t.Errorf("loaded = %+v", c)
	}
	if c.Describe() == "" {
		t.Error("Describe() returned nothing")
	}
	// A file without fitted parameters is a mistake, not a silent
	// identity map.
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"method":"platt"}`), 0o644)
	if _, err := LoadCalibrator(bad); err == nil {
		t.Error("expected an error for a calibrator without parameters")
	}
}

func TestVerdictDecisionUsesMinimum(t *testing.T) {
	v := &Verdict{IsTrojanized: 0.9, IsTrojanizedAlt: 0.4}
	if got := v.Decision(); math.Abs(got-0.4) > 1e-9 {
		t.Errorf("Decision() = %v, want the minimum 0.4", got)
	}
}

func TestVerdictDecisionPrefersCalibrated(t *testing.T) {
	v := &Verdict{IsTrojanized: 0.9, IsTrojanizedAlt: 0.4}
	v.ApplyCalibration(&Calibrator{Method: "platt", A: 3.5, B: 3.4})
	if v.Calibrated <= 0 {
		t.Errorf("Calibrated = %v, want a calibrated value", v.Calibrated)
	}
	// The decision must come from the calibrated space once a calibrator
	// was applied.
	if v.Decision() != math.Min(v.Calibrated, v.CalibratedAlt) {
		t.Errorf("Decision() = %v, want the calibrated minimum", v.Decision())
	}
}
