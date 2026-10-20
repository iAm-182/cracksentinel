package jev

// Calibration harness.
//
// Thresholds picked by intuition are not thresholds. The adjudicator's
// precision and false-positive rate can only be known by running it over
// files whose true nature is known.
//
// The harness takes a labelled corpus, runs the adjudicator over it, and
// reports the confusion matrix, precision, recall, F1, the threshold that
// maximises F1 on this corpus, and every case where the adjudicator
// disagrees with the deterministic engine — the disagreements are the
// interesting part, because they are the cases a human has to look at.
//
// The corpus grows over time: every real crack folder that gets triaged
// adds its files with a label, and the next run measures the tool against
// the user's own data rather than against a guess.

import (
	"context"
	"fmt"
	"math"
	"sort"
)

// Label is the ground truth for a calibration case.
type Label int

const (
	// LabelMalicious means the file carries a payload.
	LabelMalicious Label = iota
	// LabelLegitimate means the file is a clean crack or a utility.
	LabelLegitimate
)

func (l Label) String() string {
	if l == LabelMalicious {
		return "malicious"
	}
	return "legitimate"
}

// Case is one labelled sample.
type Case struct {
	// Name identifies the sample.
	Name string
	// Evidence is the state handed to the model.
	Evidence Evidence
	// Want is the ground truth.
	Want Label
	// Note explains why the label was assigned.
	Note string
	// Split is "fit" or "holdout". The calibrators are fitted on the fit
	// split and scored on the holdout split. Putting a case, its
	// variants and its near duplicates in the same split is what keeps
	// the evaluation honest.
	Split string
	// DeterministicVerdict is the scanner's own verdict, when known. It
	// is used to measure how often the two layers disagree.
	DeterministicVerdict string
	// DeterministicMalicious is the scanner's own conclusion, when known.
	DeterministicMalicious bool
}

// Split names for the fit/holdout discipline.
const (
	SplitFit     = "fit"
	SplitHoldout = "holdout"
)

// CaseResult is the outcome for one case.
type CaseResult struct {
	Case
	// Verdict is the model's answer.
	Verdict *Verdict
	// Got is the label the model implied at the evaluated threshold.
	Got Label
	// Correct is whether Got matched Want.
	Correct bool
	// AgreesWithDeterministic reports whether the model and the
	// deterministic engine concluded the same thing.
	AgreesWithDeterministic bool
	// HasDeterministic records that a deterministic verdict was known.
	HasDeterministic bool
}

// Calibration is the measured behaviour of the adjudicator on a corpus.
type Calibration struct {
	// Threshold is the probability threshold the results were evaluated at.
	Threshold float64
	// Total and Correct are the raw counts.
	Total   int
	Correct int
	// TP, FP, TN, FN are the confusion matrix, from the point of view of
	// "malicious".
	TP, FP, TN, FN int
	// Accuracy, Precision, Recall and F1 are derived from the matrix.
	Accuracy  float64
	Precision float64
	Recall    float64
	F1        float64
	// BestThreshold is the threshold that maximised F1 on this corpus.
	BestThreshold float64
	// BestF1 is the F1 at BestThreshold.
	BestF1 float64
	// Margin is the gap between the highest legitimate probability and the
	// lowest malicious one. A positive margin means the classes are
	// separated; a negative one means no threshold can separate them.
	Margin float64
	// HasMargin records whether a margin could be computed.
	HasMargin bool
	// FitCases and HoldoutCases are the counts per split.
	FitCases     int
	HoldoutCases int
	// Results holds every case outcome.
	Results []CaseResult
	// Disagreements holds the cases where the model and the deterministic
	// engine concluded differently.
	Disagreements []CaseResult
	// Unstable holds the cases where the two framings of the question
	// disagreed by more than the stability threshold.
	Unstable []CaseResult
}

// AssignSplits puts the cases into the fit and holdout splits, stratified
// by class so both splits keep the same class balance.
//
// A corpus that does not declare its own split gets a deterministic
// stratified assignment: every third case of each class goes to the
// holdout. The split is stable across runs, so a measurement can be
// repeated.
//
// The holdout exists so the threshold is chosen on one set of cases and
// scored on another. Choosing a threshold and evaluating it on the same
// cases is how a tool convinces itself it works.
func AssignSplits(cases []Case, holdoutEvery int) []Case {
	if holdoutEvery <= 0 {
		holdoutEvery = 3
	}
	out := make([]Case, len(cases))
	copy(out, cases)
	perClass := map[Label]int{}
	for i := range out {
		if out[i].Split == SplitFit || out[i].Split == SplitHoldout {
			continue
		}
		perClass[out[i].Want]++
		if perClass[out[i].Want]%holdoutEvery == 0 {
			out[i].Split = SplitHoldout
		} else {
			out[i].Split = SplitFit
		}
	}
	// Both splits must be non-empty for a calibration to mean anything.
	hasFit, hasHold := false, false
	for _, c := range out {
		if c.Split == SplitHoldout {
			hasHold = true
		} else {
			hasFit = true
		}
	}
	if !hasFit || !hasHold {
		for i := range out {
			if i%2 == 0 {
				out[i].Split = SplitFit
			} else {
				out[i].Split = SplitHoldout
			}
		}
	}
	return out
}

// Calibrate runs the adjudicator over a labelled corpus and measures it.
func (c *Client) Calibrate(ctx context.Context, cases []Case, threshold float64) (*Calibration, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("jev: no API key (set %s)", EnvKey)
	}
	cal := &Calibration{Threshold: threshold}
	for _, cs := range cases {
		v, err := c.Adjudicate(ctx, cs.Evidence)
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", cs.Name, err)
		}
		r := CaseResult{Case: cs, Verdict: v}
		r.Got = labelFor(v, threshold)
		r.Correct = r.Got == cs.Want
		if cs.DeterministicVerdict != "" {
			r.HasDeterministic = true
			r.AgreesWithDeterministic = (cs.DeterministicMalicious == (r.Got == LabelMalicious))
		}
		cal.Results = append(cal.Results, r)
		if !v.Agree(threshold) {
			cal.Unstable = append(cal.Unstable, r)
		}
		if r.HasDeterministic && !r.AgreesWithDeterministic {
			cal.Disagreements = append(cal.Disagreements, r)
		}
	}
	cal.score(threshold)
	cal.BestThreshold, cal.BestF1 = cal.bestThreshold()
	cal.Margin, cal.HasMargin = cal.ComputeMargin()
	for _, r := range cal.Results {
		if r.Split == SplitHoldout {
			cal.HoldoutCases++
		} else {
			cal.FitCases++
		}
	}
	return cal, nil
}

// labelFor maps a verdict to a label at a probability threshold.
//
// The two framings are combined with the MINIMUM, not the average. Calling
// a file malicious is an accusation, and an accusation has to survive both
// framings: if either one doubts it, the file is not called malicious. The
// average would let a confident framing carry a doubtful one, which is how
// a legitimate utility ends up on a delete list.
func labelFor(v *Verdict, threshold float64) Label {
	if v == nil {
		return LabelLegitimate
	}
	if v.Decision() >= threshold {
		return LabelMalicious
	}
	return LabelLegitimate
}

// score recomputes the labels at a threshold and derives the confusion
// matrix from them. The labels are recomputed here rather than reused from
// the case results: a threshold sweep that only recounts a frozen label
// matrix measures nothing.
func (cal *Calibration) score(threshold float64) {
	cal.Total = len(cal.Results)
	cal.Correct = 0
	cal.TP, cal.FP, cal.TN, cal.FN = 0, 0, 0, 0
	for i := range cal.Results {
		r := &cal.Results[i]
		r.Got = labelFor(r.Verdict, threshold)
		r.Correct = r.Got == r.Want
		if r.Correct {
			cal.Correct++
		}
		switch {
		case r.Want == LabelMalicious && r.Got == LabelMalicious:
			cal.TP++
		case r.Want == LabelLegitimate && r.Got == LabelMalicious:
			cal.FP++
		case r.Want == LabelLegitimate && r.Got == LabelLegitimate:
			cal.TN++
		default:
			cal.FN++
		}
	}
	if cal.Total > 0 {
		cal.Accuracy = float64(cal.Correct) / float64(cal.Total)
	}
	// Precision = TP / (TP + FP): of the files called malicious, how many
	// really are. Recall = TP / (TP + FN): of the files that really are
	// malicious, how many were caught.
	if d := cal.TP + cal.FP; d > 0 {
		cal.Precision = float64(cal.TP) / float64(d)
	}
	if d := cal.TP + cal.FN; d > 0 {
		cal.Recall = float64(cal.TP) / float64(d)
	}
	if cal.Precision+cal.Recall > 0 {
		cal.F1 = 2 * cal.Precision * cal.Recall / (cal.Precision + cal.Recall)
	}
}

// bestThreshold sweeps the threshold and returns the one with the best F1.
//
// When a range of thresholds achieves the same F1 — which is the normal
// case on a well-separated corpus — the MIDDLE of that range is returned,
// not the first one. The first threshold of the range sits right on the
// edge of the cluster, where a single new case would break it.
func (cal *Calibration) bestThreshold() (float64, float64) {
	bestF := -1.0
	var optimal []float64
	for i := 0; i <= 100; i++ {
		t := float64(i) / 100
		cal.score(t)
		if cal.F1 > bestF+1e-9 {
			bestF = cal.F1
			optimal = optimal[:0]
			optimal = append(optimal, t)
		} else if cal.F1 > bestF-1e-9 {
			optimal = append(optimal, t)
		}
	}
	bestT := 0.5
	if len(optimal) > 0 {
		bestT = optimal[0]
		if len(optimal) > 1 {
			bestT = (optimal[0] + optimal[len(optimal)-1]) / 2
		}
	}
	// Restore the scores for the threshold the caller asked for.
	cal.score(cal.Threshold)
	return bestT, bestF
}

// Margin is the gap between the highest legitimate probability and the
// lowest malicious one. A positive margin means the two classes are
// separated and a threshold between them is safe; a negative margin means
// the adjudicator cannot separate them on this corpus, whatever the F1
// says.
func (cal *Calibration) ComputeMargin() (float64, bool) {
	lowestMal := 1.0
	highestLegit := 0.0
	haveMal, haveLegit := false, false
	for _, r := range cal.Results {
		if r.Verdict == nil {
			continue
		}
		p := math.Min(r.Verdict.IsTrojanized, r.Verdict.IsTrojanizedAlt)
		if r.Want == LabelMalicious {
			if p < lowestMal {
				lowestMal = p
			}
			haveMal = true
		} else {
			if p > highestLegit {
				highestLegit = p
			}
			haveLegit = true
		}
	}
	if !haveMal || !haveLegit {
		return 0, false
	}
	return lowestMal - highestLegit, true
}

// Summary renders the calibration as a readable report.
func (cal *Calibration) Summary() string {
	var s []string
	s = append(s, "Adjudicator calibration")
	s = append(s, fmt.Sprintf("corpus          : %d case(s), %d correct (%.0f%%)", cal.Total, cal.Correct, cal.Accuracy*100))
	s = append(s, fmt.Sprintf("threshold       : %.2f  (best on this corpus: %.2f -> F1 %.2f)", cal.Threshold, cal.BestThreshold, cal.BestF1))
	if m, ok := cal.ComputeMargin(); ok {
		note := "classes are separated"
		if m < 0 {
			note = "CLASSES OVERLAP: the adjudicator cannot separate them on this corpus"
		}
		s = append(s, fmt.Sprintf("margin          : %+.2f (%s)", m, note))
	}
	s = append(s, fmt.Sprintf("splits          : %d fit / %d holdout", cal.FitCases, cal.HoldoutCases))
	s = append(s, fmt.Sprintf("confusion       : TP=%d FP=%d TN=%d FN=%d", cal.TP, cal.FP, cal.TN, cal.FN))
	s = append(s, fmt.Sprintf("precision       : %.2f", cal.Precision))
	s = append(s, fmt.Sprintf("recall          : %.2f", cal.Recall))
	s = append(s, fmt.Sprintf("F1              : %.2f", cal.F1))
	if len(cal.Disagreements) > 0 {
		s = append(s, fmt.Sprintf("disagreements   : %d case(s) where the model and the scanner differ", len(cal.Disagreements)))
		for _, d := range cal.Disagreements {
			s = append(s, fmt.Sprintf("  - %-28s scanner=%-10s model=%-10s (p=%.2f) %s",
				d.Name, d.DeterministicVerdict, d.Got, d.Verdict.IsTrojanized, d.Note))
		}
	}
	if len(cal.Unstable) > 0 {
		s = append(s, fmt.Sprintf("unstable        : %d case(s) where the two framings of the question disagreed", len(cal.Unstable)))
		for _, u := range cal.Unstable {
			s = append(s, fmt.Sprintf("  - %-28s p1=%.2f p2=%.2f spread=%.2f", u.Name, u.Verdict.IsTrojanized, u.Verdict.IsTrojanizedAlt, u.Verdict.Spread))
		}
	}
	s = append(s, "")
	s = append(s, "per case:")
	for _, r := range cal.Results {
		mark := "ok "
		if !r.Correct {
			mark = "MISS"
		}
		s = append(s, fmt.Sprintf("  %s %-28s want=%-10s got=%-10s p=%.2f (alt %.2f) %s",
			mark, r.Name, r.Want, r.Got, r.Verdict.IsTrojanized, r.Verdict.IsTrojanizedAlt, r.Note))
	}
	return joinLines(s)
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}

// SortResultsByName is a small helper for stable reporting.
func SortResultsByName(res []CaseResult) {
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
}
