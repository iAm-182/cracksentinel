package scan

// The semantic adjudication layer.
//
// The deterministic engine answers "does this file contain known-bad
// artefacts?" with a score. It cannot answer "is this crack carrying a
// payload?", because that is a question about MEANING, not about artefacts.
//
// A crack emulator hooks the game's API, patches the executable and ships
// unsigned DLLs. A trojanized crack does all of that AND exfiltrates
// credentials. Both produce the same import table. The only way to tell
// them apart is to judge which of the observed behaviours is explainable
// by the crack's purpose.
//
// Jev is given exactly that split and asked to weigh it. Its answer is
// recorded next to the deterministic verdict so a reviewer sees both.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gamecrack-scanner/internal/jev"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/rules"
)

// judgeBudget reserves one unit of the per-scan adjudication budget.
func (s *Scanner) judgeBudget() bool {
	s.judgeMu.Lock()
	defer s.judgeMu.Unlock()
	max := s.cfg.JudgeMaxFiles
	if max <= 0 {
		max = 8
	}
	if s.judgeUsed >= max {
		if !s.judgeWarned {
			s.judgeWarned = true
			fmt.Fprintf(os.Stderr, "warning: adjudication budget of %d file(s) reached, the rest are not assessed\n", max)
		}
		return false
	}
	s.judgeUsed++
	return true
}

// judgeFile runs the adjudication layer for one file. The result is stored
// on the FileResult; a failure is reported as a finding so the user knows
// the assessment did not happen.
func (s *Scanner) judgeFile(res *model.FileResult, strs []string) {
	c := s.cfg.Judge
	if c == nil || !c.Enabled() {
		return
	}
	if res.Score < s.cfg.JudgeMin || res.Score > s.cfg.JudgeMax {
		return
	}
	if !s.judgeBudget() {
		return
	}
	ev := buildEvidence(res, strs)

	// Bound the concurrency: the scan already runs a worker pool and each
	// adjudication is a network call.
	if s.judgeSem != nil {
		s.judgeSem <- struct{}{}
		defer func() { <-s.judgeSem }()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	v, err := c.Adjudicate(ctx, ev)
	if err != nil {
		s.warnOnce("warning: adjudication failed: " + err.Error())
		res.Findings = append(res.Findings, model.Finding{
			Rule: "judge_failed", Category: "judge", Severity: 0,
			Detail: "semantic adjudication did not complete: " + err.Error(),
		})
		return
	}

	jr := &model.JudgeResult{
		Classification: v.Classification,
		IsTrojanized:   v.IsTrojanized,
		IsMalicious:    v.IsMalicious,
		Probabilities:  v.Probabilities,
		Confidence:     v.Confidence,
		Risk:           v.Risk,
		Action:         v.Action,
		Family:         v.Family,
		Model:          v.Model,
		InputTokens:    v.InputTokens,
		OutputTokens:   v.OutputTokens,
		Summary:        v.Format(),
	}
	res.Judge = jr
	res.Findings = append(res.Findings, model.Finding{
		Rule: "judge_verdict", Category: "judge", Severity: 0,
		Detail: v.Format(),
	})

	// An override only applies when the model is confident AND the
	// deterministic evidence is not already conclusive. A confident model
	// must not be able to talk the scanner out of a confirmed payload.
	minConf := s.cfg.JudgeMinConfidence
	if minConf <= 0 {
		minConf = 0.7
	}
	if !s.cfg.JudgeOverride {
		return
	}
	if v.Confidence < minConf {
		return
	}
	if v.Prob(jev.ClassLegitimate) > 0.5 && res.Verdict == model.VerdictMalicious && res.Score < 70 {
		res.Verdict = model.VerdictSuspicious
		res.Findings = append(res.Findings, model.Finding{
			Rule: "judge_override", Category: "judge", Severity: 0,
			Detail: fmt.Sprintf("verdict downgraded to SUSPICIOUS: the adjudication judged this a legitimate crack (confidence %.0f%%)", v.Confidence*100),
		})
	}
	if v.Prob(jev.ClassUtility) > 0.5 && res.Verdict == model.VerdictMalicious {
		res.Verdict = model.VerdictSuspicious
		res.Findings = append(res.Findings, model.Finding{
			Rule: "judge_override", Category: "judge", Severity: 0,
			Detail: fmt.Sprintf("verdict downgraded to SUSPICIOUS: the adjudication judged this a legitimate utility that ships with the repack (confidence %.0f%%)", v.Confidence*100),
		})
	}
	if v.Prob(jev.ClassTrojanized) > 0.5 && res.Verdict == model.VerdictClean {
		res.Verdict = model.VerdictSuspicious
		res.Findings = append(res.Findings, model.Finding{
			Rule: "judge_override", Category: "judge", Severity: 0,
			Detail: fmt.Sprintf("verdict raised to SUSPICIOUS: the adjudication judged this a trojanized crack (confidence %.0f%%)", v.Confidence*100),
		})
	}
}

// buildEvidence splits the findings into the three buckets the model needs:
// what a crack legitimately does, what a crack never does, and what is
// uninformative. The split is the whole point — without it the model sees
// a hook import and a C2 URL side by side and calls everything malware.
func buildEvidence(res *model.FileResult, strs []string) jev.Evidence {
	ev := jev.Evidence{
		Name:      filepath.Base(res.Path),
		Type:      res.Type,
		SizeBytes: res.Size,
		Signed:    res.Signed,
		Packer:    res.Packer,
		Imphash:   res.Imphash,
		Score:     res.Score,
		Verdict:   res.Verdict.String(),
	}
	for _, f := range res.Findings {
		line := f.Rule + ": " + f.Detail
		switch rules.ClassifyRule(f.Rule) {
		case rules.RuleCrackExpected:
			ev.ExpectedForCrack = append(ev.ExpectedForCrack, line)
		case rules.RulePayload:
			ev.PayloadIndicators = append(ev.PayloadIndicators, line)
		default:
			ev.OtherFindings = append(ev.OtherFindings, line)
		}
	}
	// The crack-shaped statistics let the model reason about the shape of
	// the file rather than only about individual strings.
	profile := map[string]int{
		"total_strings":             len(strs),
		"steamapi_exports":          0,
		"payload_indicators":        len(ev.PayloadIndicators),
		"crack_expected_indicators": len(ev.ExpectedForCrack),
	}
	for _, s := range strs {
		if strings.Contains(s, "SteamAPI_") {
			profile["steamapi_exports"]++
		}
	}
	ev.EmulatorProfile = profile
	ev.Context = map[string]string{
		"file_name": filepath.Base(res.Path),
		"file_type": res.Type,
	}
	return ev
}
