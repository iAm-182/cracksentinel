package cache

import (
	"path/filepath"
	"testing"

	"gamecrack-scanner/internal/model"
)

func TestCachePreservesFindingsAndCleanEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "test-cache.jsonl")
	c, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	res := model.FileResult{
		Score:           75,
		Verdict:         model.VerdictMalicious,
		Type:            "pe",
		Signer:          "FakeCo",
		SignatureStatus: "mismatch",
		Findings: []model.Finding{
			{Rule: "signature_mismatch", Category: "tampering", Severity: 40, Detail: "tampered"},
		},
	}
	c.PutFull("abc123", res, "")
	c.PutFull("clean999", model.FileResult{Score: 0, Verdict: model.VerdictClean, Type: "pe"}, "")
	c.Close()

	c2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	got, ok := c2.Get("abc123")
	if !ok {
		t.Fatal("missing cached malicious entry")
	}
	if got.Version != CurrentVersion || got.Score != 75 || len(got.Findings) != 1 || got.Findings[0].Rule != "signature_mismatch" {
		t.Errorf("cached entry lost detail: %+v", got)
	}

	gotClean, ok := c2.Get("clean999")
	if !ok || gotClean.Verdict != "CLEAN" || gotClean.Version != CurrentVersion {
		t.Errorf("clean entry not persisted cleanly: ok=%v got=%+v", ok, gotClean)
	}
}
