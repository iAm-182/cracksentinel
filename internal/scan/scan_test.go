package scan

// Unit tests for the scoring policy and the container expansion.
//
// The scoring policy is the highest-risk piece of logic in the project: it
// decides whether a user's game folder is reported as MALICIOUS. A silent
// regression here either scares people off (false positives) or defeats the
// whole product (false negatives), so the boundaries are pinned down here.

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gamecrack-scanner/internal/model"
)

func f(rule string, sev int) model.Finding {
	return model.Finding{Rule: rule, Category: "test", Severity: sev, Detail: rule}
}

// TestComputeScoreBoundaries pins the verdict thresholds.
func TestComputeScoreBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		sev     int
		score   int
		verdict model.Verdict
	}{
		{"nothing at all", 0, 0, model.VerdictClean},
		{"one point below suspicious", 29, 29, model.VerdictClean},
		{"exactly suspicious", 30, 30, model.VerdictSuspicious},
		{"one below malicious", 69, 69, model.VerdictSuspicious},
		{"exactly malicious", 70, 70, model.VerdictMalicious},
		{"capped at 100", 250, 100, model.VerdictMalicious},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := []model.Finding{}
			if c.sev > 0 {
				findings = append(findings, f("x", c.sev))
			}
			score, verdict, _ := computeScore(findings, nil)
			if score != c.score {
				t.Errorf("score = %d, want %d", score, c.score)
			}
			if verdict != c.verdict {
				t.Errorf("verdict = %v, want %v", verdict, c.verdict)
			}
		})
	}
}

// TestComputeScoreWhitelistDiscount checks the crack whitelist penalty.
func TestComputeScoreWhitelistDiscount(t *testing.T) {
	cases := []struct {
		name      string
		sev       int
		whitelist []string
		want      int
	}{
		{"whitelist discounts a low score", 30, []string{"RUNE"}, 15},
		{"whitelist discounts a mid score", 50, []string{"Goldberg"}, 35},
		{"whitelist does not rescue a high score", 70, []string{"RUNE"}, 70},
		{"whitelist never pushes below zero", 5, []string{"RUNE"}, 0},
		{"no whitelist means no discount", 30, nil, 30},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, _, _ := computeScore([]model.Finding{f("x", c.sev)}, c.whitelist)
			if score != c.want {
				t.Errorf("score = %d, want %d", score, c.want)
			}
		})
	}
}

// TestComputeScoreEmuCap checks that a Steam-emulator-like DLL can never
// auto-escalate to MALICIOUS.
func TestComputeScoreEmuCap(t *testing.T) {
	score, verdict, extra := computeScore([]model.Finding{f("x", 100)}, []string{"EMU_STEAMAPI"})
	if score != 59 {
		t.Errorf("emu cap: score = %d, want 59", score)
	}
	if verdict != model.VerdictSuspicious {
		t.Errorf("emu cap: verdict = %v, want SUSPICIOUS", verdict)
	}
	if len(extra) != 1 || extra[0].Rule != "emu_steamapi" {
		t.Errorf("emu cap: expected one emu_steamapi note, got %v", extra)
	}
}

// TestComputeScoreEmuCapKeepsVerdict checks that the emu cap never lets a
// Steam-emulator-like DLL reach MALICIOUS, and documents the interaction
// between the two whitelist policies: the generic -15 discount applies
// first (EMU_STEAMAPI is a whitelist entry), the 59 cap second.
func TestComputeScoreEmuCapKeepsVerdict(t *testing.T) {
	score, verdict, _ := computeScore([]model.Finding{f("x", 10)}, []string{"EMU_STEAMAPI"})
	if score != 0 {
		t.Errorf("score = %d, want 0 (10 - 15 whitelist discount)", score)
	}
	if verdict != model.VerdictClean {
		t.Errorf("verdict = %v, want CLEAN", verdict)
	}
	// A heavily-flagged emu DLL is capped, not escalated.
	score, verdict, _ = computeScore([]model.Finding{f("x", 100)}, []string{"EMU_STEAMAPI"})
	if score != 59 {
		t.Errorf("score = %d, want 59 (emu cap)", score)
	}
	if verdict != model.VerdictSuspicious {
		t.Errorf("verdict = %v, want SUSPICIOUS (never MALICIOUS for an emu DLL)", verdict)
	}
}

// webhook returns a syntactically valid Discord webhook URL.
func webhook() string {
	return "https://discord.com/api/webhooks/12345678901234567/" + strings.Repeat("aB3-_", 15)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestScanNestedContainer is the regression test for the nested-archive
// defect: a payload at "setup/bin/payload.txt" inside a container was
// invisible because only the archive's top level was walked.
func TestScanNestedContainer(t *testing.T) {
	dir := t.TempDir()
	arc := filepath.Join(dir, "repack.zip")

	f, err := os.Create(arc)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	entry, err := zw.Create("setup/bin/payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	entry.Write([]byte("MZ fake payload " + webhook()))
	zw.Close()
	f.Close()

	s, err := New(Config{
		Root: dir, Workers: 1, MaxSizeMB: 64, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 2, ExtractMaxMB: 64,
		TempDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sum, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(sum.Results))
	}
	r := sum.Results[0]
	if r.Verdict == model.VerdictClean {
		t.Fatalf("nested payload was not detected: score=%d findings=%v", r.Score, r.Findings)
	}
	var sawNested bool
	for _, fd := range r.Findings {
		if fd.Rule == "nested_result" && strings.Contains(fd.Detail, "setup/bin/payload.txt") {
			sawNested = true
		}
	}
	if !sawNested {
		t.Errorf("expected a nested_result finding naming the inner path, got %v", r.Findings)
	}
}

// TestScanZipTopLevel checks the ordinary (non-nested) container path.
func TestScanZipTopLevel(t *testing.T) {
	dir := t.TempDir()
	arc := filepath.Join(dir, "flat.zip")
	f, err := os.Create(arc)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	e, _ := zw.Create("payload.txt")
	e.Write([]byte(webhook()))
	zw.Close()
	f.Close()

	s, _ := New(Config{
		Root: dir, Workers: 1, MaxSizeMB: 64, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 2, ExtractMaxMB: 64,
		TempDir: dir,
	})
	defer s.Close()
	sum, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if sum.Results[0].Verdict == model.VerdictClean {
		t.Fatalf("top-level payload not detected: %v", sum.Results[0].Findings)
	}
}

// TestScanSingleFile checks that ScanFiles only touches the given file.
func TestScanSingleFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "clean.txt")
	bad := filepath.Join(dir, "bad.txt")
	writeFile(t, good, "hello world")
	writeFile(t, bad, webhook())

	s, _ := New(Config{
		Root: dir, Workers: 1, MaxSizeMB: 64, SkipAssets: true,
		UseCache: false, FullReadMB: 32, ExtractDepth: 0,
	})
	defer s.Close()
	sum, err := s.ScanFiles([]string{bad})
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Results) != 1 {
		t.Fatalf("expected exactly 1 result, got %d", len(sum.Results))
	}
	if sum.Results[0].Path != bad {
		t.Errorf("scanned %s, want %s", sum.Results[0].Path, bad)
	}
	if sum.Results[0].Verdict == model.VerdictClean {
		t.Error("webhook file should not be CLEAN")
	}
}

// TestSkipFile checks the file-selection policy.
func TestSkipFile(t *testing.T) {
	dir := t.TempDir()
	asset := filepath.Join(dir, "data.pak")
	script := filepath.Join(dir, "a.ps1")
	other := filepath.Join(dir, "a.exe")
	writeFile(t, asset, "x")
	writeFile(t, script, "x")
	writeFile(t, other, "x")

	s, _ := New(Config{
		Root: dir, Workers: 1, MaxSizeMB: 64, SkipAssets: true,
		Excludes: []string{".exe"}, UseCache: false, ExtractDepth: 0,
	})
	defer s.Close()

	if !s.skipFile(asset) {
		t.Error("game asset should be skipped")
	}
	if s.skipFile(script) {
		t.Error("script should not be skipped")
	}
	if !s.skipFile(other) {
		t.Error("excluded extension should be skipped")
	}
}

// TestWantExt checks the container include set.
func TestWantExt(t *testing.T) {
	cases := map[string]bool{
		"setup.exe":    true,
		"a/b/c.dll":    true,
		"readme.txt":   true,
		"data.pak":     false,
		"movie.mp4":    false,
		"noext":        false,
		"script.BAT":   true,
		"archive.7z":   false,
		"thing.unknow": false,
	}
	for name, want := range cases {
		if got := wantExt(name); got != want {
			t.Errorf("wantExt(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestIncludeFiltersAreRecursive is a regression test for the 7-Zip
// "-i!" behaviour: without the "r" flag 7-Zip only processes the archive's
// top level, so nested payloads are never extracted.
func TestIncludeFiltersAreRecursive(t *testing.T) {
	filters := includeFilters()
	if len(filters) != len(extractableExts) {
		t.Fatalf("expected %d filters, got %d", len(extractableExts), len(filters))
	}
	for _, f := range filters {
		if !strings.HasPrefix(f, "-ir!") {
			t.Errorf("filter %q is missing the recursive flag (want -ir!*.ext)", f)
		}
	}
}

// TestPlanZip checks the pre-extraction size projection.
func TestPlanZip(t *testing.T) {
	dir := t.TempDir()
	arc := filepath.Join(dir, "plan.zip")
	f, _ := os.Create(arc)
	zw := zip.NewWriter(f)
	e, _ := zw.Create("a.exe")
	e.Write([]byte(strings.Repeat("A", 1000)))
	e2, _ := zw.Create("b.pak")
	e2.Write([]byte(strings.Repeat("B", 5000)))
	zw.Close()
	f.Close()

	s, _ := New(Config{Root: dir, Workers: 1, MaxSizeMB: 64, ExtractDepth: 2, ExtractMaxMB: 64})
	defer s.Close()

	entries, total, ok := s.planArchive(arc)
	if !ok {
		t.Fatal("planArchive failed")
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 extractable entry (.pak is filtered), got %d: %v", len(entries), entries)
	}
	if total != 1000 {
		t.Errorf("projected size = %d, want 1000", total)
	}
}
