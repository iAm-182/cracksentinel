package yara

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSplitRules checks the rule splitter on a small file.
func TestSplitRules(t *testing.T) {
	src := `import "pe"

rule alpha_one {
	meta:
		description = "a"
	strings:
		$a = "x"
	condition:
		$a
}

rule beta_two {
	condition:
		uint16(0) == 0x5A4D
}
`
	blocks := splitRules(src)
	if len(blocks) != 2 {
		t.Fatalf("splitRules returned %d blocks, want 2: %+v", len(blocks), blocks)
	}
	if blocks[0].name != "alpha_one" || blocks[1].name != "beta_two" {
		t.Errorf("names = %q, %q", blocks[0].name, blocks[1].name)
	}
	// A brace inside a string must not confuse the depth counter.
	tricky := `rule tricky {
	strings:
		$a = "{not a brace}"
	condition:
		$a
}
rule after {
	condition:
		true
}
`
	blocks = splitRules(tricky)
	if len(blocks) != 2 {
		t.Fatalf("tricky: got %d blocks, want 2: %+v", len(blocks), blocks)
	}
}

// TestCollectRulesDeduplicates checks that a rule name defined twice keeps
// the first definition.
func TestCollectRulesDeduplicates(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yar"), []byte("rule dup { condition: true }\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.yar"), []byte("rule dup { condition: false }\nrule other { condition: true }\n"), 0o644)
	blocks, err := collectRules([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d: %+v", len(blocks), blocks)
	}
	if blocks[0].name != "dup" || blocks[1].name != "other" {
		t.Errorf("names = %q, %q", blocks[0].name, blocks[1].name)
	}
}

// TestCompileWithRepairDropsBadRules checks the self-repairing compile: a
// rule the local build cannot handle is dropped and the rest still load.
//
// The rule below uses `filename`, which is not available in a stock YARA
// build: the signature-base collection relies on a patched YARA for it.
func TestCompileWithRepairDropsBadRules(t *testing.T) {
	bin := resolveBinary()
	if bin == "" {
		t.Skip("no yara binary available")
	}
	dir := t.TempDir()
	good := "rule gc_test_good { strings: $a = \"MZ\" condition: $a }\n"
	bad := "rule gc_test_bad { condition: filename == \"x\" }\n"
	os.WriteFile(filepath.Join(dir, "a.yar"), []byte(good+bad), 0o644)

	r := &Runner{bin: bin}
	blocks, err := collectRules([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "combined.yar")
	if err := r.compileWithRepair(out, blocks); err != nil {
		t.Fatalf("compileWithRepair failed: %v", err)
	}
	if r.RulesLoaded != 1 {
		t.Errorf("RulesLoaded = %d, want 1 (the good rule survives)", r.RulesLoaded)
	}
	if r.RulesDropped != 1 {
		t.Errorf("RulesDropped = %d, want 1", r.RulesDropped)
	}
	if len(r.DroppedNames) != 1 || r.DroppedNames[0] != "gc_test_bad" {
		t.Errorf("DroppedNames = %v, want [gc_test_bad]", r.DroppedNames)
	}
	// The combined file must exist and be usable.
	if _, err := os.Stat(out); err != nil {
		t.Errorf("combined file missing: %v", err)
	}
	run := exec.Command(bin, "-w", out, filepath.Join(dir, "a.yar"))
	if b, err := run.CombinedOutput(); err != nil {
		t.Errorf("the combined file does not compile: %v: %s", err, b)
	}
}
