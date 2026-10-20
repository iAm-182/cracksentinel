package main

// Tests for the argument reordering.
//
// The reordering exists so that a folder path can be written first and the
// flags in any order. It has to know which flags take a value, and getting
// that wrong is silent: a boolean flag swallows the flag after it, and the
// value of an unrelated flag ends up in the wrong place. The set of boolean
// flags is now derived from the registered flags, and these tests pin that
// down.

import (
	"flag"
	"strings"
	"testing"
)

func testFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("out", "", "output")
	fs.String("calibration", "", "calibrator path")
	fs.Int("workers", 3, "workers")
	fs.Bool("quiet", false, "quiet")
	fs.Bool("jev", false, "adjudication")
	fs.Bool("jev-validate", true, "claim validation")
	fs.Bool("no-cache", false, "no cache")
	return fs
}

func TestBoolFlagSet(t *testing.T) {
	bools := boolFlagSet(testFlagSet())
	for _, name := range []string{"-quiet", "-jev", "-jev-validate", "-no-cache"} {
		if !bools[name] {
			t.Errorf("%s is not recognised as a boolean flag", name)
		}
	}
	for _, name := range []string{"-out", "-calibration", "-workers"} {
		if bools[name] {
			t.Errorf("%s must not be treated as a boolean flag", name)
		}
	}
}

// TestReorderArgsKeepsBoolFlagsSeparate is the regression test for the bug
// where "-jev" ate the flag after it.
func TestReorderArgsKeepsBoolFlagsSeparate(t *testing.T) {
	bools := boolFlagSet(testFlagSet())
	got := reorderArgs([]string{
		"test_data", "-jev", "-calibration", "C:\\tmp\\cal.json", "-no-cache", "-quiet",
	}, bools)
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "-jev -calibration C:\\tmp\\cal.json") {
		t.Errorf("reordered = %v, want -jev to stay separate from -calibration", got)
	}
	if !strings.Contains(joined, "-no-cache -quiet") {
		t.Errorf("reordered = %v, want the boolean flags to stay separate", got)
	}
	// The positional argument goes last so the standard flag package can
	// still find it.
	if !strings.HasSuffix(joined, "test_data") {
		t.Errorf("reordered = %v, want the path last", got)
	}
}

func TestReorderArgsValueTakingFlag(t *testing.T) {
	bools := boolFlagSet(testFlagSet())
	got := reorderArgs([]string{"-workers", "8", "folder"}, bools)
	if strings.Join(got, " ") != "-workers 8 folder" {
		t.Errorf("reordered = %v", got)
	}
}

func TestReorderArgsEqualsForm(t *testing.T) {
	bools := boolFlagSet(testFlagSet())
	// A flag written as -name=value must not swallow the next argument.
	got := reorderArgs([]string{"-quiet=true", "folder"}, bools)
	if strings.Join(got, " ") != "-quiet=true folder" {
		t.Errorf("reordered = %v", got)
	}
}
