package deep

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, this, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/deep/<this> -> repo root is ../../ from the package dir.
	root := filepath.Join(filepath.Dir(this), "..", "..")
	p := filepath.Join(root, rel)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture missing: %s", p)
	}
	return p
}

func TestLooksLikeGoNegative(t *testing.T) {
	if got := looksLikeGo(repoFile(t, filepath.Join("test_data", "clean_notes.txt"))); got {
		t.Errorf("clean_notes.txt must not look like Go")
	}
}

func TestLooksLikeGoSelf(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}
	if !looksLikeGo(self) {
		t.Errorf("go test binary should carry a Go build stamp: %s", self)
	}
}

func TestParseGoInfo(t *testing.T) {
	b, err := os.ReadFile(repoFile(t, filepath.Join("internal", "deep", "testdata", "gobin.json")))
	if err != nil {
		t.Fatal(err)
	}
	gi := parseGoInfo(string(b))
	if gi == nil {
		t.Fatal("parseGoInfo returned nil")
	}
	if gi.GoVersion != "go1.22.10" {
		t.Errorf("GoVersion = %q", gi.GoVersion)
	}
	if gi.ModulePath != "detwin" {
		t.Errorf("ModulePath = %q", gi.ModulePath)
	}
	if gi.Settings["GOOS"] != "windows" {
		t.Errorf("GOOS = %q", gi.Settings["GOOS"])
	}
}

func TestParseDotnetInfo(t *testing.T) {
	// Shape follows the inspect_managed_artifact summary description:
	// identity + module/MVID + counts under normalized_result.
	const fixture = `{"evidence_id":"ev_1","operation":"inspect_managed_artifact",` +
		`"normalized_result":{"identity":{"assembly":"EvilRat","version":"1.2.3.0"},` +
		`"module":{"name":"EvilRat.exe","mvid":"12345678-1234-1234-1234-1234567890ab"},` +
		`"frameworks":[".NET Framework 4.8"],"summary":"managed PE/CLI"}}`
	di := parseDotnetInfo(fixture)
	if di == nil {
		t.Fatal("parseDotnetInfo returned nil")
	}
	if di.Assembly != "EvilRat" {
		t.Errorf("Assembly = %q", di.Assembly)
	}
	if di.MVID != "12345678-1234-1234-1234-1234567890ab" {
		t.Errorf("MVID = %q", di.MVID)
	}
	if parseDotnetInfo(`not json`) != nil {
		t.Errorf("garbage input must return nil")
	}
}
