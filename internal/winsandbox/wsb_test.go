package winsandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildWSBXMLIsHardenedReadOnlyAndOffline(t *testing.T) {
	tmp := t.TempDir()
	sample := filepath.Join(tmp, "setup_game.exe")
	if err := os.WriteFile(sample, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	xmlBytes, hostDir, base, err := BuildWSBXML(sample)
	if err != nil {
		t.Fatalf("BuildWSBXML failed: %v", err)
	}
	s := string(xmlBytes)
	if base != "setup_game.exe" || hostDir == "" {
		t.Fatalf("unexpected base=%q hostDir=%q", base, hostDir)
	}
	for _, must := range []string{
		"<Networking>Disable</Networking>",
		"<ReadOnly>true</ReadOnly>",
		"<ClipboardRedirection>Disable</ClipboardRedirection>",
		"<ProtectedClient>Enable</ProtectedClient>",
	} {
		if !strings.Contains(s, must) {
			t.Errorf("generated .wsb missing %s:\n%s", must, s)
		}
	}
}
