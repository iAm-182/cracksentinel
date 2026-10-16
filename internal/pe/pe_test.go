package pe

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// minimalPE builds a tiny in-memory PE image whose section table contains
// the given names. Enough for DetectPackerSections, nothing more.
func minimalPE(sections []string) []byte {
	const size = 4096
	b := make([]byte, size)
	b[0], b[1] = 'M', 'Z'
	lfanew := 0x80
	binary.LittleEndian.PutUint32(b[0x3C:], uint32(lfanew))
	b[lfanew], b[lfanew+1] = 'P', 'E'
	coff := lfanew + 4
	binary.LittleEndian.PutUint16(b[coff+2:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(b[coff+16:], 0xE0) // optional header size
	tab := coff + 20 + 0xE0
	for i, name := range sections {
		copy(b[tab+i*40:], name)
	}
	return b
}

func writeTempPE(t *testing.T, sections []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "t.exe")
	if err := os.WriteFile(p, minimalPE(sections), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectPackerSectionsUPX(t *testing.T) {
	if got := DetectPackerSections(writeTempPE(t, []string{"UPX0", "UPX1", ".rsrc"})); got != "UPX0" {
		t.Errorf("got %q, want UPX0", got)
	}
}

func TestDetectPackerSectionsClean(t *testing.T) {
	if got := DetectPackerSections(writeTempPE(t, []string{".text", ".rdata"})); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestDetectPackerSectionsGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.exe")
	os.WriteFile(p, []byte("definitely not a PE file at all"), 0o644)
	if got := DetectPackerSections(p); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	if got := DetectPackerSections(filepath.Join(t.TempDir(), "missing.exe")); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
