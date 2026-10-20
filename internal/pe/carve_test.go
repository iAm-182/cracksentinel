package pe

import (
	"os"
	"path/filepath"
	"testing"
)

// carveTestPE builds a byte sequence that passes the carve check: an MZ
// header with a PE signature behind the e_lfanew pointer.
func carveTestPE() []byte {
	b := make([]byte, 0x200)
	copy(b, []byte{'M', 'Z'})
	b[0x3c] = 0x80
	copy(b[0x80:], []byte{'P', 'E', 0, 0})
	b[0x84] = 0x4c // machine i386, low byte
	b[0x85] = 0x01 // machine i386, high byte (0x014c)
	b[0x86] = 1    // one section
	b[0x94] = 0xE0 // optional header size
	b[0x98] = 0x0b // magic PE32
	b[0x98+1] = 0x01
	return b
}

func TestCarveFindsEmbeddedPE(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.dat")

	blob := make([]byte, 3*1024*1024)
	copy(blob[1*1024*1024:], carveTestPE())
	// A second one further in, to check the chunk boundary handling.
	copy(blob[2*1024*1024+100:], carveTestPE())
	// Noise: an MZ that is not followed by a PE header must be ignored.
	copy(blob[500*1024:], []byte{'M', 'Z', 0, 0, 0, 0})

	if err := os.WriteFile(p, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	carves, err := CarvePEs(p, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(carves) != 2 {
		t.Fatalf("found %d embedded images, want 2: %+v", len(carves), carves)
	}
	if carves[0].Offset != 1*1024*1024 {
		t.Errorf("first offset = %d, want %d", carves[0].Offset, 1*1024*1024)
	}
	if carves[0].Machine != "x86" {
		t.Errorf("machine = %q, want x86", carves[0].Machine)
	}
	if carves[1].Offset != 2*1024*1024+100 {
		t.Errorf("second offset = %d, want %d", carves[1].Offset, 2*1024*1024+100)
	}
}

func TestCarveIgnoresPlainData(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plain.bin")
	blob := make([]byte, 512*1024)
	for i := range blob {
		blob[i] = byte(i % 251)
	}
	os.WriteFile(p, blob, 0o644)
	carves, err := CarvePEs(p, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(carves) != 0 {
		t.Errorf("found %d embedded images in random data: %+v", len(carves), carves)
	}
}

func TestCarveRespectsMaxCount(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "many.bin")
	blob := make([]byte, 2*1024*1024)
	for i := 0; i < 10; i++ {
		copy(blob[i*200*1024:], carveTestPE())
	}
	os.WriteFile(p, blob, 0o644)
	carves, err := CarvePEs(p, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(carves) != 3 {
		t.Errorf("found %d, want the cap of 3", len(carves))
	}
}

func TestExtractEmbedded(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "data.dat")
	payload := carveTestPE()
	blob := make([]byte, 1024*1024)
	copy(blob[500*1024:], payload)
	os.WriteFile(src, blob, 0o644)

	dst := filepath.Join(dir, "out.exe")
	if err := ExtractEmbedded(src, 500*1024, 0, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < len(payload) {
		t.Fatalf("extracted %d bytes, want at least %d", len(got), len(payload))
	}
	if got[0] != 'M' || got[1] != 'Z' {
		t.Error("the extracted bytes do not start with MZ")
	}
}
