package filetype

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func makeMinimalPE() []byte {
	buf := make([]byte, 0x100)
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], 0x80)
	copy(buf[0x80:0x84], []byte{'P', 'E', 0, 0})
	return buf
}

func TestDisguisedPEOverridesTextAndAssetExt(t *testing.T) {
	dir := t.TempDir()
	peBytes := makeMinimalPE()

	for _, name := range []string{"readme.txt", "cover.png", "data.pak", "info.nfo"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, peBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		if got := Classify(p); got != KindPE {
			t.Errorf("Classify(%s with real PE header) = %v, want KindPE", name, got)
		}
		if !IsDisguisedPE(p) {
			t.Errorf("IsDisguisedPE(%s) = false, want true", name)
		}
	}

	// Normal PE extension is NOT disguised.
	exe := filepath.Join(dir, "game.exe")
	os.WriteFile(exe, peBytes, 0o644)
	if IsDisguisedPE(exe) {
		t.Error("game.exe should not be marked as disguised PE")
	}

	// Plain text starting with "MZ" without PE header stays KindText.
	note := filepath.Join(dir, "mz_note.txt")
	os.WriteFile(note, []byte("MZ is the DOS executable header magic bytes in PE files."), 0o644)
	if got := Classify(note); got != KindText {
		t.Errorf("Classify(mz_note.txt) = %v, want KindText", got)
	}
	if IsDisguisedPE(note) {
		t.Error("mz_note.txt must not be disguised PE")
	}
}

func TestOLE2MagicDetection(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mystery.bin")
	os.WriteFile(p, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 0o644)
	if got := Classify(p); got != KindDoc {
		t.Errorf("Classify(OLE2 magic) = %v, want KindDoc", got)
	}
}

func TestArchiveMagicDetection(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"renamed_zip.dat", []byte{'P', 'K', 0x03, 0x04, 0, 0, 0, 0}, "zip"},
		{"renamed_7z.dat", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0}, "7z"},
		{"renamed_rar.dat", []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, "rar"},
		{"fg-01.bin", []byte{'A', 'r', 'C', 0x01, 0, 0, 0, 0}, "freearc"},
	}
	for _, c := range cases {
		p := filepath.Join(dir, c.name)
		os.WriteFile(p, c.data, 0o644)
		if got := ArchiveFormat(p); got != c.want {
			t.Errorf("ArchiveFormat(%s) = %q, want %q", c.name, got, c.want)
		}
		if got := Classify(p); got != KindArchive {
			t.Errorf("Classify(%s) = %v, want KindArchive", c.name, got)
		}
	}
}

func TestPythonAndRenPyScripts(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"dropper.py", "init.rpy", "setup.pyw"} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("print('hi')"), 0o644)
		if got := Classify(p); got != KindScript {
			t.Errorf("Classify(%s) = %v, want KindScript", name, got)
		}
	}
}

func TestSecondaryMultiVolume(t *testing.T) {
	cases := map[string]bool{
		"game.part1.rar":  false,
		"game.part01.rar": false,
		"game.part2.rar":  true,
		"game.part02.rar": true,
		"game.part10.rar": true,
		"game.rar":        false,
		"game.r00":        true,
		"game.r12":        true,
		"game.z01":        true,
		"game.7z.001":     false,
		"game.7z.002":     true,
	}
	for name, want := range cases {
		if got := IsSecondaryMultiVolume(name); got != want {
			t.Errorf("IsSecondaryMultiVolume(%q) = %v, want %v", name, got, want)
		}
	}
}
