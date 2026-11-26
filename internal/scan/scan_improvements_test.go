package scan

import (
	"archive/zip"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"gamecrack-scanner/internal/model"
)

func TestRuntimeDLLCapAndVeto(t *testing.T) {
	caps := []model.Finding{
		f("imp_keylogger", 30),
		f("imp_exfil", 12),
		f("imp_injection", 30),
	}
	// Clean runtime DLL gets capability capped at 15 (CLEAN).
	score, verdict, _ := computeScore(caps, []string{"RUNTIME_DLL"}, false)
	if score != runtimeCapabilityCap || verdict != model.VerdictClean {
		t.Errorf("clean runtime DLL = %d (%s), want %d (CLEAN)", score, verdict, runtimeCapabilityCap)
	}

	// Trojanized runtime DLL (with payload intent) is NOT rescued.
	trojan := append(caps, f("discord_webhook", 40))
	score, verdict, _ = computeScore(trojan, []string{"RUNTIME_DLL"}, false)
	if verdict != model.VerdictMalicious || score < 70 {
		t.Errorf("trojanized runtime DLL = %d (%s), want MALICIOUS (>=70)", score, verdict)
	}
}

func TestDisguisedPEDetected(t *testing.T) {
	dir := t.TempDir()
	peBytes := make([]byte, 0x200)
	peBytes[0], peBytes[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(peBytes[0x3C:0x40], 0x80)
	copy(peBytes[0x80:0x84], []byte{'P', 'E', 0, 0})

	p := filepath.Join(dir, "readme.txt")
	if err := os.WriteFile(p, peBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := New(Config{Root: dir, Workers: 1, MaxSizeMB: 64, FullReadMB: 32, SkipAssets: true})
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
	if r.Type != "pe" {
		t.Errorf("disguised readme.txt Type = %q, want pe", r.Type)
	}
	found := false
	for _, fd := range r.Findings {
		if fd.Rule == "masquerading_pe" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected masquerading_pe finding, got %+v", r.Findings)
	}
	if r.Verdict == model.VerdictClean {
		t.Errorf("disguised PE should not be CLEAN (score=%d)", r.Score)
	}
}

func TestDecoyRenPyZipDetected(t *testing.T) {
	dir := t.TempDir()
	arc := filepath.Join(dir, "FakeGame-Repack.zip")
	fh, err := os.Create(arc)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(fh)
	e1, _ := zw.Create("FakeGame/renpy/main.py")
	e1.Write([]byte("print('renpy')"))
	e2, _ := zw.Create("FakeGame/setup.py")
	e2.Write([]byte("# setup"))
	e3, _ := zw.Create("FakeGame/data/.BK9")
	e3.Write([]byte("0123456789abcdef"))
	e4, _ := zw.Create("FakeGame/data/FQXdVvMCZnc2.Nf")
	blob := make([]byte, 600*1024)
	rand.Read(blob)
	e4.Write(blob)
	zw.Close()
	fh.Close()

	s, err := New(Config{Root: dir, Workers: 1, MaxSizeMB: 64, FullReadMB: 32, ExtractDepth: 2, ExtractMaxMB: 64, TempDir: dir})
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
	if r.Verdict != model.VerdictMalicious {
		t.Errorf("decoy Ren'Py zip verdict = %s (score=%d, findings=%+v), want MALICIOUS", r.Verdict, r.Score, r.Findings)
	}
}

func TestDecoyRenPyFolderDetected(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "renpy"), 0o755)
	os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	os.WriteFile(filepath.Join(dir, "renpy", "main.py"), []byte("print('ok')"), 0o644)
	os.WriteFile(filepath.Join(dir, "data", ".BK9"), []byte("keybytes"), 0o644)
	blob := make([]byte, 600*1024)
	rand.Read(blob)
	os.WriteFile(filepath.Join(dir, "data", "FQXdVvMCZnc2.Nf"), blob, 0o644)

	s, err := New(Config{Root: dir, Workers: 1, MaxSizeMB: 64, FullReadMB: 32, SkipAssets: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sum, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if sum.Malicious == 0 {
		t.Errorf("expected decoy Ren'Py folder to have MALICIOUS detection, got %+v", sum.Results)
	}
}

func TestScanPathsMixedFilesAndFolders(t *testing.T) {
	d1 := t.TempDir()
	d2 := t.TempDir()
	writeFile(t, filepath.Join(d1, "clean.txt"), "hello")
	bad := filepath.Join(d2, "stealer.ps1")
	writeFile(t, bad, webhook())

	s, err := New(Config{Workers: 2, MaxSizeMB: 64, FullReadMB: 32, SkipAssets: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sum, err := s.ScanPaths([]string{d1, bad})
	if err != nil {
		t.Fatal(err)
	}
	if sum.FilesScanned != 2 {
		t.Errorf("FilesScanned = %d, want 2", sum.FilesScanned)
	}
	if sum.Suspicious+sum.Malicious == 0 {
		t.Errorf("expected stealer.ps1 to be flagged, got %+v", sum.Results)
	}
}
