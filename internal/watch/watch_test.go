package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsPartialDownload(t *testing.T) {
	yes := []string{
		"game.zip.crdownload",
		"repack.rar.part",
		"setup.exe.!qB",
		"archive.7z.aria2",
		"installer.tmp",
		"file.opdownload",
	}
	for _, f := range yes {
		if !IsPartialDownload(f) {
			t.Errorf("expected IsPartialDownload(%q) = true", f)
		}
	}
	no := []string{"game.zip", "setup.exe", "steam_api64.dll", "repack.part1.rar"}
	for _, f := range no {
		if IsPartialDownload(f) {
			t.Errorf("expected IsPartialDownload(%q) = false", f)
		}
	}
}

func TestCollectChangedSkipsPartialAndFresh(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "done.exe")
	partial := filepath.Join(dir, "downloading.zip.crdownload")
	fresh := filepath.Join(dir, "just_arrived.zip")

	os.WriteFile(ready, []byte("hello"), 0o644)
	os.WriteFile(partial, []byte("part"), 0o644)
	os.WriteFile(fresh, []byte("fresh"), 0o644)

	old := time.Now().Add(-10 * time.Second)
	os.Chtimes(ready, old, old)
	os.Chtimes(partial, old, old)

	st := &State{Files: map[string]FileState{}}
	got := collectChanged(dir, st, 2*time.Second)
	if len(got) != 1 || got[0] != ready {
		t.Errorf("collectChanged = %v, want only [%s]", got, ready)
	}
}
