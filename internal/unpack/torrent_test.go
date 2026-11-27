package unpack

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func bStr(s string) string {
	return fmt.Sprintf("%d:%s", len(s), s)
}

func TestInspectTorrentDetectsFakeRepackAndInflatedLNK(t *testing.T) {
	// Build a synthetic malicious .torrent claiming to be "CyberGame_FitGirl_Repack"
	// but containing an inflated 2.5 MB Setup.lnk + payload.ps1!
	bencode := "d" +
		bStr("announce") + bStr("http://tracker.evil-mirror.top:80/announce") +
		bStr("comment") + bStr("Password: 1234") +
		bStr("info") + "d" +
		bStr("name") + bStr("CyberGame_FitGirl_Repack") +
		bStr("piece length") + "i262144e" +
		bStr("pieces") + bStr("12345678901234567890") +
		bStr("files") + "l" +
		"d" + bStr("length") + "i2621440e" + bStr("path") + "l" + bStr("Setup_Game.lnk") + "ee" +
		"d" + bStr("length") + "i4096e" + bStr("path") + "l" + bStr("data") + bStr("stealer.ps1") + "ee" +
		"d" + bStr("length") + "i524288e" + bStr("path") + "l" + bStr("Setup.exe") + "ee" +
		"e" +
		"ee"

	tPath := filepath.Join(t.TempDir(), "CyberGame_Repack.torrent")
	if err := os.WriteFile(tPath, []byte(bencode), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := InspectTorrent(tPath)
	if err != nil {
		t.Fatalf("InspectTorrent error: %v", err)
	}
	if !rep.Valid || rep.FileCount != 3 {
		t.Fatalf("unexpected torrent report: %+v", rep)
	}

	wantRules := map[string]bool{
		"lnk_size_inflated":                  false,
		"torrent_shortcut_or_script_dropper": false,
		"torrent_tiny_fake_repack":           false,
	}
	for _, f := range rep.Findings {
		if _, ok := wantRules[f.Rule]; ok {
			wantRules[f.Rule] = true
		}
	}
	for r, hit := range wantRules {
		if !hit {
			t.Errorf("expected rule %q to trigger on fake .torrent, got findings=%+v", r, rep.Findings)
		}
	}
}
