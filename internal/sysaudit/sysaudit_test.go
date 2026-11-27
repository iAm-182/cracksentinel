package sysaudit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluateRawAuditDetectsDefenderAndPersistenceTamper(t *testing.T) {
	disabled := true
	raw := rawAuditPayload{
		RealtimeDisabled: &disabled,
		ExclusionPaths:   []string{`C:\Users\USER\AppData\Roaming`},
		ExclusionExts:    []string{`.exe`},
		Autoruns: []struct {
			Hive string `json:"hive"`
			Name string `json:"name"`
			Val  string `json:"val"`
		}{
			{Hive: `HKCU:\...\Run`, Name: "Updater", Val: `powershell.exe -w hidden -File C:\Users\USER\AppData\Local\Temp\ loader.ps1`},
			{Hive: `HKCU:\...\Run`, Name: "Discord", Val: `"C:\Users\USER\AppData\Local\Discord\Update.exe" --processStart Discord.exe`},
		},
		HostsTampered: []string{"127.0.0.1 www.virustotal.com"},
	}

	var rep Report
	evaluateRawAudit(raw, &rep)
	if rep.Status != "CRITICAL" {
		t.Fatalf("Status = %s, want CRITICAL", rep.Status)
	}
	if rep.HighCount < 4 {
		t.Fatalf("HighCount = %d, want >= 4; findings=%+v", rep.HighCount, rep.Findings)
	}
	for _, f := range rep.Findings {
		if f.Location == `HKCU:\...\Run\Discord` {
			t.Fatalf("benign Discord updater should not be flagged: %+v", f)
		}
		if f.FixAction == "" || f.FixLabel == "" {
			t.Errorf("expected FixAction and FixLabel populated on finding: %+v", f)
		}
	}
}

func TestDiscordInjectionDetectAndAutoCure(t *testing.T) {
	tmp := t.TempDir()
	coreDir := filepath.Join(tmp, "discord_desktop_core")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatal(err)
	}
	idxPath := filepath.Join(coreDir, "index.js")

	// 1. Clean Discord index.js -> not flagged
	if err := os.WriteFile(idxPath, []byte("module.exports = require('./core.asar');\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, tampered := inspectDiscordIndexJS(idxPath); tampered {
		t.Fatalf("clean Discord index.js should not be flagged as tampered")
	}

	// 2. PirateStealer/Lumma injected Discord index.js -> flagged HIGH with reset_discord_index
	malJS := "const webhook = 'https://discord.com/api/webhooks/123/abc';\nmodule.exports = require('./core.asar');"
	if err := os.WriteFile(idxPath, []byte(malJS), 0o644); err != nil {
		t.Fatal(err)
	}
	finding, tampered := inspectDiscordIndexJS(idxPath)
	if !tampered || finding.Risk != "HIGH" || finding.FixAction != "reset_discord_index" {
		t.Fatalf("expected HIGH tampered Discord finding, got tampered=%v finding=%+v", tampered, finding)
	}

	// 3. Run 1-Click Cure (ApplyFix) -> backs up malicious JS to quarantineDir & restores clean index.js!
	quarDir := filepath.Join(tmp, "quarantine")
	msg, err := ApplyFix(context.Background(), finding.FixAction, finding.FixTarget, quarDir)
	if err != nil {
		t.Fatalf("ApplyFix reset_discord_index error: %v", err)
	}
	if !strings.Contains(msg, "berhasil dibersihkan") {
		t.Fatalf("unexpected cure message: %s", msg)
	}
	if _, stillTampered := inspectDiscordIndexJS(idxPath); stillTampered {
		t.Fatalf("Discord index.js should be clean after ApplyFix")
	}
	entries, _ := os.ReadDir(quarDir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 backup file in quarantineDir, got %d", len(entries))
	}
}
