package sysaudit

import "testing"

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
	// Benign Discord Update.exe must NOT be flagged.
	for _, f := range rep.Findings {
		if f.Location == `HKCU:\...\Run\Discord` {
			t.Fatalf("benign Discord updater should not be flagged: %+v", f)
		}
	}
}
