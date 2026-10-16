package rules

import (
	"testing"

	"gamecrack-scanner/internal/filetype"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/pe"
)

func TestEICARBytes(t *testing.T) {
	// Windows Defender deletes EICAR from disk before the scanner ever sees it,
	// so this class is verified via in-memory bytes.
	b := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	fs := matchBytes(b)
	if len(fs) != 1 || fs[0].Rule != "eicar" || fs[0].Severity != 100 {
		t.Fatalf("eicar not matched, got %+v", fs)
	}
}

func TestDiscordWebhookString(t *testing.T) {
	s := []string{`$w = "https://discord.com/api/webhooks/1234567890123456789/aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz01"`}
	fs := matchStrings(s)
	found := false
	for _, f := range fs {
		if f.Rule == "discord_webhook" {
			found = true
		}
	}
	if !found {
		t.Fatalf("discord webhook not matched: %+v", fs)
	}
}

func TestTelegramToken(t *testing.T) {
	fs := matchStrings([]string{"bot token = 7412345678:AAFxYzAbCdEfGhIjKlMnOpQrStUvWxYz0123 ok"})
	if len(fs) == 0 || fs[0].Rule != "telegram_token" {
		t.Fatalf("telegram token not matched: %+v", fs)
	}
}

func TestImportIOCs(t *testing.T) {
	info := &pe.Info{Imports: map[string][]string{
		"user32.dll":   {"GetAsyncKeyState", "SetWindowsHookExA"},
		"wininet.dll":  {"InternetOpenA", "HttpSendRequestA"},
		"crypt32.dll":  {"CryptUnprotectData"},
		"kernel32.dll": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
	}}
	fs := matchImports(info)
	want := map[string]bool{"imp_keylogger": false, "imp_injection": false, "imp_credential": false, "imp_exfil": false}
	for _, f := range fs {
		if _, ok := want[f.Rule]; ok {
			want[f.Rule] = true
		}
	}
	for rule, hit := range want {
		if !hit {
			t.Fatalf("missing import rule %s in %+v", rule, fs)
		}
	}
}

func TestWhitelist(t *testing.T) {
	hits := matchWhitelist([]string{"RUNE crack by me", "Goldberg SteamEmu", "random string"})
	if len(hits) != 2 || hits[0] != "RUNE" || hits[1] != "Goldberg" {
		t.Fatalf("whitelist mismatch: %+v", hits)
	}
}

func TestFullPipelineVerdict(t *testing.T) {
	strs := []string{
		`https://discord.com/api/webhooks/1234567890123456789/aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz01`,
		"GetAsyncKeyState used here",
		"Login Data",
		"clipboardgrab",
	}
	findings, _ := Match(MatchInput{Kind: filetype.KindScript, Strs: strs})
	score := 0
	for _, f := range findings {
		score += f.Severity
	}
	if score < 70 {
		t.Fatalf("stealer script should score >=70, got %d (%+v)", score, findings)
	}
	var _ = model.VerdictMalicious
}

func emuStrs(n int) []string {
	strs := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		strs = append(strs, "SteamAPI_Foo"+string(rune('A'+i%26)))
	}
	return strs
}

func TestIsEmuLikeClean(t *testing.T) {
	findings, wl := Match(MatchInput{Kind: filetype.KindPE, Strs: emuStrs(60)})
	found := false
	for _, w := range wl {
		if w == "EMU_STEAMAPI" {
			found = true
		}
	}
	if !found {
		t.Fatalf("emu-like DLL not flagged: wl=%+v findings=%+v", wl, findings)
	}
}

func TestIsEmuLikeVetoed(t *testing.T) {
	strs := append(emuStrs(60),
		`https://discord.com/api/webhooks/1234567890123456789/aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz01`)
	findings, wl := Match(MatchInput{Kind: filetype.KindPE, Strs: strs})
	for _, w := range wl {
		if w == "EMU_STEAMAPI" {
			t.Fatalf("trojanized emu must NOT get EMU_STEAMAPI: %+v", findings)
		}
	}
}

func TestVMRegexNoWinerrorFP(t *testing.T) {
	fs := matchStrings([]string{"?_Winerror_map@std@@YAHH@Z"})
	for _, f := range fs {
		if f.Rule == "sandbox_check" {
			t.Fatalf("Winerror must not match sandbox_check: %+v", fs)
		}
	}
	// Real wine marker still fires.
	fs = matchStrings([]string{"wine_get_version"})
	found := false
	for _, f := range fs {
		if f.Rule == "sandbox_check" {
			found = true
		}
	}
	if !found {
		t.Fatalf("wine_get_version should match sandbox_check: %+v", fs)
	}
}
