package jev

// Live test against the real TypeSafe endpoint.
//
// It is skipped unless TYPESAFE_API_KEY is set, and it is opt-in:
//
//	TYPESAFE_API_KEY=... go test ./internal/jev/ -run TestLive -v
//
// It doubles as the shape check for the wire contract: a wrong question
// shape comes back as 422, and this test fails loudly when that happens.

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLive(t *testing.T) {
	if os.Getenv(EnvKey) == "" {
		t.Skipf("set %s to run the live test", EnvKey)
	}
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}
	c := New("", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// A trojanized crack: strong payload indicators next to emu imports.
	trojan := Evidence{
		Name: "crack_helper.dll", Type: "pe", Score: 100, Verdict: "MALICIOUS",
		ExpectedForCrack: []string{"imp_injection: WriteProcessMemory (normal for an emulator)"},
		PayloadIndicators: []string{
			"discord_webhook: https://discord.com/api/webhooks/...",
			"ps_encoded: powershell -enc SQBFAFgA",
			"wallet_browser_target: Login Data, wallet.dat, cookies.sqlite",
		},
		EmulatorProfile: map[string]int{"steamapi_exports": 40, "total_strings": 900},
	}
	v, err := c.Adjudicate(ctx, trojan)
	if err != nil {
		t.Fatalf("live call failed: %v", err)
	}
	t.Logf("trojanized case -> %s", v.Format())
	if v.Prob(ClassTrojanized) < 0.5 {
		t.Errorf("a payload-carrying file was not seen as trojanized: %s", v.Format())
	}

	// A clean crack: only emu behaviour, no payload indicators.
	clean := Evidence{
		Name: "steam_api64.dll", Type: "pe", Score: 30, Verdict: "SUSPICIOUS",
		ExpectedForCrack: []string{
			"imp_keylogger: GetAsyncKeyState, SetWindowsHookExA (hooking is how an emulator redirects Steam API calls)",
			"imp_injection: WriteProcessMemory (normal for an emulator)",
			"crack_whitelist: known crack/emulator signature: SmartSteamEmu, Goldberg",
		},
		PayloadIndicators: []string{},
		EmulatorProfile:   map[string]int{"steamapi_exports": 1212, "total_strings": 4312, "c2_urls": 0, "encoded_commands": 0, "credential_targets": 0},
	}
	v2, err := c.Adjudicate(ctx, clean)
	if err != nil {
		t.Fatalf("live call failed: %v", err)
	}
	t.Logf("clean crack case -> %s", v2.Format())
	if v2.Prob(ClassTrojanized) > 0.5 {
		t.Errorf("a clean crack was called trojanized: %s", v2.Format())
	}

	// A legitimate UTILITY that ships inside a repack. This is the real
	// false positive from the live FitGirl triage: QuickSFV.EXE, a
	// checksum verifier, was reported MALICIOUS (69) because it copies a
	// hash to the clipboard, enumerates and moves files, and carries a
	// large embedded blob. None of that is malicious on its own.
	utility := Evidence{
		Name: "QuickSFV.EXE", Type: "pe", Score: 69, Verdict: "MALICIOUS",
		ExpectedForCrack:  []string{},
		PayloadIndicators: []string{},
		OtherFindings: []string{
			"imp_clipboard: clipboard access API: GetClipboardData (a checksum tool copies the hash to the clipboard)",
			"imp_destructive: file/encryption API (ransomware-ish): FindFirstFileA, MoveFileA (a file-integrity tool enumerates and compares files)",
			"base64_blob: large base64 blob (len 4820) (the tool's own embedded data)",
		},
		EmulatorProfile: map[string]int{"total_strings": 2100, "payload_indicators": 0, "crack_expected_indicators": 0},
		Context: map[string]string{
			"file_name": "QuickSFV.EXE",
			"file_type": "pe",
			"origin":    "ships with a FitGirl repack, next to the MD5 checksum list it verifies",
		},
	}
	v3, err := c.Adjudicate(ctx, utility)
	if err != nil {
		t.Fatalf("live call failed: %v", err)
	}
	t.Logf("legitimate utility case -> %s", v3.Format())
	if v3.IsMalicious > 0.5 {
		t.Errorf("a checksum verifier was judged malicious: %s", v3.Format())
	}
}
