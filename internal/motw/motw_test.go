package motw

import (
	"net"
	"testing"
)

func parseNetIP(s string) net.IP { return net.ParseIP(s) }

func TestParseZoneIdentifier(t *testing.T) {
	raw := "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://ovagames.net/game-x/\r\nHostUrl=https://get.192169451.com/share/abc.zip\r\n"
	src := ParseZoneIdentifier(raw)
	if src == nil {
		t.Fatal("expected non-nil DownloadSource")
	}
	if src.ZoneID != 3 || src.ZoneName != "Internet" {
		t.Errorf("zone = %d (%s), want 3 (Internet)", src.ZoneID, src.ZoneName)
	}
	if src.HostDomain != "get.192169451.com" {
		t.Errorf("HostDomain = %q, want get.192169451.com", src.HostDomain)
	}
	if src.ReferrerURL != "https://ovagames.net/game-x/" {
		t.Errorf("ReferrerURL = %q", src.ReferrerURL)
	}
}

func TestAnalyzeURLDecoyChain(t *testing.T) {
	a := AnalyzeURL("https://get.192169451.com/share/Far_Cry_Repack-FitGirl.zip", "https://mroat0j0w.store/go", "Far_Cry_Repack-FitGirl.zip", 25*1024*1024)
	if a.Verdict != "MALICIOUS" {
		t.Errorf("decoy chain verdict = %s (score=%d, findings=%+v), want MALICIOUS", a.Verdict, a.Score, a.Findings)
	}
}

func TestAnalyzeURLDoubleExtension(t *testing.T) {
	a := AnalyzeURL("https://cdn.discordapp.com/attachments/1/2/patch.pdf.exe", "", "patch.pdf.exe", 500000)
	if a.Verdict != "MALICIOUS" {
		t.Errorf("discord double-ext verdict = %s (score=%d), want MALICIOUS", a.Verdict, a.Score)
	}
}

func TestAnalyzeURLTrustedClean(t *testing.T) {
	a := AnalyzeURL("https://store.steampowered.com/downloads/SteamSetup.exe", "", "SteamSetup.exe", 3*1024*1024)
	if a.Verdict != "CLEAN" {
		t.Errorf("steam setup verdict = %s (score=%d, findings=%+v), want CLEAN", a.Verdict, a.Score, a.Findings)
	}
}

func TestSSRFIPGuard(t *testing.T) {
	blocked := []string{"127.0.0.1", "10.0.0.1", "192.168.100.13", "172.16.5.1", "100.121.161.10", "169.254.169.254", "::1", "fc00::1"}
	for _, s := range blocked {
		if !isBlockedSSRFIP(parseTestIP(s)) {
			t.Errorf("expected %s to be blocked by SSRF guard", s)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "104.21.3.79"}
	for _, s := range allowed {
		if isBlockedSSRFIP(parseTestIP(s)) {
			t.Errorf("expected public IP %s to be allowed", s)
		}
	}
}

func parseTestIP(s string) []byte {
	var ip []byte
	for _, x := range []string{s} {
		ip = parseNetIP(x)
	}
	return ip
}
