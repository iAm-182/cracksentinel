package unpack

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildSyntheticAsar(t *testing.T, files map[string][]byte) string {
	t.Helper()
	type fmeta struct {
		Size   int    `json:"size"`
		Offset string `json:"offset"`
	}
	root := struct {
		Files map[string]fmeta `json:"files"`
	}{Files: map[string]fmeta{}}

	var payload bytes.Buffer
	for name, content := range files {
		off := payload.Len()
		payload.Write(content)
		root.Files[name] = fmeta{
			Size:   len(content),
			Offset: itoaTest(off),
		}
	}
	jb, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	aligned := (len(jb) + 3) & ^3
	padded := make([]byte, aligned)
	copy(padded, jb)

	var out bytes.Buffer
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 4)
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(8+aligned))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(4+aligned))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(jb)))
	out.Write(hdr[:])
	out.Write(padded)
	out.Write(payload.Bytes())

	p := filepath.Join(t.TempDir(), "app.asar")
	if err := os.WriteFile(p, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func itoaTest(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestAsarListAndExtract(t *testing.T) {
	jsCode := []byte(`const wh = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcd";`)
	asarPath := buildSyntheticAsar(t, map[string][]byte{
		"main.js":      jsCode,
		"package.json": []byte(`{"name":"launcher","main":"main.js"}`),
		"../evil.js":   []byte(`console.log("traversal")`),
	})
	if !IsAsar(asarPath) {
		t.Fatalf("expected IsAsar(%s) = true", asarPath)
	}
	_, ext, _, err := ListAsar(asarPath)
	if err != nil {
		t.Fatalf("ListAsar failed: %v", err)
	}
	if len(ext) < 2 {
		t.Fatalf("expected >=2 extractable entries, got %d", len(ext))
	}
	dest := filepath.Join(t.TempDir(), "out")
	n, _, err := ExtractAsar(asarPath, dest, 10<<20)
	if err != nil || n < 2 {
		t.Fatalf("ExtractAsar n=%d err=%v", n, err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "main.js"))
	if err != nil || !bytes.Contains(got, []byte("discord.com/api/webhooks")) {
		t.Fatalf("extracted main.js missing expected payload: err=%v", err)
	}
}

func TestPyInstallerExtractStrings(t *testing.T) {
	// Build a synthetic PyInstaller v2.1 CArchive appended to a dummy stub.
	stub := bytes.Repeat([]byte{0x90}, 256)

	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	zw.Write([]byte("\x00\x00\x00\x00import urllib.request\nWEBHOOK = 'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcd'\napp_bound_encrypted_key\n"))
	zw.Close()
	compData := zbuf.Bytes()

	// Build TOC entry for user script "stealer_main" (typeCode = 's', cFlag = 1)
	nameBytes := append([]byte("stealer_main"), 0)
	entryLen := 18 + len(nameBytes)
	if rem := entryLen % 16; rem != 0 {
		nameBytes = append(nameBytes, bytes.Repeat([]byte{0}, 16-rem)...)
		entryLen = 18 + len(nameBytes)
	}
	toc := make([]byte, entryLen)
	binary.BigEndian.PutUint32(toc[0:4], uint32(entryLen))
	binary.BigEndian.PutUint32(toc[4:8], 0) // ePos = 0 relative to overlayPos
	binary.BigEndian.PutUint32(toc[8:12], uint32(len(compData)))
	binary.BigEndian.PutUint32(toc[12:16], 512)
	toc[16] = 1   // compressed
	toc[17] = 's' // Python entry script
	copy(toc[18:], nameBytes)

	tocOff := len(compData)
	tocLen := len(toc)
	pkgLen := len(compData) + tocLen + pyCookie21Size

	cookie := make([]byte, pyCookie21Size)
	copy(cookie[0:8], pyInstCookieMagic)
	binary.BigEndian.PutUint32(cookie[8:12], uint32(pkgLen))
	binary.BigEndian.PutUint32(cookie[12:16], uint32(tocOff))
	binary.BigEndian.PutUint32(cookie[16:20], uint32(tocLen))
	binary.BigEndian.PutUint32(cookie[20:24], 311)
	copy(cookie[24:], []byte("python311.dll\x00"))

	var full bytes.Buffer
	full.Write(stub)
	full.Write(compData)
	full.Write(toc)
	full.Write(cookie)

	exePath := filepath.Join(t.TempDir(), "launcher.exe")
	if err := os.WriteFile(exePath, full.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	scripts, strs, ok := ExtractPyInstallerStrings(exePath, 8<<20)
	if !ok {
		t.Fatalf("ExtractPyInstallerStrings returned ok=false")
	}
	if len(scripts) != 1 || scripts[0] != "stealer_main" {
		t.Fatalf("scripts = %v, want [stealer_main]", scripts)
	}
	joined := strings.Join(strs, "\n")
	if !strings.Contains(joined, "discord.com/api/webhooks") || !strings.Contains(joined, "app_bound_encrypted_key") {
		t.Fatalf("unpacked PyInstaller strings missing stealer indicators: %s", joined)
	}
}
