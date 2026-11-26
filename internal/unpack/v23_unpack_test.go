package unpack

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLNKInflatedAndCommandArgs(t *testing.T) {
	// Construct a valid binary MS-SHLLINK (.lnk) with HasArguments | IsUnicode | SW_SHOWMINNOACTIVE (7)
	// plus 1.2 MB of zero-padding (LNK size-inflation trick).
	var b bytes.Buffer
	hdr := make([]byte, 76)
	binary.LittleEndian.PutUint32(hdr[0:4], 0x4C)
	copy(hdr[4:20], lnkHeaderCLSID)
	// LinkFlags: HasArguments (0x20) | HasIconLocation (0x40) | IsUnicode (0x80)
	binary.LittleEndian.PutUint32(hdr[20:24], 0x20|0x40|0x80)
	binary.LittleEndian.PutUint32(hdr[60:64], 7) // SW_SHOWMINNOACTIVE
	b.Write(hdr)

	writeU16Counted := func(s string) {
		var u []byte
		for _, r := range s {
			u = append(u, byte(r), 0)
		}
		var cnt [2]byte
		binary.LittleEndian.PutUint16(cnt[:], uint16(len(s)))
		b.Write(cnt[:])
		b.Write(u)
	}
	args := "-w hidden -enc SQBFAFgA"
	icon := `C:\Windows\System32\shell32.dll`
	writeU16Counted(args)
	writeU16Counted(icon)

	// TrackerDataBlock (0xA0000003, size 96, MachineID at offset 16)
	tracker := make([]byte, 96)
	binary.LittleEndian.PutUint32(tracker[0:4], 96)
	binary.LittleEndian.PutUint32(tracker[4:8], 0xA0000003)
	copy(tracker[16:], []byte("EVILBUILDERPC\x00"))
	b.Write(tracker)
	// Terminal block (0x00000000) + 1.2 MB zero-padding!
	b.Write(make([]byte, 1200*1024))

	lnkPath := filepath.Join(t.TempDir(), "Setup_Game.lnk")
	if err := os.WriteFile(lnkPath, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	info := ParseLNK(lnkPath)
	if !info.Valid || !info.ZeroPadded || !info.IsMinimizedHidden {
		t.Fatalf("unexpected LNK flags: %+v", info)
	}
	if info.Arguments != args || info.MachineID != "EVILBUILDERPC" {
		t.Fatalf("unexpected LNK strings: args=%q machine=%q", info.Arguments, info.MachineID)
	}
}

func TestInspectJarConstantPoolFractureiserLike(t *testing.T) {
	// Build a minimal JVM .class (0xCAFEBABE) containing Runtime.getRuntime + Discord webhook in Constant Pool
	var cls bytes.Buffer
	cls.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34}) // Java 8
	entries := []string{
		"java/lang/Runtime",
		"getRuntime",
		"java/net/URLClassLoader",
		"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcd",
	}
	var cpCnt [2]byte
	binary.BigEndian.PutUint16(cpCnt[:], uint16(len(entries)+1))
	cls.Write(cpCnt[:])
	for _, s := range entries {
		cls.WriteByte(1) // CONSTANT_Utf8
		var sl [2]byte
		binary.BigEndian.PutUint16(sl[:], uint16(len(s)))
		cls.Write(sl[:])
		cls.WriteString(s)
	}

	jarPath := filepath.Join(t.TempDir(), "OptiFineMod.jar")
	zf, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("net/mod/Loader.class")
	w.Write(cls.Bytes())
	zw.Close()
	zf.Close()

	rep, err := InspectJarOrModZip(jarPath, 100)
	if err != nil {
		t.Fatalf("InspectJarOrModZip err=%v", err)
	}
	if rep.ClassCount != 1 || !rep.FractureiserLike {
		t.Fatalf("expected ClassCount=1 & FractureiserLike=true, got %+v", rep)
	}
	joined := strings.Join(rep.ExtractedStrings, "\n")
	if !strings.Contains(joined, "discord.com/api/webhooks") {
		t.Fatalf("missing webhook from Java constant pool: %s", joined)
	}
}
