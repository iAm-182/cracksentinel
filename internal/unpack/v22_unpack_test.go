package unpack

import (
	"bytes"
	"compress/flate"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutoItAndInnoDetection(t *testing.T) {
	tmp := t.TempDir()

	// 1. Synthetic AutoIt3 EA06 wrapped binary
	au3Path := filepath.Join(tmp, "trainer_setup.exe")
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte{0x90}, 512))
	b.Write(autoItScriptGuid)
	b.Write([]byte("AU3!EA06"))
	b.Write(bytes.Repeat([]byte{0x41}, 128))
	if err := os.WriteFile(au3Path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	info := DetectScriptWrapper(au3Path)
	if !info.HasAutoIt {
		t.Fatalf("expected HasAutoIt=true, got %+v", info)
	}

	// 2. Synthetic Inno Setup header
	innoPath := filepath.Join(tmp, "setup_game.exe")
	var b2 bytes.Buffer
	b2.Write(bytes.Repeat([]byte{0x00}, 256))
	b2.Write([]byte("Inno Setup Setup Data (6.2.2) (u)\x00"))
	if err := os.WriteFile(innoPath, b2.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	info2 := DetectScriptWrapper(innoPath)
	if !info2.HasInnoSetup || !strings.Contains(info2.InnoVersionHdr, "Inno Setup Setup Data (6.2.2)") {
		t.Fatalf("expected HasInnoSetup with version, got %+v", info2)
	}
}

func TestInspectDotnetMetadataAndCostura(t *testing.T) {
	// Build a minimal synthetic PE32+ carrying a CLR header (dd[14]), BSJB metadata root
	// with #US (UTF-16 user string), #Strings ("BepInEx", "costura.evil.dll.compressed"),
	// #~ ManifestResource table (0x28), and a deflate-compressed inner MZ DLL!
	innerDLL := make([]byte, 128)
	innerDLL[0] = 'M'
	innerDLL[1] = 'Z'
	copy(innerDLL[16:], []byte("https://discord.com/api/webhooks/123456789012345678/abcdefgh"))

	var compBuf bytes.Buffer
	fw, _ := flate.NewWriter(&compBuf, flate.DefaultCompression)
	fw.Write(innerDLL)
	fw.Close()
	compBytes := compBuf.Bytes()

	// CLR Resource blob: [uint32 length][deflate bytes]
	var resBlob bytes.Buffer
	var lenHdr [4]byte
	binary.LittleEndian.PutUint32(lenHdr[:], uint32(len(compBytes)))
	resBlob.Write(lenHdr[:])
	resBlob.Write(compBytes)

	// Build #Strings heap: "\x00BepInEx\x00costura.evil.dll.compressed\x00"
	var strHeap bytes.Buffer
	strHeap.WriteByte(0)
	bepOff := strHeap.Len()
	_ = bepOff
	strHeap.WriteString("BepInEx\x00")
	costuraNameOff := strHeap.Len()
	strHeap.WriteString("costura.evil.dll.compressed\x00")
	for strHeap.Len()%4 != 0 {
		strHeap.WriteByte(0)
	}

	// Build #US heap: [0x00][length][UTF-16LE "https://paste.ee/r/evil"][0x00]
	usText := "https://paste.ee/r/evil"
	var u16 bytes.Buffer
	for _, r := range usText {
		u16.WriteByte(byte(r))
		u16.WriteByte(0)
	}
	u16.WriteByte(0) // terminal byte
	var usHeap bytes.Buffer
	usHeap.WriteByte(0)
	usHeap.WriteByte(byte(u16.Len()))
	usHeap.Write(u16.Bytes())
	for usHeap.Len()%4 != 0 {
		usHeap.WriteByte(0)
	}

	// Build #~ stream with ONLY table 0x28 (ManifestResource) valid (1 row):
	// Offset(4)=0, Flags(4)=1, Name(2)=costuraNameOff, Implementation(2)=0
	var tilde bytes.Buffer
	tildeHdr := make([]byte, 24)
	tildeHdr[4] = 2 // MajorVersion
	binary.LittleEndian.PutUint64(tildeHdr[8:16], uint64(1)<<0x28)
	tilde.Write(tildeHdr)
	var rowCnt [4]byte
	binary.LittleEndian.PutUint32(rowCnt[:], 1)
	tilde.Write(rowCnt[:])
	mrRow := make([]byte, 12)
	binary.LittleEndian.PutUint32(mrRow[0:4], 0)
	binary.LittleEndian.PutUint32(mrRow[4:8], 1)
	binary.LittleEndian.PutUint16(mrRow[8:10], uint16(costuraNameOff))
	binary.LittleEndian.PutUint16(mrRow[10:12], 0)
	tilde.Write(mrRow)
	for tilde.Len()%4 != 0 {
		tilde.WriteByte(0)
	}

	// Build BSJB Metadata root with 3 streams: #Strings, #US, #~
	verStr := "v4.0.30319\x00\x00" // 12 bytes (4-byte aligned)
	// Stream headers:
	// "#Strings\x00" (9 -> padded to 12) -> 8+12 = 20 bytes
	// "#US\x00" (4) -> 8+4 = 12 bytes
	// "#~\x00\x00" (4) -> 8+4 = 12 bytes
	// Total BSJB header before stream data = 16 + 12 + 4 + (20 + 12 + 12) = 76 bytes
	const metaHdrLen = 76
	offStrings := uint32(metaHdrLen)
	offUS := offStrings + uint32(strHeap.Len())
	offTilde := offUS + uint32(usHeap.Len())

	var bsjb bytes.Buffer
	bsjb.WriteString("BSJB")
	bsjb.Write([]byte{1, 0, 1, 0, 0, 0, 0, 0})
	var vlen [4]byte
	binary.LittleEndian.PutUint32(vlen[:], uint32(len(verStr)))
	bsjb.Write(vlen[:])
	bsjb.WriteString(verStr)
	bsjb.Write([]byte{0, 0, 3, 0}) // flags=0, streams=3

	writeStreamHdr := func(off, sz uint32, paddedName []byte) {
		var h [8]byte
		binary.LittleEndian.PutUint32(h[0:4], off)
		binary.LittleEndian.PutUint32(h[4:8], sz)
		bsjb.Write(h[:])
		bsjb.Write(paddedName)
	}
	writeStreamHdr(offStrings, uint32(strHeap.Len()), []byte("#Strings\x00\x00\x00\x00"))
	writeStreamHdr(offUS, uint32(usHeap.Len()), []byte("#US\x00"))
	writeStreamHdr(offTilde, uint32(tilde.Len()), []byte("#~\x00\x00"))

	bsjb.Write(strHeap.Bytes())
	bsjb.Write(usHeap.Bytes())
	bsjb.Write(tilde.Bytes())

	// Layout inside .text section (RVA 0x1000):
	// [0x00..0x48) COR20 header (72 bytes)
	// [0x50..0x50+len(bsjb)) BSJB Metadata
	// [aligned..+len(resBlob)) CLR Resources
	var sec bytes.Buffer
	cor20 := make([]byte, 72)
	binary.LittleEndian.PutUint32(cor20[0:4], 72)
	metaRVA := uint32(0x1050)
	binary.LittleEndian.PutUint32(cor20[8:12], metaRVA)
	binary.LittleEndian.PutUint32(cor20[12:16], uint32(bsjb.Len()))
	resStartInSec := ((0x50 + bsjb.Len()) + 15) & ^15
	resRVA := uint32(0x1000 + resStartInSec)
	binary.LittleEndian.PutUint32(cor20[24:28], resRVA)
	binary.LittleEndian.PutUint32(cor20[28:32], uint32(resBlob.Len()))

	sec.Write(cor20)
	sec.Write(make([]byte, 0x50-72))
	sec.Write(bsjb.Bytes())
	if pad := resStartInSec - sec.Len(); pad > 0 {
		sec.Write(make([]byte, pad))
	}
	sec.Write(resBlob.Bytes())
	for sec.Len()%0x200 != 0 {
		sec.WriteByte(0)
	}

	// Minimal PE32+ wrapper with DataDirectory[14] pointing to RVA 0x1000, size 72
	hdr := make([]byte, 0x400)
	hdr[0], hdr[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(hdr[0x3C:0x40], 0x80)
	copy(hdr[0x80:0x84], []byte{'P', 'E', 0, 0})
	fh := 0x84
	binary.LittleEndian.PutUint16(hdr[fh:fh+2], 0x8664)
	binary.LittleEndian.PutUint16(hdr[fh+2:fh+4], 1)
	binary.LittleEndian.PutUint16(hdr[fh+16:fh+18], 240)
	binary.LittleEndian.PutUint16(hdr[fh+18:fh+20], 0x2022)
	oh := fh + 20
	binary.LittleEndian.PutUint16(hdr[oh:oh+2], 0x20B)
	binary.LittleEndian.PutUint64(hdr[oh+24:oh+32], 0x180000000)
	binary.LittleEndian.PutUint32(hdr[oh+32:oh+36], 0x1000)
	binary.LittleEndian.PutUint32(hdr[oh+36:oh+40], 0x200)
	binary.LittleEndian.PutUint32(hdr[oh+56:oh+60], 0x3000)
	binary.LittleEndian.PutUint32(hdr[oh+60:oh+64], 0x400)
	binary.LittleEndian.PutUint32(hdr[oh+108:oh+112], 16)
	dd14 := oh + 112 + 14*8
	binary.LittleEndian.PutUint32(hdr[dd14:dd14+4], 0x1000)
	binary.LittleEndian.PutUint32(hdr[dd14+4:dd14+8], 72)

	st := oh + 240
	copy(hdr[st:st+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(hdr[st+8:st+12], uint32(sec.Len()))
	binary.LittleEndian.PutUint32(hdr[st+12:st+16], 0x1000)
	binary.LittleEndian.PutUint32(hdr[st+16:st+20], uint32(sec.Len()))
	binary.LittleEndian.PutUint32(hdr[st+20:st+24], 0x400)
	binary.LittleEndian.PutUint32(hdr[st+36:st+40], pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_MEM_READ|pe.IMAGE_SCN_MEM_EXECUTE)

	dllPath := filepath.Join(t.TempDir(), "FakeBepInExMod.dll")
	if err := os.WriteFile(dllPath, append(hdr, sec.Bytes()...), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "costura_out")
	rep, err := InspectDotnet(dllPath, dest, 10<<20)
	if err != nil {
		t.Fatalf("InspectDotnet err=%v", err)
	}
	if !rep.IsDotnet || !rep.IsGameModPlugin {
		t.Fatalf("expected IsDotnet && IsGameModPlugin, got %+v", rep)
	}
	if len(rep.UserStrings) == 0 || rep.UserStrings[0] != usText {
		t.Fatalf("UserStrings = %v, want [%s]", rep.UserStrings, usText)
	}
	if len(rep.CosturaDLLs) != 1 || len(rep.ExtractedFiles) != 1 {
		t.Fatalf("expected 1 Costura DLL extracted, got dlls=%v files=%v", rep.CosturaDLLs, rep.ExtractedFiles)
	}
}
