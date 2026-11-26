package unpack

import (
	"bytes"
	"compress/flate"
	"debug/pe"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DotnetReport summarizes deep pure-Go CLI metadata & Costura.Fody inspection.
type DotnetReport struct {
	IsDotnet        bool
	UserStrings     []string
	MetadataStrings []string
	ResourceNames   []string
	CosturaDLLs     []string // e.g. ["costura.newtonsoft.json.dll.compressed"]
	ExtractedFiles  []string // paths written to destDir (when destDir != "")
	IsGameModPlugin bool     // references BepInEx / MelonLoader / HarmonyLib / UnityEngine
}

// InspectDotnet parses the ECMA-335 CLI metadata root ("BSJB"), extracts #US
// (UTF-16 user strings) and #Strings (identifier/namespace/method names), and
// optionally decompresses Costura.Fody ("costura.*.dll.compressed") embedded
// assemblies from the .NET ManifestResource directory into destDir.
func InspectDotnet(path, destDir string, maxDecompBytes int64) (*DotnetReport, error) {
	pf, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	var clrDir pe.DataDirectory
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		clrDir = oh.DataDirectory[14]
	case *pe.OptionalHeader64:
		clrDir = oh.DataDirectory[14]
	default:
		return &DotnetReport{}, nil
	}
	if clrDir.VirtualAddress == 0 || clrDir.Size < 72 {
		return &DotnetReport{}, nil
	}

	rf, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer rf.Close()
	st, err := rf.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := st.Size()

	clrOff, ok := rvaToFileOff(pf, clrDir.VirtualAddress)
	if !ok || clrOff+72 > fileSize {
		return &DotnetReport{}, nil
	}
	var corHdr [72]byte
	if _, err := rf.ReadAt(corHdr[:], clrOff); err != nil {
		return &DotnetReport{}, nil
	}
	// IMAGE_COR20_HEADER:
	// [8:12]  MetaData RVA
	// [12:16] MetaData Size
	// [24:28] Resources RVA
	// [28:32] Resources Size
	metaRVA := binary.LittleEndian.Uint32(corHdr[8:12])
	metaSize := int64(binary.LittleEndian.Uint32(corHdr[12:16]))
	resRVA := binary.LittleEndian.Uint32(corHdr[24:28])
	resSize := int64(binary.LittleEndian.Uint32(corHdr[28:32]))

	if metaRVA == 0 || metaSize < 32 || metaSize > 32<<20 {
		return &DotnetReport{}, nil
	}
	metaOff, ok := rvaToFileOff(pf, metaRVA)
	if !ok || metaOff+metaSize > fileSize {
		return &DotnetReport{}, nil
	}
	meta := make([]byte, metaSize)
	if _, err := rf.ReadAt(meta, metaOff); err != nil {
		return &DotnetReport{}, nil
	}
	// ECMA-335 II.24.2.1 Metadata root starts with "BSJB" (0x424A5342)
	if len(meta) < 20 || string(meta[0:4]) != "BSJB" {
		return &DotnetReport{}, nil
	}
	verLen := int(binary.LittleEndian.Uint32(meta[12:16]))
	verAligned := (verLen + 3) & ^3
	pos := 16 + verAligned
	if pos+4 > len(meta) {
		return &DotnetReport{IsDotnet: true}, nil
	}
	numStreams := int(binary.LittleEndian.Uint16(meta[pos+2 : pos+4]))
	pos += 4

	rep := &DotnetReport{IsDotnet: true}
	type streamHdr struct {
		off  uint32
		size uint32
		name string
	}
	streams := map[string]streamHdr{}
	for i := 0; i < numStreams && i < 16 && pos+8 <= len(meta); i++ {
		sOff := binary.LittleEndian.Uint32(meta[pos : pos+4])
		sSize := binary.LittleEndian.Uint32(meta[pos+4 : pos+8])
		pos += 8
		nameStart := pos
		for pos < len(meta) && meta[pos] != 0 && pos-nameStart < 32 {
			pos++
		}
		sName := string(meta[nameStart:pos])
		pos++ // skip null
		pos = (pos + 3) & ^3
		if int64(sOff)+int64(sSize) <= int64(len(meta)) {
			streams[sName] = streamHdr{off: sOff, size: sSize, name: sName}
		}
	}

	// 1. Parse #US (User Strings heap — UTF-16LE literals in C#/VB code).
	if us, ok := streams["#US"]; ok && us.size > 1 {
		rep.UserStrings = parseDotnetUserStrings(meta[us.off:us.off+us.size], 8000)
	}

	// 2. Parse #Strings (identifier/type/method/resource names).
	if ss, ok := streams["#Strings"]; ok && ss.size > 1 {
		rep.MetadataStrings = parseDotnetStringsHeap(meta[ss.off:ss.off+ss.size], 8000)
		for _, s := range rep.MetadataStrings {
			low := strings.ToLower(s)
			if strings.HasPrefix(low, "costura.") && (strings.HasSuffix(low, ".dll.compressed") || strings.HasSuffix(low, ".exe.compressed")) {
				rep.CosturaDLLs = append(rep.CosturaDLLs, s)
			}
			if low == "bepinex" || low == "melonloader" || low == "harmonylib" || low == "0harmony" || low == "unityengine" {
				rep.IsGameModPlugin = true
			}
		}
	}

	// 3. Parse #~ / #- ManifestResource table (table 40 / 0x28) when Costura resources exist,
	// or scan the CLR Resources directory for deflate-compressed MZ/PE assemblies.
	if destDir != "" && resRVA != 0 && resSize > 16 && len(rep.CosturaDLLs) > 0 {
		if resOff, ok := rvaToFileOff(pf, resRVA); ok && resOff+resSize <= fileSize {
			if maxDecompBytes <= 0 {
				maxDecompBytes = 32 << 20
			}
			ts, hasTilde := streams["#~"]
			if !hasTilde {
				ts, hasTilde = streams["#-"]
			}
			var strHeap []byte
			if ss, ok := streams["#Strings"]; ok {
				strHeap = meta[ss.off : ss.off+ss.size]
			}
			if hasTilde && len(strHeap) > 0 {
				resEntries := parseManifestResources(meta[ts.off:ts.off+ts.size], strHeap)
				var totalWritten int64
				for idx, re := range resEntries {
					low := strings.ToLower(re.name)
					if !strings.HasSuffix(low, ".compressed") {
						continue
					}
					rep.ResourceNames = append(rep.ResourceNames, re.name)
					// In CLR Resources directory: each resource starts with a uint32 length at resOff + re.offset
					entryPos := resOff + int64(re.offset)
					if entryPos+8 > resOff+resSize {
						continue
					}
					var lenBuf [4]byte
					if _, err := rf.ReadAt(lenBuf[:], entryPos); err != nil {
						continue
					}
					blobLen := int64(binary.LittleEndian.Uint32(lenBuf[:]))
					if blobLen <= 32 || blobLen > 16<<20 || entryPos+4+blobLen > resOff+resSize {
						continue
					}
					if totalWritten >= maxDecompBytes || idx >= 24 {
						break
					}
					comp := make([]byte, blobLen)
					if _, err := rf.ReadAt(comp, entryPos+4); err != nil {
						continue
					}
					fr := flate.NewReader(bytes.NewReader(comp))
					decomp, err := io.ReadAll(io.LimitReader(fr, 16<<20))
					fr.Close()
					if err != nil && len(decomp) < 64 {
						continue
					}
					if len(decomp) >= 64 && decomp[0] == 'M' && decomp[1] == 'Z' {
						cleanName := sanitizeCosturaName(re.name)
						outPath := filepath.Join(destDir, cleanName)
						if err := os.MkdirAll(destDir, 0o755); err == nil {
							if os.WriteFile(outPath, decomp, 0o644) == nil {
								rep.ExtractedFiles = append(rep.ExtractedFiles, outPath)
								totalWritten += int64(len(decomp))
							}
						}
					}
				}
			}
		}
	}

	return rep, nil
}

type manifestResEntry struct {
	offset uint32
	name   string
}

// parseManifestResources walks the ECMA-335 #~ table stream up to Table 0x28 (ManifestResource).
func parseManifestResources(tilde []byte, stringsHeap []byte) []manifestResEntry {
	if len(tilde) < 24 {
		return nil
	}
	heapSizes := tilde[6]
	strIdxSz := 2
	if (heapSizes & 0x01) != 0 {
		strIdxSz = 4
	}
	guidIdxSz := 2
	if (heapSizes & 0x02) != 0 {
		guidIdxSz = 4
	}
	blobIdxSz := 2
	if (heapSizes & 0x04) != 0 {
		blobIdxSz = 4
	}
	valid := binary.LittleEndian.Uint64(tilde[8:16])
	pos := 24
	var rows [64]uint32
	for t := 0; t < 64; t++ {
		if (valid & (uint64(1) << t)) != 0 {
			if pos+4 > len(tilde) {
				return nil
			}
			rows[t] = binary.LittleEndian.Uint32(tilde[pos : pos+4])
			pos += 4
		}
	}
	if rows[0x28] == 0 {
		return nil
	}

	simpleSz := func(table int) int {
		if rows[table] > 0xFFFF {
			return 4
		}
		return 2
	}
	codedSz := func(tagBits int, tables ...int) int {
		limit := uint32(1) << (16 - tagBits)
		for _, tb := range tables {
			if tb >= 0 && rows[tb] >= limit {
				return 4
			}
		}
		return 2
	}

	// Row sizes for ECMA-335 tables 0x00 .. 0x27 so we can seek accurately to 0x28 (ManifestResource).
	tdOrRef := codedSz(2, 0x02, 0x01, 0x1B)
	hasConst := codedSz(2, 0x04, 0x08, 0x17)
	hasCustomAttr := codedSz(5, 0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B)
	customAttrType := codedSz(3, -1, -1, 0x06, 0x0A, -1)
	hasDeclSec := codedSz(2, 0x02, 0x06, 0x20)
	memRefParent := codedSz(3, 0x02, 0x01, 0x1A, 0x06, 0x1B)
	hasSemantics := codedSz(1, 0x14, 0x17)
	methodDefOrRef := codedSz(1, 0x06, 0x0A)
	memberForwarded := codedSz(1, 0x04, 0x06)
	implementation := codedSz(2, 0x26, 0x23, 0x27)
	resScope := codedSz(2, 0x00, 0x1A, 0x23, 0x01)

	tableRowSize := func(t int) int {
		switch t {
		case 0x00: // Module
			return 2 + strIdxSz + 3*guidIdxSz
		case 0x01: // TypeRef
			return resScope + 2*strIdxSz
		case 0x02: // TypeDef
			return 4 + 2*strIdxSz + tdOrRef + simpleSz(0x04) + simpleSz(0x06)
		case 0x03: // FieldPtr
			return simpleSz(0x04)
		case 0x04: // Field
			return 2 + strIdxSz + blobIdxSz
		case 0x05: // MethodPtr
			return simpleSz(0x06)
		case 0x06: // MethodDef
			return 4 + 2 + 2 + strIdxSz + blobIdxSz + simpleSz(0x08)
		case 0x07: // ParamPtr
			return simpleSz(0x08)
		case 0x08: // Param
			return 2 + 2 + strIdxSz
		case 0x09: // InterfaceImpl
			return simpleSz(0x02) + tdOrRef
		case 0x0A: // MemberRef
			return memRefParent + strIdxSz + blobIdxSz
		case 0x0B: // Constant
			return 2 + hasConst + blobIdxSz
		case 0x0C: // CustomAttribute
			return hasCustomAttr + customAttrType + blobIdxSz
		case 0x0D: // FieldMarshal
			return codedSz(1, 0x04, 0x08) + blobIdxSz
		case 0x0E: // DeclSecurity
			return 2 + hasDeclSec + blobIdxSz
		case 0x0F: // ClassLayout
			return 2 + 4 + simpleSz(0x02)
		case 0x10: // FieldLayout
			return 4 + simpleSz(0x04)
		case 0x11: // StandAloneSig
			return blobIdxSz
		case 0x12: // EventMap
			return simpleSz(0x02) + simpleSz(0x14)
		case 0x13: // EventPtr
			return simpleSz(0x14)
		case 0x14: // Event
			return 2 + strIdxSz + tdOrRef
		case 0x15: // PropertyMap
			return simpleSz(0x02) + simpleSz(0x17)
		case 0x16: // PropertyPtr
			return simpleSz(0x17)
		case 0x17: // Property
			return 2 + strIdxSz + blobIdxSz
		case 0x18: // MethodSemantics
			return 2 + simpleSz(0x06) + hasSemantics
		case 0x19: // MethodImpl
			return simpleSz(0x02) + 2*methodDefOrRef
		case 0x1A: // ModuleRef
			return strIdxSz
		case 0x1B: // TypeSpec
			return blobIdxSz
		case 0x1C: // ImplMap
			return 2 + memberForwarded + strIdxSz + simpleSz(0x1A)
		case 0x1D: // FieldRVA
			return 4 + simpleSz(0x04)
		case 0x1E, 0x1F: // ENCLog, ENCMap
			return 8
		case 0x20: // Assembly
			return 4 + 8 + 4 + blobIdxSz + 2*strIdxSz
		case 0x21: // AssemblyProcessor
			return 4
		case 0x22: // AssemblyOS
			return 12
		case 0x23: // AssemblyRef
			return 8 + 4 + 2*blobIdxSz + 2*strIdxSz
		case 0x24: // AssemblyRefProcessor
			return 4 + simpleSz(0x23)
		case 0x25: // AssemblyRefOS
			return 12 + simpleSz(0x23)
		case 0x26: // File
			return 4 + strIdxSz + blobIdxSz
		case 0x27: // ExportedType
			return 4 + 4 + 2*strIdxSz + implementation
		}
		return -1
	}

	for t := 0; t < 0x28; t++ {
		if rows[t] == 0 {
			continue
		}
		rsz := tableRowSize(t)
		if rsz <= 0 {
			return nil
		}
		pos += int(rows[t]) * rsz
		if pos > len(tilde) {
			return nil
		}
	}

	// Table 0x28 ManifestResource: Offset(4) + Flags(4) + Name(strIdxSz) + Implementation(implementation)
	mrRowSz := 4 + 4 + strIdxSz + implementation
	count := int(rows[0x28])
	if count > 512 {
		count = 512
	}
	var out []manifestResEntry
	for i := 0; i < count && pos+mrRowSz <= len(tilde); i++ {
		off := binary.LittleEndian.Uint32(tilde[pos : pos+4])
		var nameIdx uint32
		if strIdxSz == 4 {
			nameIdx = binary.LittleEndian.Uint32(tilde[pos+8 : pos+12])
		} else {
			nameIdx = uint32(binary.LittleEndian.Uint16(tilde[pos+8 : pos+10]))
		}
		pos += mrRowSz
		if int(nameIdx) < len(stringsHeap) {
			end := int(nameIdx)
			for end < len(stringsHeap) && stringsHeap[end] != 0 && end-int(nameIdx) < 260 {
				end++
			}
			nm := string(stringsHeap[nameIdx:end])
			if nm != "" {
				out = append(out, manifestResEntry{offset: off, name: nm})
			}
		}
	}
	return out
}

func parseDotnetUserStrings(us []byte, maxCount int) []string {
	var out []string
	i := 1 // index 0 is empty blob
	for i < len(us) && len(out) < maxCount {
		b0 := us[i]
		var blobLen int
		var hdr int
		switch {
		case (b0 & 0x80) == 0:
			blobLen = int(b0)
			hdr = 1
		case (b0 & 0xC0) == 0x80:
			if i+1 >= len(us) {
				return out
			}
			blobLen = (int(b0&0x3F) << 8) | int(us[i+1])
			hdr = 2
		case (b0 & 0xE0) == 0xC0:
			if i+3 >= len(us) {
				return out
			}
			blobLen = (int(b0&0x1F) << 24) | (int(us[i+1]) << 16) | (int(us[i+2]) << 8) | int(us[i+3])
			hdr = 4
		default:
			i++
			continue
		}
		i += hdr
		if blobLen <= 1 || i+blobLen > len(us) {
			if blobLen > 0 {
				i += blobLen
			} else {
				i++
			}
			continue
		}
		// Last byte of a #US entry is a terminal 0x00/0x01 flag; body is UTF-16LE.
		utf16Body := us[i : i+blobLen-1]
		i += blobLen
		if len(utf16Body) >= 8 && len(utf16Body) <= 4096 {
			s := decodeUTF16LEString(utf16Body)
			if len(s) >= 4 {
				out = append(out, s)
			}
		}
	}
	return out
}

func parseDotnetStringsHeap(heap []byte, maxCount int) []string {
	var out []string
	start := 1
	for i := 1; i < len(heap) && len(out) < maxCount; i++ {
		if heap[i] == 0 {
			if i-start >= 4 && i-start <= 512 {
				out = append(out, string(heap[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

func decodeUTF16LEString(b []byte) string {
	var sb strings.Builder
	for j := 0; j+1 < len(b); j += 2 {
		r := rune(uint16(b[j]) | uint16(b[j+1])<<8)
		if r == 0 {
			continue
		}
		sb.WriteRune(r)
	}
	return strings.TrimSpace(sb.String())
}

func rvaToFileOff(pf *pe.File, rva uint32) (int64, bool) {
	for _, s := range pf.Sections {
		vsz := s.VirtualSize
		if s.Size > vsz {
			vsz = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+vsz {
			return int64(s.Offset) + int64(rva-s.VirtualAddress), true
		}
	}
	return 0, false
}

func sanitizeCosturaName(name string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".compressed")
	n = strings.TrimPrefix(n, "costura.")
	n = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, n)
	if n == "" {
		return "costura_embedded.dll"
	}
	return n
}
