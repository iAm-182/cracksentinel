package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"strings"
)

const (
	scnMemExecute = 0x20000000
	scnMemRead    = 0x40000000
	scnMemWrite   = 0x80000000
)

var pyInstallerMagic = []byte{'M', 'E', 'I', 0x0c, 0x0b, 0x0a, 0x0b, 0x0e}

// analyzeHeuristics performs deep structural PE inspection inspired by
// Detect-It-Easy (DosX heuristics) and Chinese anti-evasion research
// (white_patch_detect PEB/LDR shellcode walk, AheadLib export-forwarding proxy
// DLLs, and SysWhispers/Hell's Gate direct syscall stubs).
func analyzeHeuristics(f *pe.File, r io.ReaderAt, actualSize int64, info *Info) {
	var (
		dd        [16]pe.DataDirectory
		epRVA     uint32
		imageBase uint64
		is64      bool
	)
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory
		epRVA = oh.AddressOfEntryPoint
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory
		epRVA = oh.AddressOfEntryPoint
		imageBase = oh.ImageBase
		is64 = true
	default:
		return
	}
	info.IsDLL = (f.FileHeader.Characteristics & 0x2000) != 0

	// 1. Section permission & EntryPoint location checks (DosX style).
	var epSec *pe.Section
	for _, s := range f.Sections {
		name := strings.TrimRight(s.Name, "\x00")
		upName := strings.ToUpper(name)
		isUPXSec := strings.HasPrefix(upName, "UPX")

		if (s.Characteristics&scnMemExecute) != 0 && (s.Characteristics&scnMemWrite) != 0 && !isUPXSec {
			info.RWXSections = append(info.RWXSections, name)
		}
		vsize := s.VirtualSize
		if s.Size > vsize {
			vsize = s.Size
		}
		if epRVA != 0 && epRVA >= s.VirtualAddress && epRVA < s.VirtualAddress+vsize {
			epSec = s
		}
		// Scan executable sections (bounded to 8 MB) for direct syscall stubs & PEB/LDR shellcode walk.
		if (s.Characteristics&scnMemExecute) != 0 && s.Size > 0 {
			readSz := s.Size
			if readSz > 8<<20 {
				readSz = 8 << 20
			}
			code := make([]byte, readSz)
			if n, _ := r.ReadAt(code, int64(s.Offset)); n > 16 {
				code = code[:n]
				if is64 {
					info.DirectSyscallStubs += countSyscallStubs64(code)
					if hasPEBLDRWalk64(code) {
						info.PEBLDRWalk = true
					}
				} else {
					if hasPEBLDRWalk32(code) {
						info.PEBLDRWalk = true
					}
				}
			}
		}
	}

	if epSec != nil {
		epName := strings.TrimRight(epSec.Name, "\x00")
		lowEP := strings.ToLower(epName)
		if !strings.HasPrefix(strings.ToUpper(epName), "UPX") &&
			lowEP != ".text" && lowEP != "code" && lowEP != ".code" && lowEP != ".init" && lowEP != "text" {
			info.AbnormalEPSection = epName
		}
	}

	// 2. TLS Callbacks inspection (DataDirectory[9]).
	if dd[9].VirtualAddress != 0 && dd[9].Size >= 16 {
		tlsCount, susp := inspectTLSCallbacks(f, r, dd[9].VirtualAddress, imageBase, is64)
		info.TLSCallbacks = tlsCount
		info.TLSSuspicious = susp
	}

	// 3. Export Table & AheadLib Proxy DLL Forwarding (DataDirectory[0]).
	if dd[0].VirtualAddress != 0 && dd[0].Size > 0 {
		expTotal, fwdCount, fwdTargets := inspectExports(f, r, dd[0])
		info.ExportCount = expTotal
		info.ForwardedExports = fwdCount
		info.ForwardTargets = fwdTargets
	}

	// 4. Overlay inspection (exclude Authenticode certificate table at dd[4]).
	endOfSections := info.FileSize
	if actualSize > endOfSections && endOfSections > 0 {
		ovStart := endOfSections
		ovEnd := actualSize
		// Authenticode DataDirectory[4].VirtualAddress is a raw file offset!
		certOff := int64(dd[4].VirtualAddress)
		certSz := int64(dd[4].Size)
		if certOff >= ovStart && certSz > 0 && certOff < ovEnd {
			// If the certificate sits at the start of the overlay, inspect any gap after/before it;
			// typically the certificate IS the overlay on signed files.
			if certOff == ovStart && certOff+certSz >= ovEnd-16 {
				ovEnd = ovStart
			} else if certOff > ovStart {
				ovEnd = certOff
			}
		}
		if ovEnd > ovStart {
			info.OverlaySize = ovEnd - ovStart
			sampleLen := info.OverlaySize
			if sampleLen > 256*1024 {
				sampleLen = 256 * 1024
			}
			ovBuf := make([]byte, sampleLen)
			if n, _ := r.ReadAt(ovBuf, ovStart); n > 0 {
				ovBuf = ovBuf[:n]
				info.OverlayEntropy = round2(entropy(ovBuf))
				info.OverlayFormat = detectOverlayMagic(ovBuf)
			}
		}
	}

	// Check tail 64 KB for PyInstaller CArchive cookie ("MEI\x0c\x0b\x0a\x0b\x0e") or NSIS header.
	if actualSize > 64 {
		tailLen := int64(64 * 1024)
		if actualSize < tailLen {
			tailLen = actualSize
		}
		tail := make([]byte, tailLen)
		if n, _ := r.ReadAt(tail, actualSize-tailLen); n > 0 {
			if bytes.Contains(tail[:n], pyInstallerMagic) {
				info.HasPyInstaller = true
				if info.OverlayFormat == "" {
					info.OverlayFormat = "pyinstaller"
				}
			}
		}
	}
	analyzeGoAndRust(f, r, info)
}

func detectOverlayMagic(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	switch {
	case b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4:
		return "zip"
	case bytes.Equal(b[:6], []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}):
		return "7z"
	case bytes.Equal(b[:6], []byte{'R', 'a', 'r', '!', 0x1A, 0x07}):
		return "rar"
	case bytes.Equal(b[:4], []byte{'M', 'S', 'C', 'F'}):
		return "cab"
	case bytes.Contains(b[:minInt(len(b), 4096)], []byte("NullsoftInst")):
		return "nsis"
	case bytes.Contains(b[:minInt(len(b), 4096)], []byte("Inno Setup")):
		return "innosetup"
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func inspectTLSCallbacks(f *pe.File, r io.ReaderAt, tlsRVA uint32, imageBase uint64, is64 bool) (count int, suspicious bool) {
	off := int64(rvaToOffset(f, tlsRVA))
	var cbVA uint64
	if is64 {
		var dir [40]byte
		if _, err := r.ReadAt(dir[:], off); err != nil {
			return 0, false
		}
		cbVA = binary.LittleEndian.Uint64(dir[24:32])
	} else {
		var dir [24]byte
		if _, err := r.ReadAt(dir[:], off); err != nil {
			return 0, false
		}
		cbVA = uint64(binary.LittleEndian.Uint32(dir[12:16]))
	}
	if cbVA <= imageBase {
		return 0, false
	}
	cbRVA := uint32(cbVA - imageBase)
	arrOff := int64(rvaToOffset(f, cbRVA))
	ptrSz := int64(4)
	if is64 {
		ptrSz = 8
	}
	for i := int64(0); i < 32; i++ {
		var fnVA uint64
		if is64 {
			var b [8]byte
			if _, err := r.ReadAt(b[:], arrOff+i*ptrSz); err != nil {
				break
			}
			fnVA = binary.LittleEndian.Uint64(b[:])
		} else {
			var b [4]byte
			if _, err := r.ReadAt(b[:], arrOff+i*ptrSz); err != nil {
				break
			}
			fnVA = uint64(binary.LittleEndian.Uint32(b[:]))
		}
		if fnVA == 0 {
			break
		}
		count++
		if fnVA > imageBase {
			fnRVA := uint32(fnVA - imageBase)
			sec := sectionForRVA(f, fnRVA)
			if sec == nil {
				suspicious = true
			} else {
				nm := strings.ToLower(strings.TrimRight(sec.Name, "\x00"))
				if (sec.Characteristics&scnMemWrite) != 0 || (nm != ".text" && nm != "code" && nm != ".code") {
					suspicious = true
				}
			}
		}
	}
	return count, suspicious
}

func sectionForRVA(f *pe.File, rva uint32) *pe.Section {
	for _, s := range f.Sections {
		vsz := s.VirtualSize
		if s.Size > vsz {
			vsz = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+vsz {
			return s
		}
	}
	return nil
}

func inspectExports(f *pe.File, r io.ReaderAt, expDir pe.DataDirectory) (total int, forwarded int, targets []string) {
	off := int64(rvaToOffset(f, expDir.VirtualAddress))
	var hdr [40]byte
	if _, err := r.ReadAt(hdr[:], off); err != nil {
		return 0, 0, nil
	}
	numFuncs := binary.LittleEndian.Uint32(hdr[20:24])
	addrOfFuncs := binary.LittleEndian.Uint32(hdr[28:32])
	if numFuncs == 0 || addrOfFuncs == 0 {
		return 0, 0, nil
	}
	if numFuncs > 4096 {
		numFuncs = 4096
	}
	fnTableOff := int64(rvaToOffset(f, addrOfFuncs))
	seenTarget := map[string]bool{}
	dirStart := expDir.VirtualAddress
	dirEnd := expDir.VirtualAddress + expDir.Size

	for i := uint32(0); i < numFuncs; i++ {
		var b [4]byte
		if _, err := r.ReadAt(b[:], fnTableOff+int64(i)*4); err != nil {
			break
		}
		fnRVA := binary.LittleEndian.Uint32(b[:])
		if fnRVA == 0 {
			continue
		}
		total++
		// In the PE spec, an export RVA pointing inside the export directory itself
		// is a forwarder string ("DLLNAME.FuncName"), heavily used by AheadLib proxy DLLs.
		if fnRVA >= dirStart && fnRVA < dirEnd {
			forwarded++
			fwd := cstringAt(r, f, fnRVA)
			if dot := strings.LastIndexByte(fwd, '.'); dot > 0 {
				mod := strings.ToLower(strings.TrimSpace(fwd[:dot]))
				if mod != "" && !seenTarget[mod] && len(targets) < 8 {
					seenTarget[mod] = true
					targets = append(targets, mod)
				}
			}
		}
	}
	return total, forwarded, targets
}

// countSyscallStubs64 detects x64 direct syscall stubs generated by SysWhispers /
// Hell's Gate / Halo's Gate:
//
//	4C 8B D1             mov r10, rcx
//	B8 xx xx 00 00       mov eax, <SSN>
//	[optional 49 89 CA]
//	0F 05                syscall
//	C3                   ret
func countSyscallStubs64(code []byte) int {
	hits := 0
	for i := 0; i+11 <= len(code); i++ {
		if code[i] != 0x4C || code[i+1] != 0x8B || code[i+2] != 0xD1 || code[i+3] != 0xB8 {
			continue
		}
		// SSN high 2 bytes are 00 00 on Windows NT syscalls (< 0x2000).
		if code[i+6] != 0x00 || code[i+7] != 0x00 {
			continue
		}
		if code[i+8] == 0x0F && code[i+9] == 0x05 && code[i+10] == 0xC3 {
			hits++
			i += 10
			continue
		}
		if i+14 <= len(code) && code[i+8] == 0x49 && code[i+9] == 0x89 && code[i+10] == 0xCA &&
			code[i+11] == 0x0F && code[i+12] == 0x05 && code[i+13] == 0xC3 {
			hits++
			i += 13
		}
	}
	return hits
}

// hasPEBLDRWalk64 detects shellcode-style GS:[0x60] (PEB) -> [reg+0x18] (PEB_LDR_DATA)
// -> [reg+0x20] / [reg+0x10] module-list traversal (inspired by huoji120/white_patch_detect).
func hasPEBLDRWalk64(code []byte) bool {
	for i := 0; i+24 <= len(code); i++ {
		// 65 48 8B <modrm> 60 ... (mov reg, gs:[0x60])
		if code[i] != 0x65 || code[i+1] != 0x48 || code[i+2] != 0x8B {
			continue
		}
		found60 := false
		for k := 3; k <= 7 && i+k < len(code); k++ {
			if code[i+k] == 0x60 {
				found60 = true
				break
			}
		}
		if !found60 {
			continue
		}
		// Look ahead 36 bytes for [reg+0x18] (48 8B ?? 18) AND [reg+0x20 or 0x10] (48 8B ?? 20/10)
		end := i + 42
		if end > len(code) {
			end = len(code)
		}
		win := code[i+4 : end]
		hasLdr := false
		hasList := false
		for j := 0; j+4 <= len(win); j++ {
			if win[j] == 0x48 && win[j+1] == 0x8B {
				disp := win[j+3]
				if disp == 0x18 {
					hasLdr = true
				} else if hasLdr && (disp == 0x20 || disp == 0x10 || disp == 0x30) {
					hasList = true
				}
			}
		}
		if hasLdr && hasList {
			return true
		}
	}
	return false
}

// hasPEBLDRWalk32 detects x86 shellcode FS:[0x30] (PEB) -> [reg+0x0C] (Ldr) -> [reg+0x14/0x1C] walk.
func hasPEBLDRWalk32(code []byte) bool {
	for i := 0; i+18 <= len(code); i++ {
		// 64 8B ?? 30 (mov reg, fs:[0x30]) or 64 A1 30 00 00 00 (mov eax, fs:[0x30])
		matched := false
		if code[i] == 0x64 && code[i+1] == 0xA1 && code[i+2] == 0x30 && code[i+3] == 0x00 && code[i+4] == 0x00 && code[i+5] == 0x00 {
			matched = true
		} else if code[i] == 0x64 && code[i+1] == 0x8B && (code[i+3] == 0x30 || (i+5 < len(code) && code[i+4] == 0x30)) {
			matched = true
		}
		if !matched {
			continue
		}
		end := i + 32
		if end > len(code) {
			end = len(code)
		}
		win := code[i+3 : end]
		hasLdr, hasList := false, false
		for j := 0; j+3 <= len(win); j++ {
			if win[j] == 0x8B {
				d := win[j+2]
				if d == 0x0C {
					hasLdr = true
				} else if hasLdr && (d == 0x14 || d == 0x1C || d == 0x0C) {
					hasList = true
				}
			}
		}
		if hasLdr && hasList {
			return true
		}
	}
	return false
}
