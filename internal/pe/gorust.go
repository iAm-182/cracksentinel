package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"strings"
)

var (
	goBuildInfoMagic = []byte("\xff Go buildinf:")
	rustPanicMarker1 = []byte("/rustc/")
	rustCargoMarker  = []byte("cargo\\registry\\src\\")
	rustCargoMarker2 = []byte("cargo/registry/src/")
)

// analyzeGoAndRust inspects PE sections for Golang build/symbol metadata
// (`\xff Go buildinf:`, `.gopclntab` magic `0xFFFFFFF0` / `0xFFFFFFF1` / `0xFFFFFFFA`)
// and Rust compiler/Cargo crate footprints (inspired by Mandiant GoReSym,
// 0xjiayu/go_parser, and peiwithhao/gopclntabParser).
func analyzeGoAndRust(f *pe.File, r io.ReaderAt, info *Info) {
	seenSym := map[string]bool{}
	addSym := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) >= 5 && len(s) <= 240 && !seenSym[s] && len(info.RecoveredSymbols) < 300 {
			seenSym[s] = true
			info.RecoveredSymbols = append(info.RecoveredSymbols, s)
		}
	}

	for _, s := range f.Sections {
		if s.Size == 0 {
			continue
		}
		secName := strings.ToLower(strings.TrimRight(s.Name, "\x00"))
		// Only inspect .rdata / .data / .text / .gopclntab / .go.buildinfo up to 6 MB per section
		if secName != ".rdata" && secName != ".data" && secName != ".text" &&
			!strings.Contains(secName, "gopcln") && !strings.Contains(secName, "buildin") {
			continue
		}
		readSz := s.Size
		if readSz > 6<<20 {
			readSz = 6 << 20
		}
		buf := make([]byte, readSz)
		n, _ := r.ReadAt(buf, int64(s.Offset))
		if n < 32 {
			continue
		}
		buf = buf[:n]

		// 1. Check Go buildinf magic & .gopclntab magic (Go 1.16: FA FF FF FF, Go 1.18: F0 FF FF FF, Go 1.20+: F1 FF FF FF)
		if bytes.Contains(buf, goBuildInfoMagic) {
			info.IsGoBinary = true
		}
		if pclnOff := findGoPclntab(buf); pclnOff >= 0 {
			info.IsGoBinary = true
			for _, fn := range extractGoPclntabFuncNames(buf[pclnOff:]) {
				addSym(fn)
			}
		}

		// 2. Check Rust `/rustc/<commit>/` & `cargo/registry/src/.../<crate>-<ver>/` crate paths
		if bytes.Contains(buf, rustPanicMarker1) || bytes.Contains(buf, rustCargoMarker) || bytes.Contains(buf, rustCargoMarker2) {
			info.IsRustBinary = true
			for _, crate := range extractRustCrates(buf) {
				addSym("rust_crate:" + crate)
			}
		}
	}
}

// findGoPclntab searches for a valid Go 1.16 / 1.18 / 1.20+ pcHeader magic:
// [0..4] magic (0xFFFFFFFA / 0xFFFFFFF0 / 0xFFFFFFF1 little-endian: FA/F0/F1 FF FF FF)
// [4..6] pad = 0x00, 0x00
// [6]    minLC (1, 2, or 4)
// [7]    ptrSize (4 or 8)
func findGoPclntab(b []byte) int {
	for i := 0; i+64 <= len(b); i += 4 {
		b0 := b[i]
		if (b0 != 0xF1 && b0 != 0xF0 && b0 != 0xFA) || b[i+1] != 0xFF || b[i+2] != 0xFF || b[i+3] != 0xFF {
			continue
		}
		if b[i+4] != 0 || b[i+5] != 0 {
			continue
		}
		minLC := b[i+6]
		ptrSz := b[i+7]
		if (minLC == 1 || minLC == 2 || minLC == 4) && (ptrSz == 4 || ptrSz == 8) {
			return i
		}
	}
	return -1
}

// extractGoPclntabFuncNames recovers non-stdlib function/package names from Go 1.16–1.22+
// pcHeader -> funcnametab (`funcnameOffset` sits at `8 + 3*ptrSize` in Go 1.18/1.20+ pcHeader,
// and `8 + 2*ptrSize` in Go 1.16). Even `-ldflags "-s -w"` stripped Go binaries preserve this!
func extractGoPclntabFuncNames(pcln []byte) []string {
	if len(pcln) < 64 {
		return nil
	}
	magic := pcln[0]
	ptrSz := int(pcln[7])
	readUintPtr := func(off int) uint64 {
		if off+ptrSz > len(pcln) {
			return 0
		}
		if ptrSz == 8 {
			return binary.LittleEndian.Uint64(pcln[off : off+8])
		}
		return uint64(binary.LittleEndian.Uint32(pcln[off : off+4]))
	}

	nfunc := readUintPtr(8)
	if nfunc == 0 || nfunc > 200000 {
		return nil
	}
	var funcnameOff uint64
	if magic == 0xFA { // Go 1.16
		funcnameOff = readUintPtr(8 + 2*ptrSz)
	} else { // Go 1.18 / 1.20+
		funcnameOff = readUintPtr(8 + 3*ptrSz)
	}
	if funcnameOff == 0 || funcnameOff >= uint64(len(pcln)) {
		return nil
	}

	tab := pcln[funcnameOff:]
	var out []string
	start := 0
	for i := 0; i < len(tab) && len(out) < 250; i++ {
		if tab[i] == 0 {
			if i-start >= 6 && i-start <= 200 {
				fn := string(tab[start:i])
				if isUserGoSymbol(fn) {
					out = append(out, fn)
				}
			}
			start = i + 1
		}
	}
	return out
}

func isUserGoSymbol(fn string) bool {
	// Skip noisy Go runtime / stdlib prefixes so only third-party modules & `main.*` stand out!
	stdPrefixes := []string{
		"runtime.", "internal/", "reflect.", "syscall.", "sync.", "os.", "io.",
		"fmt.", "net.", "crypto/", "encoding/", "math.", "strings.", "bytes.",
		"time.", "sort.", "strconv.", "unicode", "path/", "bufio.", "compress/",
		"type:.", "go:itab.",
	}
	for _, p := range stdPrefixes {
		if strings.HasPrefix(fn, p) {
			return false
		}
	}
	for i := 0; i < len(fn); i++ {
		if fn[i] < 0x20 || fn[i] > 0x7E {
			return false
		}
	}
	return strings.Contains(fn, ".") || strings.Contains(fn, "/")
}

func extractRustCrates(b []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, marker := range [][]byte{rustCargoMarker, rustCargoMarker2} {
		search := b
		for len(out) < 40 {
			idx := bytes.Index(search, marker)
			if idx < 0 {
				break
			}
			after := search[idx+len(marker):]
			search = after
			// Format: `index.crates.io-6f17d22bba15001f\winapi-0.3.9\src\...`
			end := 0
			for end < len(after) && end < 140 && after[end] >= 0x20 && after[end] <= 0x7E {
				end++
			}
			seg := strings.ReplaceAll(string(after[:end]), "\\", "/")
			parts := strings.Split(seg, "/")
			if len(parts) >= 2 {
				crate := parts[1]
				if crate != "" && !seen[crate] {
					seen[crate] = true
					out = append(out, crate)
				}
			}
		}
	}
	return out
}
