package unpack

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"os"
	"strings"
)

// Pure-Go PyInstaller CArchive extractor inspired by extremecoders-re/pyinstxtractor.
// Requires ZERO external Python installation: locates the "MEI\x0c\x0b\x0a\x0b\x0e"
// cookie at the tail of a PyInstaller .exe, parses the TOC (Table of Contents),
// decompresses embedded user scripts ('s') and modules ('m'/'M'), and extracts
// printable ASCII & UTF-16 strings directly in memory for rule matching.

var pyInstCookieMagic = []byte{'M', 'E', 'I', 0x0c, 0x0b, 0x0a, 0x0b, 0x0e}

const (
	pyCookie20Size = 24
	pyCookie21Size = 24 + 64
)

// ExtractPyInstallerStrings unpacks user Python scripts & bytecode modules from a
// PyInstaller executable and returns script entry names + extracted strings.
func ExtractPyInstallerStrings(path string, maxTotalBytes int64) (scriptNames []string, extracted []string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 64 {
		return nil, nil, false
	}
	fileSize := st.Size()
	searchLen := int64(64 * 1024)
	if fileSize < searchLen {
		searchLen = fileSize
	}
	tail := make([]byte, searchLen)
	n, err := f.ReadAt(tail, fileSize-searchLen)
	if err != nil && n == 0 {
		return nil, nil, false
	}
	tail = tail[:n]
	idx := bytes.LastIndex(tail, pyInstCookieMagic)
	if idx < 0 {
		return nil, nil, false
	}
	cookieAbs := (fileSize - int64(n)) + int64(idx)
	rem := tail[idx:]
	if len(rem) < pyCookie20Size {
		return nil, nil, false
	}

	// PyInstaller CArchive cookie is Big-Endian!
	// magic[8], pkgLen(int32), tocOff(int32), tocLen(int32), pyVer(int32), [pylibname[64] in v2.1+]
	pkgLen := int64(uint32(binary.BigEndian.Uint32(rem[8:12])))
	tocOff := int64(int32(binary.BigEndian.Uint32(rem[12:16])))
	tocLen := int64(int32(binary.BigEndian.Uint32(rem[16:20])))

	cookieSize := int64(pyCookie21Size)
	if cookieAbs+pyCookie21Size > fileSize {
		cookieSize = pyCookie20Size
	} else {
		// Verify whether v2.1 (88-byte) or v2.0 (24-byte) aligns better with pkgLen:
		// overlayStart = cookieEnd - pkgLen must be >= 0 and toc must fit inside package.
		end21 := cookieAbs + pyCookie21Size
		if pkgLen <= 0 || end21-pkgLen < 0 {
			cookieSize = pyCookie20Size
		} else {
			// Check if pylibname looks like printable ASCII ("python311.dll\x00...") or null bytes.
			libField := rem[24:minPyInt(len(rem), 88)]
			if !looksLikePyLibField(libField) && (cookieAbs+pyCookie20Size)-pkgLen >= 0 {
				cookieSize = pyCookie20Size
			}
		}
	}

	overlayEnd := cookieAbs + cookieSize
	if overlayEnd > fileSize || pkgLen <= 0 || pkgLen > overlayEnd {
		return nil, nil, false
	}
	overlayPos := overlayEnd - pkgLen
	tocAbs := overlayPos + tocOff
	if tocOff < 0 || tocLen <= 0 || tocLen > 16<<20 || tocAbs < 0 || tocAbs+tocLen > fileSize {
		return nil, nil, false
	}

	tocBuf := make([]byte, tocLen)
	if _, err := f.ReadAt(tocBuf, tocAbs); err != nil {
		return nil, nil, false
	}

	if maxTotalBytes <= 0 {
		maxTotalBytes = 24 << 20
	}
	var unpackedBytes int64
	seenStr := map[string]bool{}
	addStrs := func(raw []byte) {
		for _, s := range extractPrintableStrings(raw, 6) {
			if !seenStr[s] && len(extracted) < 15000 {
				seenStr[s] = true
				extracted = append(extracted, s)
			}
		}
	}

	pos := 0
	entriesParsed := 0
	for pos+18 <= len(tocBuf) && entriesParsed < 4000 {
		entrySize := int(int32(binary.BigEndian.Uint32(tocBuf[pos : pos+4])))
		if entrySize < 18 || pos+entrySize > len(tocBuf) {
			break
		}
		ePos := int64(uint32(binary.BigEndian.Uint32(tocBuf[pos+4 : pos+8])))
		cSize := int64(uint32(binary.BigEndian.Uint32(tocBuf[pos+8 : pos+12])))
		uSize := int64(uint32(binary.BigEndian.Uint32(tocBuf[pos+12 : pos+16])))
		cFlag := tocBuf[pos+16]
		typeCode := tocBuf[pos+17]
		rawName := tocBuf[pos+18 : pos+entrySize]
		if z := bytes.IndexByte(rawName, 0); z >= 0 {
			rawName = rawName[:z]
		}
		name := strings.TrimSpace(string(rawName))
		pos += entrySize
		entriesParsed++

		if name == "" {
			continue
		}
		// Record user-authored entry scripts ('s'), skipping standard PyInstaller bootstrap scripts.
		if typeCode == 's' && !strings.HasPrefix(name, "pyiboot") && !strings.HasPrefix(name, "pyi_rth_") {
			scriptNames = append(scriptNames, name)
			if !seenStr[name] {
				seenStr[name] = true
				extracted = append(extracted, name)
			}
		}

		// Inspect user scripts ('s') and bundled modules ('m', 'M') when not standard stdlib bootstrap.
		inspect := false
		if typeCode == 's' && !strings.HasPrefix(name, "pyiboot") && !strings.HasPrefix(name, "pyi_rth_") {
			inspect = true
		} else if (typeCode == 'm' || typeCode == 'M') && len(scriptNames) < 32 && !isCommonStdlibModule(name) {
			inspect = true
		}
		if !inspect || cSize <= 0 || cSize > 4<<20 || uSize > 8<<20 {
			continue
		}
		dataAbs := overlayPos + ePos
		if dataAbs < 0 || dataAbs+cSize > fileSize || unpackedBytes >= maxTotalBytes {
			continue
		}
		comp := make([]byte, cSize)
		if _, err := f.ReadAt(comp, dataAbs); err != nil {
			continue
		}
		var plain []byte
		if cFlag == 1 {
			zr, err := zlib.NewReader(bytes.NewReader(comp))
			if err != nil {
				// Some PyInstaller builds prepend a 12/16-byte .pyc header before zlib or vice versa;
				// if raw zlib fails, still scan raw bytes.
				plain = comp
			} else {
				plain, _ = io.ReadAll(io.LimitReader(zr, 4<<20))
				zr.Close()
			}
		} else {
			plain = comp
		}
		unpackedBytes += int64(len(plain))
		addStrs(plain)
	}

	return scriptNames, extracted, entriesParsed > 0
}

func looksLikePyLibField(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	low := strings.ToLower(string(b))
	return strings.Contains(low, "python") || strings.Contains(low, "libpython")
}

func isCommonStdlibModule(name string) bool {
	switch name {
	case "struct", "pyimod01_archive", "pyimod02_importers", "pyimod03_ctypes", "pyimod04_pywin32",
		"codecs", "encodings", "abc", "io", "os", "stat", "ntpath", "genericpath", "_collections_abc":
		return true
	}
	return strings.HasPrefix(name, "encodings.") || strings.HasPrefix(name, "pyimod")
}

func extractPrintableStrings(b []byte, minLen int) []string {
	var out []string
	start := -1
	for i, c := range b {
		if c >= 0x20 && c <= 0x7E {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= minLen && i-start <= 2048 {
				out = append(out, string(b[start:i]))
			}
			start = -1
		}
	}
	if start >= 0 && len(b)-start >= minLen && len(b)-start <= 2048 {
		out = append(out, string(b[start:]))
	}
	return out
}

func minPyInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
