package unpack

import (
	"bytes"
	"os"
)

// Pure-Go AutoIt v3 ("AU3!EA06" / "AU3!EA05" / ".a3x") & Inno Setup signature
// inspection inspired by AutoIt-Ripper and innounp. AutoIt v3 compiled droppers
// are heavily used by Russian/Eastern-European FUD crypters to wrap LummaC2,
// RedLine, AsyncRAT, and DarkGate inside fake game cracks & trainers.

var (
	autoItEA06Magic = []byte{'A', 'U', '3', '!', 'E', 'A', '0', '6'}
	autoItEA05Magic = []byte{'A', 'U', '3', '!', 'E', 'A', '0', '5'}
	// Standard 16-byte AutoIt v3 script signature ("\xA3\x48\x4B\xBE\x98\x6C\x4A\xA9\x99\x4C\x53\x0A\x86\xD6\x48\x7D")
	autoItScriptGuid = []byte{0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D}
	innoSetupHdrs    = [][]byte{
		[]byte("Inno Setup Setup Data ("),
		[]byte("Inno Setup Messages ("),
	}
)

// ScriptWrapperInfo describes AutoIt3 or Inno Setup embedded payloads inside an executable.
type ScriptWrapperInfo struct {
	HasAutoIt      bool
	AutoItVariant  string // "AU3!EA06", "AU3!EA05", "A3X-GUID"
	AutoItOffset   int64
	HasInnoSetup   bool
	InnoVersionHdr string
}

// DetectScriptWrapper scans a PE/binary file (head + overlay/tail) for compiled
// AutoIt v3 script containers and Inno Setup data headers without executing anything.
func DetectScriptWrapper(path string) ScriptWrapperInfo {
	var out ScriptWrapperInfo
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 32 {
		return out
	}
	sz := st.Size()

	// Scan up to first 4 MB + last 4 MB (covers 99.9% of AutoIt stubs & Inno headers).
	scanWindow := func(offset int64, length int64) {
		if length <= 0 || offset < 0 || offset >= sz {
			return
		}
		if offset+length > sz {
			length = sz - offset
		}
		buf := make([]byte, length)
		n, _ := f.ReadAt(buf, offset)
		if n < 16 {
			return
		}
		buf = buf[:n]

		if !out.HasAutoIt {
			if idx := bytes.Index(buf, autoItEA06Magic); idx >= 0 {
				out.HasAutoIt = true
				out.AutoItVariant = "AU3!EA06"
				out.AutoItOffset = offset + int64(idx)
			} else if idx := bytes.Index(buf, autoItEA05Magic); idx >= 0 {
				out.HasAutoIt = true
				out.AutoItVariant = "AU3!EA05"
				out.AutoItOffset = offset + int64(idx)
			} else if idx := bytes.Index(buf, autoItScriptGuid); idx >= 0 {
				out.HasAutoIt = true
				out.AutoItVariant = "AU3-Script-GUID"
				out.AutoItOffset = offset + int64(idx)
			}
		}

		if !out.HasInnoSetup {
			for _, hdr := range innoSetupHdrs {
				if idx := bytes.Index(buf, hdr); idx >= 0 {
					out.HasInnoSetup = true
					end := idx + 64
					if end > len(buf) {
						end = len(buf)
					}
					line := buf[idx:end]
					if z := bytes.IndexAny(line, "\x00\r\n"); z >= 0 {
						line = line[:z]
					}
					out.InnoVersionHdr = string(line)
					break
				}
			}
		}
	}

	const win = 4 << 20
	if sz <= win*2 {
		scanWindow(0, sz)
	} else {
		scanWindow(0, win)
		scanWindow(sz-win, win)
	}
	return out
}
