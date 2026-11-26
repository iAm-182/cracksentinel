package filetype

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Kind int

const (
	KindUnknown Kind = iota
	KindPE
	KindScript
	KindArchive
	KindShortcut
	KindAsset
	KindDoc
	KindText
)

// textExt are files that hold text and cannot execute anything. A base64
// PowerShell command in a notes file is not a threat on its own: it only
// becomes one when the user renames it or pastes it somewhere runnable.
var textExt = map[string]bool{
	".txt": true, ".md": true, ".nfo": true, ".log": true, ".json": true,
	".xml": true, ".csv": true, ".ini": true, ".cfg": true, ".conf": true,
	".srt": true, ".sub": true, ".yaml": true, ".yml": true,
	".toml": true, ".htm": true, ".html": true,
	".list": true, ".sha": true, ".md5": true, ".sfv": true, ".cue": true,
}

var scriptExt = map[string]bool{
	".bat": true, ".cmd": true, ".ps1": true, ".psm1": true, ".psd1": true,
	".vbs": true, ".vbe": true, ".js": true, ".mjs": true, ".cjs": true,
	".jse": true, ".wsf": true, ".hta": true, ".py": true, ".pyw": true,
	".rpy": true, ".rpyc": true, ".lua": true, ".reg": true,
	".nsi": true, ".nsh": true, ".iss": true, ".au3": true, ".a3x": true,
}

var assetExt = map[string]bool{
	".pak": true, ".mp4": true, ".mkv": true, ".avi": true, ".wav": true,
	".uasset": true, ".bundle": true, ".bk2": true, ".png": true,
	".jpg": true, ".jpeg": true, ".dds": true, ".tga": true, ".fbx": true,
	".bank": true, ".wem": true, ".tex": true, ".asset": true,
}

var docExt = map[string]bool{
	".pdf": true, ".docm": true, ".xlsm": true, ".doc": true, ".xls": true,
	".docx": true, ".xlsx": true, ".pptx": true, ".pptm": true,
	".rtf": true, ".chm": true,
}

var containerExt = map[string]bool{
	".zip": true, ".7z": true, ".rar": true, ".iso": true, ".cab": true,
	".arj": true, ".tgz": true, ".tar": true, ".gz": true, ".xz": true,
	".bz2": true, ".msi": true, ".img": true, ".vhd": true, ".vhdx": true,
	".udf": true, ".asar": true, ".jar": true, ".ts4script": true,
}

var peNormalExt = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".ocx": true,
	".cpl": true, ".drv": true, ".efi": true, ".pyd": true, ".asi": true,
	".flt": true, ".ax": true, ".tsp": true, ".ime": true, ".com": true,
	".node": true, ".bin": true, ".tmp": true, "": true,
}

var (
	reMultiPartRar = regexp.MustCompile(`(?i)\.part0*([0-9]+)\.rar$`)
	reOldSplitRar  = regexp.MustCompile(`(?i)\.r[0-9]{2}$`)
	reSplitZip     = regexp.MustCompile(`(?i)\.z[0-9]{2}$`)
	reNumericSplit = regexp.MustCompile(`(?i)\.[0-9]{3}$`)
)

func IsContainerExt(path string) bool {
	return containerExt[strings.ToLower(filepath.Ext(path))]
}

// IsSecondaryMultiVolume reports whether path is part 2+ of a split archive
// (e.g. game.part2.rar, game.part02.rar, game.r00, game.z01, game.7z.002).
// Extracting part 1 already pulls in the whole volume set; expanding every
// secondary volume separately wastes time and produces misleading errors.
func IsSecondaryMultiVolume(path string) bool {
	base := filepath.Base(path)
	if m := reMultiPartRar.FindStringSubmatch(base); len(m) == 2 {
		return m[1] != "1"
	}
	if reOldSplitRar.MatchString(base) || reSplitZip.MatchString(base) {
		return true
	}
	if reNumericSplit.MatchString(base) && !strings.HasSuffix(strings.ToLower(base), ".001") {
		return true
	}
	return false
}

func IsFreeArc(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 4)
	n, _ := f.Read(b)
	return n == 4 && b[0] == 'A' && b[1] == 'r' && b[2] == 'C' && b[3] == 0x01
}

// HasValidPEHeader checks for a genuine DOS "MZ" header whose e_lfanew points
// to a "PE\x00\x00" NT signature. Unlike a bare "MZ" prefix check, this never
// trips on plain text notes that happen to start with the letters "MZ".
func HasValidPEHeader(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [64]byte
	n, err := f.Read(hdr[:])
	if err != nil && n < 64 {
		return false
	}
	if n < 64 || hdr[0] != 'M' || hdr[1] != 'Z' {
		return false
	}
	lfanew := int64(binary.LittleEndian.Uint32(hdr[0x3C:0x40]))
	if lfanew < 0x40 || lfanew > 16<<20 {
		return false
	}
	var sig [4]byte
	if m, _ := f.ReadAt(sig[:], lfanew); m < 4 {
		return false
	}
	return sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0
}

// IsDisguisedPE reports a genuine PE executable masquerading under a non-PE
// extension such as .txt, .png, .jpg, .pdf, .pak, .nfo, or .mp4.
func IsDisguisedPE(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if peNormalExt[ext] {
		return false
	}
	return HasValidPEHeader(path)
}

// ArchiveFormat detects container formats by magic bytes regardless of file extension.
func ArchiveFormat(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var head [32]byte
	n, _ := f.Read(head[:])
	if n >= 24 && binary.LittleEndian.Uint32(head[0:4]) == 4 {
		jLen := binary.LittleEndian.Uint32(head[12:16])
		if jLen >= 10 && jLen <= 64<<20 {
			rest := bytes.TrimLeft(head[16:n], " \t\r\n")
			if bytes.HasPrefix(rest, []byte(`{"files"`)) || bytes.HasPrefix(rest, []byte(`{"integrity"`)) {
				return "asar"
			}
		}
	}
	if n >= 4 {
		if head[0] == 'P' && head[1] == 'K' && (head[2] == 0x03 && head[3] == 0x04 || head[2] == 0x05 && head[3] == 0x06) {
			return "zip"
		}
		if head[0] == 'A' && head[1] == 'r' && head[2] == 'C' && head[3] == 0x01 {
			return "freearc"
		}
	}
	if n >= 6 && bytes.Equal(head[:6], []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) {
		return "7z"
	}
	if n >= 7 && bytes.Equal(head[:7], []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}) {
		return "rar"
	}
	if n >= 8 && bytes.Equal(head[:8], []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}) {
		return "rar"
	}
	if n >= 2 && head[0] == 0x1F && head[1] == 0x8B {
		return "gzip"
	}
	return ""
}

// IsExpandableContainer reports whether path is an archive either by extension
// or by magic bytes (excluding Office OOXML documents and game asset packs).
func IsExpandableContainer(path string) bool {
	if IsContainerExt(path) || IsFreeArc(path) {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	if docExt[ext] || assetExt[ext] || ext == ".jar" || ext == ".apk" {
		return ext == ".jar"
	}
	return ArchiveFormat(path) != ""
}

func Classify(path string) Kind {
	// Magic-byte check for genuine PE executables ALWAYS runs first so a
	// malware binary renamed to .txt, .png, or .pak cannot bypass PE analysis.
	if HasValidPEHeader(path) {
		return KindPE
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch {
	case assetExt[ext]:
		return KindAsset
	case docExt[ext]:
		return KindDoc
	case ext == ".lnk" || ext == ".url" || ext == ".pif":
		return KindShortcut
	case scriptExt[ext]:
		return KindScript
	case textExt[ext]:
		return KindText
	case containerExt[ext]:
		return KindArchive
	}
	head := make([]byte, 8)
	f, err := os.Open(path)
	if err != nil {
		if ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == ".cpl" || ext == ".ocx" {
			return KindPE
		}
		return KindUnknown
	}
	defer f.Close()
	n, _ := f.Read(head)
	if n >= 2 {
		if bytes.Equal(head[:2], []byte("MZ")) {
			return KindPE
		}
		if bytes.Equal(head[:2], []byte("PK")) {
			return KindArchive
		}
	}
	if n >= 4 && bytes.Equal(head[:4], []byte{0xD0, 0xCF, 0x11, 0xE0}) {
		return KindDoc
	}
	if ArchiveFormat(path) != "" {
		return KindArchive
	}
	if ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == ".cpl" || ext == ".ocx" {
		return KindPE
	}
	return KindUnknown
}
