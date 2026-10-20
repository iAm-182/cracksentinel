package filetype

import (
	"bytes"
	"os"
	"path/filepath"
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
	".reg": true, ".srt": true, ".sub": true, ".yaml": true, ".yml": true,
	".toml": true, ".htm": true, ".html": true, ".rtf": true, ".url": true,
	".list": true, ".sha": true, ".md5": true, ".sfv": true, ".cue": true,
}

var scriptExt = map[string]bool{
	".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".js": true,
	".jse": true, ".wsf": true, ".hta": true,
}

var assetExt = map[string]bool{
	".pak": true, ".mp4": true, ".mkv": true, ".avi": true, ".wav": true,
	".uasset": true, ".bundle": true, ".bk2": true, ".png": true,
	".jpg": true, ".jpeg": true, ".dds": true, ".tga": true, ".fbx": true,
	".bank": true, ".wem": true, ".tex": true, ".asset": true,
}

var docExt = map[string]bool{
	".pdf": true, ".docm": true, ".xlsm": true, ".doc": true, ".xls": true,
	".rtf": true, ".chm": true,
}

var containerExt = map[string]bool{
	".zip": true, ".7z": true, ".rar": true, ".iso": true, ".cab": true,
	".arj": true, ".tgz": true, ".tar": true,
}

func IsContainerExt(path string) bool {
	return containerExt[strings.ToLower(filepath.Ext(path))]
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

func Classify(path string) Kind {
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
		// .7z/.rar/.iso/.cab/.tar have no reliable magic byte, so the
		// extension is the only signal. Without this they land in
		// KindUnknown and the archive rule set never fires.
		return KindArchive
	}
	head := make([]byte, 4)
	f, err := os.Open(path)
	if err != nil {
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
		if bytes.Equal(head[1:2], []byte{0x00}) && (head[0] == 0xD0 || head[0] == 0xCF) {
			return KindDoc
		}
	}
	if ext == ".exe" || ext == ".dll" || ext == ".sys" {
		return KindPE
	}
	return KindUnknown
}
