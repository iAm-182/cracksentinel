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
)

var scriptExt = map[string]bool{
	".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".js": true,
	".jse": true, ".wsf": true, ".hta": true, ".scr": false,
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
	}
	head := make([]byte, 2)
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
		if bytes.Equal(head[:2], []byte("MZ")) {
			return KindPE
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
