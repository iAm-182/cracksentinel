package unpack

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// asarNode represents one node in an Electron ASAR JSON archive header.
// Inspired by bkerler/asar_extract: hardened against forged/negative offsets,
// oversized JSON headers, and path-traversal entries ("..").
type asarNode struct {
	Files      map[string]*asarNode `json:"files,omitempty"`
	Size       int64                `json:"size,omitempty"`
	Offset     json.RawMessage      `json:"offset,omitempty"`
	Unpacked   bool                 `json:"unpacked,omitempty"`
	Executable bool                 `json:"executable,omitempty"`
}

// AsarEntry describes one file listed inside an Electron .asar archive.
type AsarEntry struct {
	RelPath string
	Offset  int64
	Size    int64
}

var asarScanExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".json": true, ".html": true, ".htm": true,
	".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".wsf": true, ".hta": true,
	".exe": true, ".dll": true, ".node": true, ".scr": true, ".py": true, ".nsi": true, ".iss": true,
}

// IsAsar checks whether path has a valid Chromium Pickle + JSON ASAR header.
func IsAsar(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [32]byte
	n, err := f.Read(hdr[:])
	if err != nil || n < 24 {
		return false
	}
	return isAsarHeaderBytes(hdr[:n])
}

func isAsarHeaderBytes(hdr []byte) bool {
	if len(hdr) < 24 {
		return false
	}
	// Chromium Pickle header layout:
	// [0:4]   uint32 = 4 (pickle payload size of first pickle)
	// [4:8]   uint32 = header pickle total size
	// [8:12]  uint32 = header pickle payload size
	// [12:16] uint32 = JSON string byte length
	// [16..]  JSON object starting with `{"files"`
	if binary.LittleEndian.Uint32(hdr[0:4]) != 4 {
		return false
	}
	jsonLen := binary.LittleEndian.Uint32(hdr[12:16])
	if jsonLen < 10 || jsonLen > 64<<20 {
		return false
	}
	rest := bytes.TrimLeft(hdr[16:], " \t\r\n")
	return bytes.HasPrefix(rest, []byte(`{"files"`)) || bytes.HasPrefix(rest, []byte(`{"integrity"`))
}

func parseAsarHeader(f *os.File) (*asarNode, int64, int64, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, 0, 0, err
	}
	fileSize := st.Size()
	if fileSize < 24 {
		return nil, 0, 0, fmt.Errorf("file too small for ASAR")
	}
	var pre [16]byte
	if _, err := io.ReadFull(f, pre[:]); err != nil {
		return nil, 0, 0, err
	}
	if binary.LittleEndian.Uint32(pre[0:4]) != 4 {
		return nil, 0, 0, fmt.Errorf("invalid ASAR pickle magic")
	}
	headerSize := int64(binary.LittleEndian.Uint32(pre[4:8]))
	jsonLen := int64(binary.LittleEndian.Uint32(pre[12:16]))
	if jsonLen < 2 || jsonLen > 32<<20 || 16+jsonLen > fileSize {
		return nil, 0, 0, fmt.Errorf("invalid ASAR JSON header size %d", jsonLen)
	}
	dataOffset := 8 + headerSize
	if dataOffset < 16+jsonLen || dataOffset > fileSize {
		// Fallback aligned calculation if tampered pickle size (bkerler/asar_extract trick)
		aligned := (jsonLen + 3) & ^int64(3)
		dataOffset = 16 + aligned
		if dataOffset > fileSize {
			return nil, 0, 0, fmt.Errorf("ASAR data offset out of bounds")
		}
	}
	jbuf := make([]byte, jsonLen)
	if _, err := f.ReadAt(jbuf, 16); err != nil {
		return nil, 0, 0, err
	}
	jbuf = bytes.TrimRight(jbuf, "\x00")
	var root asarNode
	if err := json.Unmarshal(jbuf, &root); err != nil {
		return nil, 0, 0, err
	}
	return &root, dataOffset, fileSize, nil
}

func parseAsarOffset(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		var v int64
		if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &v); err == nil && v >= 0 {
			return v, true
		}
		return 0, false
	}
	var v int64
	if err := json.Unmarshal(raw, &v); err == nil && v >= 0 {
		return v, true
	}
	return 0, false
}

// ListAsar enumerates all packed files inside an Electron .asar container.
func ListAsar(path string) (all []AsarEntry, extractable []AsarEntry, totalExtractBytes int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, err
	}
	defer f.Close()
	root, dataOffset, fileSize, err := parseAsarHeader(f)
	if err != nil {
		return nil, nil, 0, err
	}
	var walk func(prefix string, n *asarNode, depth int)
	walk = func(prefix string, n *asarNode, depth int) {
		if n == nil || depth > 24 || len(all) > 10000 {
			return
		}
		if len(n.Files) > 0 {
			for name, child := range n.Files {
				clean := sanitizeAsarSeg(name)
				if clean == "" {
					continue
				}
				rel := clean
				if prefix != "" {
					rel = prefix + "/" + clean
				}
				walk(rel, child, depth+1)
			}
			return
		}
		if n.Unpacked || n.Size <= 0 {
			return
		}
		off, ok := parseAsarOffset(n.Offset)
		if !ok || dataOffset+off < dataOffset || dataOffset+off+n.Size > fileSize {
			return
		}
		e := AsarEntry{RelPath: prefix, Offset: dataOffset + off, Size: n.Size}
		all = append(all, e)
		ext := strings.ToLower(filepath.Ext(prefix))
		if asarScanExts[ext] && n.Size <= 64<<20 {
			extractable = append(extractable, e)
			totalExtractBytes += n.Size
		}
	}
	walk("", root, 0)
	return all, extractable, totalExtractBytes, nil
}

// ExtractAsar extracts scannable code/scripts/binaries from an .asar archive into destDir.
func ExtractAsar(path, destDir string, maxBytes int64) (int, int64, error) {
	_, entries, _, err := ListAsar(path)
	if err != nil {
		return 0, 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	if maxBytes <= 0 {
		maxBytes = 256 << 20
	}
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return 0, 0, err
	}
	var written int64
	count := 0
	for _, e := range entries {
		if count >= 2500 || written+e.Size > maxBytes {
			break
		}
		outPath := filepath.Join(absDest, filepath.FromSlash(e.RelPath))
		if !strings.HasPrefix(strings.ToLower(outPath), strings.ToLower(absDest)+string(os.PathSeparator)) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			continue
		}
		w, err := os.Create(outPath)
		if err != nil {
			continue
		}
		sr := io.NewSectionReader(f, e.Offset, e.Size)
		n, _ := io.Copy(w, sr)
		w.Close()
		written += n
		count++
	}
	return count, written, nil
}

func sanitizeAsarSeg(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\\", "_"))
	s = strings.ReplaceAll(s, "/", "_")
	if s == "" || s == "." || s == ".." || strings.Contains(s, ":") {
		return ""
	}
	return s
}
