package unpack

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TorrentFileEntry describes one file inside a .torrent metadata tree.
type TorrentFileEntry struct {
	RelPath string
	Size    int64
}

// TorrentFinding represents a security finding detected from a .torrent file's metadata before downloading.
type TorrentFinding struct {
	Rule     string
	Category string
	Severity int
	Detail   string
}

// TorrentReport summarizes the pre-download inspection of a BitTorrent (.torrent) file.
type TorrentReport struct {
	Valid            bool
	Name             string
	Comment          string
	CreatedBy        string
	TotalSize        int64
	FileCount        int
	Files            []TorrentFileEntry
	Trackers         []string
	ExtractedStrings []string
	Findings         []TorrentFinding
}

// InspectTorrent parses a Bencode .torrent file in pure Go and inspects its
// file tree, file sizes, and tracker metadata to catch fake game torrents,
// bloated .lnk shortcuts, script droppers, and decoy Ren'Py templates BEFORE
// the user downloads gigabytes in qBittorrent/uTorrent.
func InspectTorrent(path string) (*TorrentReport, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 16 || b[0] != 'd' {
		return nil, errors.New("not a valid Bencode .torrent dictionary")
	}
	val, _, err := parseBencode(b, 0, 0)
	if err != nil {
		return nil, err
	}
	root, ok := val.(map[string]any)
	if !ok {
		return nil, errors.New("top-level Bencode value is not a dictionary")
	}
	infoMap, ok := root["info"].(map[string]any)
	if !ok {
		return nil, errors.New("missing torrent info dictionary")
	}

	rep := &TorrentReport{Valid: true}
	rep.Name, _ = infoMap["name"].(string)
	rep.Comment, _ = root["comment"].(string)
	rep.CreatedBy, _ = root["created by"].(string)

	if ann, ok := root["announce"].(string); ok && ann != "" {
		rep.Trackers = append(rep.Trackers, ann)
	}
	if al, ok := root["announce-list"].([]any); ok {
		for _, tier := range al {
			if tlist, ok := tier.([]any); ok {
				for _, u := range tlist {
					if us, ok := u.(string); ok && us != "" && len(rep.Trackers) < 32 {
						rep.Trackers = append(rep.Trackers, us)
					}
				}
			}
		}
	}

	if rep.Name != "" {
		rep.ExtractedStrings = append(rep.ExtractedStrings, rep.Name)
	}
	if rep.Comment != "" {
		rep.ExtractedStrings = append(rep.ExtractedStrings, rep.Comment)
	}
	if rep.CreatedBy != "" {
		rep.ExtractedStrings = append(rep.ExtractedStrings, rep.CreatedBy)
	}
	rep.ExtractedStrings = append(rep.ExtractedStrings, rep.Trackers...)

	// Extract single-file or multi-file tree
	if filesRaw, ok := infoMap["files"].([]any); ok {
		for _, item := range filesRaw {
			fm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			sz, _ := fm["length"].(int64)
			var parts []string
			if plist, ok := fm["path"].([]any); ok {
				for _, seg := range plist {
					if s, ok := seg.(string); ok && s != "" {
						parts = append(parts, s)
					}
				}
			}
			rel := strings.Join(parts, "/")
			if rel == "" {
				continue
			}
			rep.TotalSize += sz
			rep.FileCount++
			if len(rep.Files) < 2500 {
				rep.Files = append(rep.Files, TorrentFileEntry{RelPath: rel, Size: sz})
				rep.ExtractedStrings = append(rep.ExtractedStrings, rel)
			}
		}
	} else if singleLen, ok := infoMap["length"].(int64); ok {
		rep.TotalSize = singleLen
		rep.FileCount = 1
		name := rep.Name
		if name == "" {
			name = filepath.Base(path)
		}
		rep.Files = append(rep.Files, TorrentFileEntry{RelPath: name, Size: singleLen})
	}

	evaluateTorrentHeuristics(rep)
	return rep, nil
}

func evaluateTorrentHeuristics(rep *TorrentReport) {
	if len(rep.Files) == 0 {
		return
	}
	var (
		hasLNK           string
		inflatedLNK      string
		inflatedLNKSize  int64
		hasScriptDropper string
		hasDoubleExt     string
		hasExecOrArchive string
		hasRenpyDir      bool
		hasRenpyLib      bool
		hasGameDir       bool
		suspiciousBlob   string
		blobSize         int64
	)

	for _, f := range rep.Files {
		low := strings.ToLower(strings.ReplaceAll(f.RelPath, "\\", "/"))
		base := filepath.Base(low)
		ext := filepath.Ext(base)

		if hasTorrentDoubleExt(base) && hasDoubleExt == "" {
			hasDoubleExt = f.RelPath
		}

		switch ext {
		case ".lnk", ".pif", ".url":
			if hasLNK == "" {
				hasLNK = f.RelPath
			}
			if f.Size >= 1024*1024 && inflatedLNK == "" {
				inflatedLNK = f.RelPath
				inflatedLNKSize = f.Size
			}
		case ".hta", ".vbs", ".vbe", ".jse", ".wsf", ".scr", ".cpl":
			if hasScriptDropper == "" {
				hasScriptDropper = f.RelPath
			}
		case ".bat", ".cmd", ".ps1":
			// Flag root-level or small-torrent batch/PowerShell launchers
			if rep.TotalSize < 120*1024*1024 && hasScriptDropper == "" {
				hasScriptDropper = f.RelPath
			}
		case ".exe", ".msi", ".iso", ".rar", ".zip", ".7z":
			if hasExecOrArchive == "" {
				hasExecOrArchive = f.RelPath
			}
		}

		// Decoy Ren'Py check inside .torrent file tree
		if strings.HasPrefix(low, "renpy/") || strings.Contains(low, "/renpy/") {
			hasRenpyDir = true
		}
		if strings.Contains(low, "librenpython.dll") {
			hasRenpyLib = true
		}
		if strings.HasPrefix(low, "game/") || strings.Contains(low, "/game/") {
			hasGameDir = true
		}
		if (strings.HasPrefix(low, "data/") || strings.Contains(low, "/data/")) && f.Size >= 500*1024 {
			switch ext {
			case ".pak", ".rpa", ".rpy", ".rpyc", ".png", ".jpg", ".ogg", ".wav", ".mp3", ".mp4", ".ttf", ".json", ".txt":
			default:
				suspiciousBlob = f.RelPath
				blobSize = f.Size
			}
		}
	}

	if inflatedLNK != "" {
		rep.Findings = append(rep.Findings, TorrentFinding{
			Rule:     "lnk_size_inflated",
			Category: "evasion",
			Severity: 50,
			Detail:   fmt.Sprintf(".torrent payload contains artificially bloated .lnk shortcut %q (%.1f MB) masquerading as game setup", inflatedLNK, float64(inflatedLNKSize)/(1<<20)),
		})
	}

	if hasDoubleExt != "" || hasLNK != "" || hasScriptDropper != "" {
		sample := hasDoubleExt
		why := "double-extension executable"
		if sample == "" && hasLNK != "" {
			sample = hasLNK
			why = "Windows .lnk shortcut launcher"
		}
		if sample == "" && hasScriptDropper != "" {
			sample = hasScriptDropper
			why = "script/LOLBin dropper"
		}
		rep.Findings = append(rep.Findings, TorrentFinding{
			Rule:     "torrent_shortcut_or_script_dropper",
			Category: "dropper",
			Severity: 65,
			Detail:   fmt.Sprintf("fake/trojanized .torrent payload contains %s (%q) — legitimate game torrents do not distribute shortcut/script droppers", why, sample),
		})
	}

	if (hasRenpyDir || hasRenpyLib) && !hasGameDir && suspiciousBlob != "" {
		rep.Findings = append(rep.Findings, TorrentFinding{
			Rule:     "torrent_decoy_renpy_dropper",
			Category: "dropper",
			Severity: 75,
			Detail:   fmt.Sprintf("decoy Ren'Py SDK game torrent detected BEFORE download: no game/ directory, carries encrypted payload blob %q (%.1f MB)", suspiciousBlob, float64(blobSize)/(1<<20)),
		})
	}

	// Tiny fake repack torrent: claims to be a game/repack or ships a tiny standalone .exe/.iso (< 45 MB)
	if rep.TotalSize > 0 && rep.TotalSize < 45*1024*1024 && hasExecOrArchive != "" {
		lowName := strings.ToLower(rep.Name)
		looksLikeGameClaim := rep.FileCount <= 3 ||
			strings.Contains(lowName, "repack") || strings.Contains(lowName, "fitgirl") ||
			strings.Contains(lowName, "dodi") || strings.Contains(lowName, "setup") ||
			strings.Contains(lowName, "crack") || strings.Contains(lowName, "edition") ||
			strings.Contains(lowName, "goty") || strings.Contains(lowName, "game")
		if looksLikeGameClaim {
			rep.Findings = append(rep.Findings, TorrentFinding{
				Rule:     "torrent_tiny_fake_repack",
				Category: "dropper",
				Severity: 55,
				Detail:   fmt.Sprintf(".torrent total payload is only %.2f MB (%d file(s), %q) — classic fake-repack / malware dropper torrent", float64(rep.TotalSize)/(1<<20), rep.FileCount, hasExecOrArchive),
			})
		}
	}
}

func hasTorrentDoubleExt(name string) bool {
	parts := strings.Split(strings.ToLower(name), ".")
	if len(parts) < 3 {
		return false
	}
	prev := "." + parts[len(parts)-2]
	last := "." + parts[len(parts)-1]
	docOrMedia := map[string]bool{
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".png": true, ".jpg": true, ".jpeg": true, ".mp4": true, ".mkv": true,
		".txt": true, ".nfo": true, ".iso": true, ".rar": true, ".zip": true,
	}
	execs := map[string]bool{
		".exe": true, ".scr": true, ".bat": true, ".cmd": true, ".vbs": true,
		".ps1": true, ".hta": true, ".js": true, ".lnk": true, ".com": true,
	}
	return docOrMedia[prev] && execs[last]
}

// Pure-Go recursive Bencode parser with strict depth & allocation bounds.
func parseBencode(b []byte, pos int, depth int) (any, int, error) {
	if depth > 32 {
		return nil, pos, errors.New("bencode nesting too deep")
	}
	if pos >= len(b) {
		return nil, pos, errors.New("unexpected EOF in bencode")
	}
	switch b[pos] {
	case 'i':
		end := pos + 1
		for end < len(b) && b[end] != 'e' {
			end++
		}
		if end >= len(b) {
			return nil, pos, errors.New("unterminated bencode integer")
		}
		n, err := strconv.ParseInt(string(b[pos+1:end]), 10, 64)
		if err != nil {
			return nil, pos, err
		}
		return n, end + 1, nil

	case 'l':
		pos++
		var list []any
		for pos < len(b) && b[pos] != 'e' {
			item, next, err := parseBencode(b, pos, depth+1)
			if err != nil {
				return nil, pos, err
			}
			list = append(list, item)
			pos = next
		}
		if pos >= len(b) {
			return nil, pos, errors.New("unterminated bencode list")
		}
		return list, pos + 1, nil

	case 'd':
		pos++
		dict := make(map[string]any)
		for pos < len(b) && b[pos] != 'e' {
			kRaw, next, err := parseBencode(b, pos, depth+1)
			if err != nil {
				return nil, pos, err
			}
			kStr, ok := kRaw.(string)
			if !ok {
				return nil, pos, errors.New("bencode dict key is not a string")
			}
			// Skip raw SHA-1 "pieces" blob storage to keep memory usage tiny
			val, next2, err := parseBencode(b, next, depth+1)
			if err != nil {
				return nil, next, err
			}
			if kStr != "pieces" {
				dict[kStr] = val
			}
			pos = next2
		}
		if pos >= len(b) {
			return nil, pos, errors.New("unterminated bencode dict")
		}
		return dict, pos + 1, nil

	default:
		if b[pos] < '0' || b[pos] > '9' {
			return nil, pos, fmt.Errorf("invalid bencode token %q at %d", b[pos], pos)
		}
		colon := pos
		for colon < len(b) && b[colon] >= '0' && b[colon] <= '9' {
			colon++
		}
		if colon >= len(b) || b[colon] != ':' {
			return nil, pos, errors.New("invalid bencode string length")
		}
		strLen, err := strconv.Atoi(string(b[pos:colon]))
		if err != nil || strLen < 0 || colon+1+strLen > len(b) {
			return nil, pos, errors.New("bencode string out of bounds")
		}
		start := colon + 1
		return string(b[start : start+strLen]), start + strLen, nil
	}
}
