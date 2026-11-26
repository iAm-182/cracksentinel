package unpack

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// JavaJarReport summarizes static inspection of Java .jar / .class mods (e.g.
// Minecraft Forge/Fabric/Bukkit mods — inspired by KosmX/jneedle & Fractureiser
// detectors) and Sims 4 .ts4script (ZIP of .pyc bytecode) archives.
type JavaJarReport struct {
	ClassCount       int
	PycCount         int
	ExtractedStrings []string
	HasExecOrNetAPI  bool
	FractureiserLike bool
}

// InspectJarOrModZip parses Java `.class` Constant Pools (`CONSTANT_Utf8` tag 1)
// and Python `.pyc` / `MANIFEST.MF` entries directly inside `.jar` or `.ts4script`
// archives without requiring a JVM or writing class files to disk.
func InspectJarOrModZip(path string, maxClasses int) (*JavaJarReport, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	if maxClasses <= 0 {
		maxClasses = 600
	}

	rep := &JavaJarReport{}
	seen := map[string]bool{}
	addStr := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) >= 5 && len(s) <= 1024 && !seen[s] && len(rep.ExtractedStrings) < 12000 {
			seen[s] = true
			rep.ExtractedStrings = append(rep.ExtractedStrings, s)
		}
	}

	var hasURLClassLoader, hasRuntimeExec, hasBase64OrDiscord bool

	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || zf.UncompressedSize64 > 8<<20 {
			continue
		}
		ext := strings.ToLower(filepath.Ext(zf.Name))
		base := strings.ToLower(filepath.Base(zf.Name))
		if ext != ".class" && ext != ".pyc" && base != "manifest.mf" && ext != ".json" && ext != ".toml" {
			continue
		}
		if ext == ".class" && rep.ClassCount >= maxClasses {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 4<<20))
		rc.Close()
		if err != nil || len(raw) < 10 {
			continue
		}

		if ext == ".class" {
			rep.ClassCount++
			cpStrs := parseJavaClassConstantPool(raw)
			for _, cs := range cpStrs {
				low := strings.ToLower(cs)
				if strings.Contains(low, "java/net/urlclassloader") || strings.Contains(low, "defineclass") {
					hasURLClassLoader = true
				}
				if strings.Contains(low, "java/lang/runtime") || strings.Contains(low, "java/lang/processbuilder") || strings.Contains(low, "getruntime") {
					hasRuntimeExec = true
				}
				if strings.Contains(low, "discord") || strings.Contains(low, "webhooks") || strings.Contains(low, "telegram") ||
					strings.Contains(low, "app_bound_encrypted_key") || strings.Contains(low, "login data") || strings.Contains(low, " powershell") ||
					strings.Contains(low, "cmd.exe") || strings.Contains(low, "http://") || strings.Contains(low, "https://") {
					hasBase64OrDiscord = true
				}
				// Filter noisy Java stdlib internal descriptors unless URL/command/suspicious
				if isInterestingJavaString(cs) {
					addStr(cs)
				}
			}
		} else {
			if ext == ".pyc" {
				rep.PycCount++
			}
			for _, ps := range extractPrintableStrings(raw, 6) {
				addStr(ps)
			}
		}
	}

	rep.HasExecOrNetAPI = hasRuntimeExec || hasURLClassLoader
	if (hasRuntimeExec || hasURLClassLoader) && hasBase64OrDiscord {
		rep.FractureiserLike = true
	}
	return rep, nil
}

// parseJavaClassConstantPool parses JVM `.class` (`0xCAFEBABE`) Constant Pool entries
// and returns all `CONSTANT_Utf8` (tag 1) strings.
func parseJavaClassConstantPool(b []byte) []string {
	if len(b) < 10 || binary.BigEndian.Uint32(b[0:4]) != 0xCAFEBABE {
		return nil
	}
	cpCount := int(binary.BigEndian.Uint16(b[8:10]))
	if cpCount <= 1 || cpCount > 16384 {
		return nil
	}
	pos := 10
	var out []string
	for idx := 1; idx < cpCount && pos < len(b); idx++ {
		tag := b[pos]
		pos++
		switch tag {
		case 1: // CONSTANT_Utf8: uint16 length + bytes
			if pos+2 > len(b) {
				return out
			}
			ln := int(binary.BigEndian.Uint16(b[pos : pos+2]))
			pos += 2
			if pos+ln > len(b) {
				return out
			}
			if ln >= 4 && ln <= 1024 {
				out = append(out, string(b[pos:pos+ln]))
			}
			pos += ln
		case 3, 4: // Integer, Float
			pos += 4
		case 5, 6: // Long, Double (takes 2 constant pool slots!)
			pos += 8
			idx++
		case 7, 8, 16, 19, 20: // Class, String, MethodType, Module, Package
			pos += 2
		case 9, 10, 11, 12, 17, 18: // Fieldref, Methodref, InterfaceMethodref, NameAndType, Dynamic, InvokeDynamic
			pos += 4
		case 15: // MethodHandle
			pos += 3
		default:
			// Unknown constant pool tag — stop parsing cleanly
			return out
		}
	}
	return out
}

func isInterestingJavaString(s string) bool {
	if strings.HasPrefix(s, "(") || strings.HasPrefix(s, "[L") {
		return false
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "java/lang/object") || strings.HasPrefix(low, "java/util/") || strings.HasPrefix(low, "org/objectweb/") {
		return false
	}
	return true
}

// InspectRpyc extracts readable strings from compiled Ren'Py `.rpyc` scripts
// (which start with `"RENPY RPC2"` slot table followed by `zlib`-compressed AST).
func InspectRpyc(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < 32 {
		return nil
	}
	if !bytes.HasPrefix(raw, []byte("RENPY RPC2")) {
		return nil
	}
	// Slot 1 offset & length sit at bytes [10..22] (slot id=1, start uint32, len uint32)
	var out []string
	pos := 10
	for slot := 0; slot < 4 && pos+12 <= len(raw); slot++ {
		slotID := binary.LittleEndian.Uint32(raw[pos : pos+4])
		start := int(binary.LittleEndian.Uint32(raw[pos+4 : pos+8]))
		length := int(binary.LittleEndian.Uint32(raw[pos+8 : pos+12]))
		pos += 12
		if slotID == 0 {
			break
		}
		if start > 0 && length > 0 && start+length <= len(raw) && length <= 4<<20 {
			if plain, ok := tryZlibDecompress(raw[start : start+length]); ok {
				out = append(out, extractPrintableStrings(plain, 6)...)
			}
		}
	}
	return out
}

func tryZlibDecompress(comp []byte) ([]byte, bool) {
	zr, err := zlibReader(comp)
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	dec, err := io.ReadAll(io.LimitReader(zr, 4<<20))
	return dec, err == nil && len(dec) > 0
}
