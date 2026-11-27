package sysaudit

import (
	"os"
	"path/filepath"
	"strings"

	"gamecrack-scanner/internal/authenticode"
)

const cleanDiscordIndexJS = "module.exports = require('./core.asar');"

// scanClientIntegrity checks installed Discord and Steam clients for persistent
// post-infection tampering (e.g. PirateStealer/BlueTiger/Lumma Discord index.js
// token-stealer injection, or unsigned proxy DLL sideloading inside Steam's folder).
func scanClientIntegrity() (findings []Finding, checked int) {
	var roots []string
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		for _, client := range []string{"Discord", "DiscordPTB", "DiscordCanary", "Lightcord"} {
			d := filepath.Join(localApp, client)
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				roots = append(roots, d)
			}
		}
	}
	if appData := os.Getenv("APPDATA"); appData != "" {
		for _, client := range []string{"discord", "discordptb", "discordcanary"} {
			d := filepath.Join(appData, client)
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				roots = append(roots, d)
			}
		}
	}

	seenIdx := map[string]bool{}
	for _, r := range roots {
		filepath.WalkDir(r, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			low := strings.ToLower(path)
			if filepath.Base(low) == "index.js" && strings.Contains(low, "discord_desktop_core") {
				if seenIdx[low] {
					return nil
				}
				seenIdx[low] = true
				checked++
				if f, tampered := inspectDiscordIndexJS(path); tampered {
					findings = append(findings, f)
				}
			}
			return nil
		})
	}

	// Check Steam installation directories for unsigned proxy DLL sideloading next to steam.exe
	steamDirs := []string{
		`C:\Program Files (x86)\Steam`,
		`C:\Program Files\Steam`,
		`D:\Steam`,
		`E:\Steam`,
	}
	sideloadHijackDLLs := []string{
		"version.dll", "winmm.dll", "winhttp.dll", "hid.dll",
		"dinput8.dll", "dxgi.dll", "wtsapi32.dll", "userenv.dll",
		"profapi.dll", "cryptbase.dll", "dwmapi.dll", "uxtheme.dll",
	}
	for _, sd := range steamDirs {
		steamExe := filepath.Join(sd, "steam.exe")
		if _, err := os.Stat(steamExe); err != nil {
			continue
		}
		checked++
		for _, dllName := range sideloadHijackDLLs {
			dllPath := filepath.Join(sd, dllName)
			st, err := os.Stat(dllPath)
			if err != nil || st.IsDir() {
				continue
			}
			vr, verr := authenticode.Verify(dllPath)
			if verr == nil && vr.Status == authenticode.StatusIntact && !vr.SelfSigned {
				continue
			}
			findings = append(findings, Finding{
				Category:  "discord_steam",
				Risk:      "HIGH",
				Title:     "DLL Sideloading Pencuri Sesi Terdeteksi di Folder Steam (" + dllName + ")!",
				Location:  dllPath,
				Command:   "Unsigned system proxy DLL inside Steam root: " + dllPath,
				Reason:    "Ditemukan DLL proxy sistem tanpa tanda tangan digital resmi di folder utama Steam (teknik pembajakan sesi & token Steam)!",
				FixAction: "quarantine_file",
				FixTarget: dllPath,
				FixLabel:  "Karantina DLL Palsu",
			})
		}
	}

	return findings, checked
}

func inspectDiscordIndexJS(path string) (Finding, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Finding{}, false
	}
	content := strings.TrimSpace(string(b))
	// Strip UTF-8 BOM if present
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")
	content = strings.TrimSpace(content)

	// Normal clean Discord index.js is a single line: module.exports = require('./core.asar');
	normalized := strings.ReplaceAll(content, "\"", "'")
	normalized = strings.TrimSuffix(normalized, ";")
	normalized = strings.TrimSpace(normalized)
	if normalized == "module.exports = require('./core.asar')" {
		return Finding{}, false
	}

	preview := content
	if len(preview) > 180 {
		preview = preview[:180] + "..."
	}
	preview = strings.ReplaceAll(strings.ReplaceAll(preview, "\r", " "), "\n", " ")

	return Finding{
		Category:  "discord_steam",
		Risk:      "HIGH",
		Title:     "Aplikasi Discord Terinfeksi Script Pencuri Token (Discord Core Injection)!",
		Location:  path,
		Command:   preview,
		Reason:    "File index.js di dalam discord_desktop_core telah disuntik kode tambahan (pola PirateStealer/BlueTiger/Lumma) yang menyadap token, password, & kartu/billing Discord setiap kali aplikasi dibuka!",
		FixAction: "reset_discord_index",
		FixTarget: path,
		FixLabel:  "Bersihkan Injeksi Discord",
	}, true
}
