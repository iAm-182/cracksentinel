package rules

import (
	"regexp"
	"strings"

	"gamecrack-scanner/internal/filetype"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/pe"
)

type importIOC struct {
	funcs    []string
	category string
	severity int
	desc     string
}

var importIOCs = map[string]importIOC{
	"keylogger": {
		funcs:    []string{"GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW", "GetKeyboardState", "GetKeyState", "GetRawInputData", "RegisterRawInputDevices", "MapVirtualKeyA", "GetForegroundWindow"},
		category: "keylogger",
		severity: 30,
		desc:     "keyboard/input capture API",
	},
	"injection": {
		funcs:    []string{"WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "VirtualProtectEx", "NtUnmapViewOfSection", "SetThreadContext", "QueueUserAPC", "RtlMoveMemory"},
		category: "injection",
		severity: 30,
		desc:     "process injection API",
	},
	"credential": {
		funcs:    []string{"CryptUnprotectData", "CredEnumerateA", "CredEnumerateW", "LsaEnumerateLogonSessions", "CredReadA"},
		category: "stealer",
		severity: 25,
		desc:     "credential/cookie decryption API",
	},
	"exfil": {
		funcs:    []string{"URLDownloadToFile", "InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA", "InternetReadFile", "WSAStartup", "send", "connect"},
		category: "network",
		severity: 12,
		desc:     "network/exfil API",
	},
	"clipboard": {
		funcs:    []string{"GetClipboardData", "OpenClipboard", "EmptyClipboard"},
		category: "stealer",
		severity: 15,
		desc:     "clipboard access API",
	},
	"persistence": {
		funcs:    []string{"RegSetValueExA", "RegSetValueExW", "CreateServiceA", "StartServiceA"},
		category: "persistence",
		severity: 12,
		desc:     "persistence API",
	},
	"destructive": {
		funcs:    []string{"CryptEncrypt", "CryptGenKey", "FindFirstFileA", "MoveFileA", "DeleteFileA"},
		category: "ransomware",
		severity: 8,
		desc:     "file/encryption API (ransomware-ish)",
	},
}

var stealerCombo = model.Finding{
	Rule:     "combo_stealer_stack",
	Category: "stealer",
	Severity: 25,
	Detail:   "browser credential + clipboard + network APIs combined (classic stealer stack)",
}

var reDiscord = regexp.MustCompile(`https://(discordapp\.com|discord\.com)/api/webhooks/\d{17,20}/[\w-]{60,90}`)
var reTelegram = regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{30,45}\b`)
var reEncoded = regexp.MustCompile(`(?i)(-e|-enc|-encodedcommand)\s*[A-Za-z0-9+/=]{40,}`)
var reCradle = regexp.MustCompile(`(?i)(curl|wget|Invoke-WebRequest|Invoke-Expression|iex|certutil|bitsadmin|mshta|regsvr32)\s+[^\r\n]{0,120}https?://`)
var reIPPort = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b`)
var reBase64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)
var reWallet = regexp.MustCompile(`(?i)(wallet\.dat|metamask|exodus|electrum|seed phrase|mnemonic|Login Data|cookies\.sqlite|passwords\.txt|autofill)`)
var reKeylogWord = regexp.MustCompile(`(?i)(keylog|keystroke|clipboard ?grab|grabber|stealer|exfiltrat)`)
var reRunKey = regexp.MustCompile(`(?i)(CurrentVersion\\\\Run|schtasks\s+/create|New-Service|reg\s+add\s+HKLM)`)
var reVM = regexp.MustCompile(`(?i)(vmware|virtualbox|vbox|sandboxie|wine[^a-z])`)

var scriptKeywords = []string{
	"getasynckeystate", "setwindowshookex", "cryptunprotectdata",
	"login data", "wallet.dat", "discord.com/api/webhooks",
	"start-process -windowstyle hidden", "-windowstyle hidden",
	"copy-item $env:", "appdata\\local\\google\\chrome",
}

var crackWhitelist = []string{
	"RUNE", "Goldberg", "SmartSteamEmu", "SmartSteam", "FLT", "ALI213",
	"HOODLUM", "CODEX", "CPY", "SKIDROW", "RELOADED", "PLAZA", "TENOKE",
	"steam_emu", "ColdClientLoader", "creamlab",
}

// strongStringIOCs are string-level findings that veto the emulator-cap below:
// a trojanized emu almost always adds one of these (C2 URL, encoded command,
// credential targets). Import-only findings don't veto — hooking imports are
// core emulator behavior.
var strongStringIOCs = map[string]bool{
	"discord_webhook": true, "telegram_token": true, "ps_encoded": true,
	"download_cradle": true, "ip_port": true, "wallet_browser_target": true,
	"keylog_word": true, "keylog_word2": true, "persistence_string": true,
}

type MatchInput struct {
	Kind  filetype.Kind
	PE    *pe.Info
	Strs  []string
	Bytes []byte
}

func Match(in MatchInput) (findings []model.Finding, whitelistHits []string) {
	if in.PE != nil {
		findings = append(findings, matchImports(in.PE)...)
	}
	findings = append(findings, matchStrings(in.Strs)...)
	findings = append(findings, matchBytes(in.Bytes)...)
	whitelistHits = matchWhitelist(in.Strs)
	if isEmuLike(in.Strs, findings) {
		whitelistHits = append(whitelistHits, "EMU_STEAMAPI")
	}
	if len(findings) == 0 && len(whitelistHits) > 0 {
		findings = append(findings, model.Finding{
			Rule:     "crack_whitelist",
			Category: "info",
			Severity: 0,
			Detail:   "known crack/emulator signature: " + strings.Join(whitelistHits, ", "),
		})
	}
	return findings, whitelistHits
}

func matchImports(info *pe.Info) []model.Finding {
	var out []model.Finding
	flat := map[string]bool{}
	for _, funcs := range info.Imports {
		for _, fn := range funcs {
			flat[strings.ToLower(fn)] = true
		}
	}
	cats := map[string]bool{}
	for name, ioc := range importIOCs {
		var hit []string
		for _, fn := range ioc.funcs {
			if flat[strings.ToLower(fn)] {
				hit = append(hit, fn)
			}
		}
		if len(hit) > 0 {
			out = append(out, model.Finding{
				Rule:     "imp_" + name,
				Category: ioc.category,
				Severity: ioc.severity,
				Detail:   ioc.desc + ": " + strings.Join(hit, ", "),
			})
			cats[name] = true
		}
	}
	if cats["credential"] && cats["clipboard"] && cats["exfil"] {
		out = append(out, stealerCombo)
	}
	if cats["keylogger"] && cats["exfil"] {
		out = append(out, model.Finding{
			Rule:     "combo_keylog_exfil",
			Category: "keylogger",
			Severity: 20,
			Detail:   "keylogger API + network exfil API combined",
		})
	}
	if info.Packer != "" {
		sev := 15
		if info.Packer == "unknown(entropy)" {
			sev = 8
		}
		out = append(out, model.Finding{
			Rule:     "packer",
			Category: "packing",
			Severity: sev,
			Detail:   "packer/obfuscation: " + info.Packer,
		})
	}
	if info.Dotnet {
		out = append(out, model.Finding{
			Rule:     "dotnet",
			Category: "info",
			Severity: 2,
			Detail:   ".NET assembly (decompile with ilspy/dnspy for review)",
		})
	}
	return out
}

func matchStrings(strs []string) []model.Finding {
	var out []model.Finding
	seen := map[string]int{}
	for _, s := range strs {
		l := strings.ToLower(s)
		switch {
		case reDiscord.MatchString(s):
			add(&out, seen, "discord_webhook", "c2", 40, "Discord webhook URL: "+trunc(s, 80))
		case reTelegram.MatchString(s):
			add(&out, seen, "telegram_token", "c2", 35, "Telegram bot token: "+trunc(s, 50))
		}
		switch {
		case reEncoded.MatchString(s):
			add(&out, seen, "ps_encoded", "evasion", 30, "PowerShell encoded command: "+trunc(s, 100))
		case reCradle.MatchString(s):
			add(&out, seen, "download_cradle", "dropper", 20, "download cradle: "+trunc(s, 100))
		case reIPPort.MatchString(s):
			add(&out, seen, "ip_port", "c2", 10, "hardcoded IP:port: "+s)
		case reWallet.MatchString(l):
			add(&out, seen, "wallet_browser_target", "stealer", 15, "browser/wallet target string: "+trunc(s, 60))
		case reKeylogWord.MatchString(l):
			add(&out, seen, "keylog_word", "keylogger", 12, "keylogger terminology: "+trunc(s, 60))
		case reRunKey.MatchString(s):
			add(&out, seen, "persistence_string", "persistence", 15, "persistence string: "+trunc(s, 80))
		case reVM.MatchString(l):
			add(&out, seen, "sandbox_check", "evasion", 8, "sandbox/VM detection string: "+trunc(s, 60))
		case reBase64Blob.MatchString(s):
			add(&out, seen, "base64_blob", "evasion", 6, "large base64 blob (len "+itoa(len(s))+")")
		}
		if len(s) >= 4 && strings.Contains(l, "asynckeystate") {
			add(&out, seen, "keylog_word2", "keylogger", 5, "keylog API referenced in string: "+trunc(s, 60))
		}
	}
	return out
}

func matchBytes(b []byte) []model.Finding {
	var out []model.Finding
	for _, pat := range []struct {
		name string
		hex  []byte
		cat  string
		sev  int
		desc string
	}{
		{"eicar", []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), "testfile", 100, "EICAR antivirus test file"},
	} {
		if len(b) > 0 && bytesContains(b, pat.hex) {
			out = append(out, model.Finding{Rule: pat.name, Category: pat.cat, Severity: pat.sev, Detail: pat.desc})
		}
	}
	return out
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// isEmuLike reports whether the file looks like a Steam emulator DLL (TENOKE /
// Goldberg style): dominated by SteamAPI exports with no exfil/payload string
// IOCs. Hooking imports (WriteProcessMemory, SetWindowsHookEx) are normal emu
// behavior, so they don't veto — but any strong string IOC does, because a
// trojanized twin needs payload strings (C2 URLs, encoded commands, paths).
func isEmuLike(strs []string, findings []model.Finding) bool {
	emu := 0
	for _, s := range strs {
		if strings.Contains(s, "SteamAPI_") {
			emu++
			if emu >= 50 {
				break
			}
		}
	}
	if emu < 50 {
		return false
	}
	for _, f := range findings {
		if strongStringIOCs[f.Rule] {
			return false
		}
	}
	return true
}

func matchWhitelist(strs []string) []string {
	var hits []string
	seen := map[string]bool{}
	for _, s := range strs {
		for _, w := range crackWhitelist {
			if strings.Contains(s, w) && !seen[w] {
				seen[w] = true
				hits = append(hits, w)
			}
		}
	}
	return hits
}

func add(out *[]model.Finding, seen map[string]int, rule, cat string, sev int, detail string) {
	if seen[rule] >= 2 {
		return
	}
	seen[rule]++
	*out = append(*out, model.Finding{Rule: rule, Category: cat, Severity: sev, Detail: detail})
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
