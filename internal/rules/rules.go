package rules

import (
	"path/filepath"
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

// scriptRules are kind-specific indicators for script payloads (.bat/.cmd/
// .ps1/.vbs/.js/.hta). A script has no import table, so its behaviour is
// described by the APIs and paths it mentions — these rules are the script
// equivalent of the PE import-IOC table.
type keywordRule struct {
	rule     string
	category string
	severity int
	desc     string
	any      []string // match if ANY needle appears
	all      []string // match if ALL needles appear
}

var scriptRules = []keywordRule{
	{
		rule: "script_hidden_exec", category: "evasion", severity: 25,
		desc: "hidden-window execution",
		any: []string{
			"start-process -windowstyle hidden", "-windowstyle hidden",
			"-w hidden", "windowstylehidden", "createobject(\"wscript.shell\")",
			"wscript.shell", "wscript.shell.run", "shell.application",
		},
	},
	{
		rule: "script_cred_paths", category: "stealer", severity: 20,
		desc: "browser/profile credential path access",
		any: []string{
			"copy-item $env:", "copy-item", "appdata\\local\\google\\chrome",
			"appdata\\roaming\\mozilla", "login data", "cookies.sqlite",
			"\\google\\chrome\\user data", "web data", "local state",
		},
	},
	{
		rule: "script_hook_api", category: "keylogger", severity: 20,
		desc: "keylogging/credential-decryption API referenced",
		any: []string{
			"getasynckeystate", "setwindowshookex", "getkeystate",
			"cryptunprotectdata", "getforegroundwindow", "getkeyboardstate",
		},
	},
	{
		rule: "script_download_exec", category: "dropper", severity: 30,
		desc: "download-and-execute pattern",
		all:  []string{"iex"},
		any: []string{
			"downloadstring", "downloadfile", "invoke-webrequest",
			"system.net.webclient", "net.webclient", "mshta http",
			"certutil -urlcache", "bitsadmin /transfer",
		},
	},
	{
		rule: "script_exfil", category: "c2", severity: 20,
		desc: "outbound exfiltration channel",
		any: []string{
			"invoke-webrequest", "system.net.webclient", "uploadstring",
			"uploadfile", "send-mailmessage", "smtpclient", "httpwebrequest",
			"curl -s", "wget -q",
		},
	},
	{
		rule: "script_defender_bypass", category: "evasion", severity: 30,
		desc: "AV/EDR tampering",
		any: []string{
			"set-mppreference", "disable-realtimemonitoring", "disable-realtime-monitoring",
			"amsiutils", "amsiinitfailed", "add-mppreference", "-exclusionpath",
			"windows defender", "amsi.dll", "amsiutils.dll",
		},
	},
	{
		rule: "script_obfuscation", category: "evasion", severity: 15,
		desc: "script obfuscation / encoded payload",
		any: []string{
			"frombase64string", "powershell -e", "-encodedcommand",
			"-ec ", "char(", "iex(new-object", "invoke-expression",
			"set-executionpolicy bypass", "bypass", "hidden -enc",
		},
	},
	{
		rule: "script_persistence", category: "persistence", severity: 15,
		desc: "script-level persistence",
		any: []string{
			"schtasks /create", "reg add hklm", "reg add hkcu",
			"new-service", "startup folder", "shell:startup",
			"currentversion\\run", "currentversion\\runonce",
		},
	},
	{
		rule: "script_crypto_miner", category: "miner", severity: 20,
		desc: "cryptominer configuration",
		any: []string{
			"stratum+tcp", "stratum+ssl", "xmrig", "minerd", "cpuminer",
			"nicehash", "randomx",
		},
	},
	{
		rule: "script_reverse_shell", category: "c2", severity: 30,
		desc: "reverse-shell / interactive backdoor primitive",
		any: []string{
			"new-object system.net.sockets.tcpclient", "socket()",
			"nc -e", "ncat -e", "bash -i >&", "powershell -nop -c",
			"socket.socket", "pty.spawn",
		},
	},
}

// shortcutRules apply to .lnk/.url/.pif files. A shortcut is a binary whose
// argument string carries the real payload — the classic "lnk runs powershell"
// dropper vector.
var shortcutRules = []keywordRule{
	{
		rule: "shortcut_exec", category: "dropper", severity: 25,
		desc: "shortcut target runs a script/interpreter host",
		any: []string{
			"powershell", "cmd.exe /c", "cmd /c", "mshta", "wscript",
			"cscript", "rundll32", "regsvr32", "certutil", "bitsadmin",
			"explorer.exe", "\\\\system32\\\\",
		},
	},
	{
		rule: "shortcut_remote", category: "c2", severity: 20,
		desc: "shortcut points at a remote URL",
		any:  []string{"http://", "https://"},
	},
	{
		rule: "shortcut_hidden", category: "evasion", severity: 10,
		desc: "shortcut hides its window / no visible icon",
		any:  []string{"showwindow=0", "windowstyle", "minimized", "hidden"},
	},
}

// docRules apply to .doc/.docm/.xlsm/.rtf/.pdf: macro or DDE launchers.
var docRules = []keywordRule{
	{
		rule: "doc_macro", category: "dropper", severity: 25,
		desc: "document macro auto-executes code",
		any: []string{
			"autoopen", "document_open", "workbook_open", "sub autoopen",
			"shell(", "auto_close", "vbproject", "shellpayload",
		},
	},
	{
		rule: "doc_dde", category: "dropper", severity: 30,
		desc: "DDE auto-execution field",
		any:  []string{"ddeauto", "dde ", "msexcel", "ddeserver"},
	},
}

// archiveRules apply to container files (zip/7z/rar/iso) — a double extension
// inside an archive is the classic "innocuous.pdf.exe" dropper shape.
var archiveRules = []keywordRule{
	{
		rule: "archive_double_ext", category: "dropper", severity: 20,
		desc: "double extension (file disguised as document/image)",
		any: []string{
			".pdf.exe", ".doc.exe", ".jpg.exe", ".png.exe", ".txt.exe",
			".xls.exe", ".zip.exe", ".mp4.exe", ".jpg.scr", ".pdf.scr",
			".txt.scr", ".gif.scr", ".js.exe",
		},
	},
	{
		rule: "archive_office_macro", category: "dropper", severity: 20,
		desc: "archive contains a macro-enabled office document",
		any:  []string{".docm", ".xlsm", ".pptm", ".xlam", ".xll"},
	},
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
	Path  string
}

// yaraCategory maps a YARA rule name to the internal finding category it
// duplicates. The YARA engine and the internal engine both detect the same
// malware families, so without this mapping one signal (e.g. a Discord
// webhook) is counted twice — 40 from the internal regex plus 20 from YARA —
// which inflates a single finding into a 60-point score and pushes innocent
// files into MALICIOUS.
func YaraCategory(rule string) string {
	r := strings.ToLower(rule)
	switch {
	case strings.Contains(r, "eicar"):
		return "testfile"
	case strings.Contains(r, "discord"), strings.Contains(r, "telegram"), strings.Contains(r, "c2"):
		return "c2"
	case strings.Contains(r, "powershell"), strings.Contains(r, "encoded"), strings.Contains(r, "obfus"), strings.Contains(r, "sandbox"):
		return "evasion"
	case strings.Contains(r, "keylog"):
		return "keylogger"
	case strings.Contains(r, "steal"), strings.Contains(r, "credential"), strings.Contains(r, "wallet"), strings.Contains(r, "browser"):
		return "stealer"
	case strings.Contains(r, "inject"), strings.Contains(r, "hollow"):
		return "injection"
	case strings.Contains(r, "persist"), strings.Contains(r, "run_key"):
		return "persistence"
	case strings.Contains(r, "miner"), strings.Contains(r, "stratum"):
		return "miner"
	case strings.Contains(r, "crack"), strings.Contains(r, "emu"), strings.Contains(r, "info"):
		return "info"
	}
	return ""
}

// Match evaluates every detection layer against one file.
//
// Layer order matters: the generic string/regex pass runs first, then the
// kind-specific passes (script / shortcut / doc / archive) which are more
// specific and therefore carry higher confidence.
func Match(in MatchInput) (findings []model.Finding, whitelistHits []string) {
	if in.PE != nil {
		findings = append(findings, matchImports(in.PE)...)
	}
	findings = append(findings, matchStrings(in.Strs)...)
	findings = append(findings, matchBytes(in.Bytes)...)
	findings = append(findings, matchKind(in.Kind, in.Strs, in.Path)...)
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

// matchKind dispatches to the kind-specific rule sets. Each set is only
// applied to the file class it was designed for, which keeps signal high and
// false positives low (a .doc mentioning "powershell" is not a script).
func matchKind(kind filetype.Kind, strs []string, path string) []model.Finding {
	var out []model.Finding
	switch kind {
	case filetype.KindScript:
		out = append(out, matchKeywords(strs, scriptRules)...)
	case filetype.KindShortcut:
		out = append(out, matchKeywords(strs, shortcutRules)...)
	case filetype.KindDoc:
		out = append(out, matchKeywords(strs, docRules)...)
	case filetype.KindArchive:
		out = append(out, matchKeywords(strs, archiveRules)...)
	}
	// A double extension is meaningful for ANY file kind, not just archives:
	// "invoice.pdf.exe" sitting loose in a game folder is a dropper.
	if path != "" && hasDoubleExt(path) {
		out = append(out, model.Finding{
			Rule:     "double_extension",
			Category: "dropper",
			Severity: 20,
			Detail:   "double extension (disguised executable): " + filepath.Base(path),
		})
	}
	return out
}

// matchKeywords evaluates a keyword rule set against a file's strings.
// Rules are matched case-insensitively on the lowercased string set.
func matchKeywords(strs []string, set []keywordRule) []model.Finding {
	if len(strs) == 0 {
		return nil
	}
	lower := make([]string, 0, len(strs))
	for _, s := range strs {
		lower = append(lower, strings.ToLower(s))
	}
	var out []model.Finding
	for _, kr := range set {
		if kr.all != nil {
			if !containsAll(lower, kr.all) {
				continue
			}
		} else if len(kr.any) > 0 && !containsAny(lower, kr.any) {
			continue
		}
		hit := ""
		for _, s := range lower {
			if matchesRule(s, kr) {
				hit = s
				break
			}
		}
		if hit == "" {
			hit = "(matched)"
		}
		out = append(out, model.Finding{
			Rule:     kr.rule,
			Category: kr.category,
			Severity: kr.severity,
			Detail:   kr.desc + ": " + trunc(hit, 70),
		})
	}
	return out
}

func matchesRule(s string, kr keywordRule) bool {
	for _, n := range kr.any {
		if strings.Contains(s, n) {
			return true
		}
	}
	if kr.all != nil {
		return containsAll([]string{s}, kr.all)
	}
	return false
}

func containsAny(strs []string, needles []string) bool {
	for _, s := range strs {
		for _, n := range needles {
			if n != "" && strings.Contains(s, n) {
				return true
			}
		}
	}
	return false
}

func containsAll(strs []string, needles []string) bool {
	for _, n := range needles {
		if n == "" {
			continue
		}
		found := false
		for _, s := range strs {
			if strings.Contains(s, n) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return len(needles) > 0
}

// hasDoubleExt reports a filename like "invoice.pdf.exe" — a document or
// image extension followed by an executable one.
func hasDoubleExt(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return false
	}
	docExts := map[string]bool{
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".txt": true, ".rtf": true, ".mp3": true, ".mp4": true, ".avi": true,
		".zip": true, ".rar": true, ".html": true, ".csv": true,
	}
	execExts := map[string]bool{
		".exe": true, ".scr": true, ".com": true, ".pif": true, ".bat": true,
		".cmd": true, ".ps1": true, ".vbs": true, ".js": true, ".hta": true,
		".jar": true, ".msi": true,
	}
	return docExts["."+parts[len(parts)-2]] && execExts["."+parts[len(parts)-1]]
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
