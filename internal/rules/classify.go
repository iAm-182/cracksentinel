package rules

// Rule classification for the semantic adjudicator.
//
// The deterministic engine produces findings without saying HOW MUCH they
// argue for a payload. That distinction matters when the findings are handed
// to a model: a crack emulator hooks APIs (SetWindowsHookExA,
// WriteProcessMemory) and that is completely normal for it, while the same
// APIs in a script are a keylogger. A flat list of findings makes a model
// call every emulator trojanized.
//
// Three classes:
//   - RulePayload: never expected in a legitimate crack
//   - RuleCrackExpected: normal for a crack, emulator or DRM bypass
//   - RuleNeutral: uninformative either way (the default)

type RuleClass int

const (
	// RulePayload marks evidence that has no place in a legitimate crack.
	RulePayload RuleClass = iota
	// RuleCrackExpected marks behaviour a crack or emulator legitimately has.
	RuleCrackExpected
	// RuleNeutral marks a finding that argues neither way.
	RuleNeutral
)

// crackExpectedRules are findings that a legitimate crack, emulator or DRM
// bypass routinely produces. Hooking the game's own API is the whole point
// of a crack.
var crackExpectedRules = map[string]bool{
	"imp_keylogger":             true, // hooking is how an emulator redirects SteamAPI
	"imp_injection":             true, // same, and how the crack patches the executable
	"crack_whitelist":           true,
	"emu_steamapi":              true,
	"packer":                    true, // crack tools are frequently packed
	"dotnet":                    true,
	"pe_parse":                  true,
	"yara:gc_crack_emu_info":    true,
	"yara:gc_keylogger_strings": true, // same hooking APIs as imp_keylogger
	"yara:gc_injection_apis":    true,
	"container_expanded":        true,
	"container_not_expanded":    true,
	"nested_result":             true,
	"nested_worst":              true,
}

// payloadRules are findings that never belong in a legitimate crack.
//
// The bar for this list is high on purpose. A rule lands here only when it
// is malicious in ANY context. Dual-use behaviour — reading a file, copying
// a hash to the clipboard, listing a directory, downloading an update,
// hiding a window — is deliberately NOT here: a checksum verifier, an
// archive tool and a crack launcher all do those things, and putting them
// in the payload bucket makes the adjudicator call every legitimate tool
// a trojan. Those rules stay neutral and the model weighs them in context.
var payloadRules = map[string]bool{
	// Import-based payload behaviour.
	"imp_credential":  true, // credential/cookie decryption
	"imp_persistence": true, // run keys, services
	// Combination rules: a stack that only makes sense as a payload.
	"combo_stealer_stack": true,
	"combo_keylog_exfil":  true,
	// String-level payload evidence: a C2 channel or a stolen-data target.
	"discord_webhook":       true,
	"telegram_token":        true,
	"ip_port":               true,
	"ps_encoded":            true,
	"download_cradle":       true,
	"wallet_browser_target": true,
	"keylog_word":           true,
	"keylog_word2":          true,
	"persistence_string":    true,
	// Script behaviour that is unambiguously malicious.
	"script_cred_paths":      true,
	"script_hook_api":        true,
	"script_defender_bypass": true,
	"script_crypto_miner":    true,
	"script_reverse_shell":   true,
	// Shortcut, document and archive behaviour.
	"shortcut_remote":      true,
	"doc_macro":            true,
	"doc_dde":              true,
	"archive_double_ext":   true,
	"archive_office_macro": true,
	"double_extension":     true,
	// Behavioural sandbox.
	"behav_network_connect": true,
	"behav_file_drop":       true,
	"behav_child_process":   true,
	"behav_killed":          true,
	"behav_crash":           true,
	"behav_failed":          true,
	// Test file.
	"eicar": true,
	// YARA payload rules.
	"yara:gc_discord_webhook":    true,
	"yara:gc_telegram_bot_token": true,
	"yara:gc_stealer_strings":    true,
	"yara:gc_hardcoded_c2":       true,
	"yara:gc_powershell_encoded": true,
}

// ClassifyRule reports how strongly a rule argues for a malicious payload.
// Unknown rules are neutral: the adjudicator must not accuse on the basis of
// a rule nobody has classified.
func ClassifyRule(rule string) RuleClass {
	if crackExpectedRules[rule] {
		return RuleCrackExpected
	}
	if payloadRules[rule] {
		return RulePayload
	}
	return RuleNeutral
}
