package rules

import "testing"

// TestClassifyRule pins the buckets the adjudicator relies on. A rule that
// moves between buckets changes what the model is told, so the placement is
// part of the contract.
func TestClassifyRule(t *testing.T) {
	cases := []struct {
		rule string
		want RuleClass
	}{
		// Normal for a crack or emulator.
		{"imp_keylogger", RuleCrackExpected},
		{"imp_injection", RuleCrackExpected},
		{"crack_whitelist", RuleCrackExpected},
		{"emu_steamapi", RuleCrackExpected},
		{"packer", RuleCrackExpected},
		{"yara:gc_crack_emu_info", RuleCrackExpected},

		// Malicious in any context.
		{"discord_webhook", RulePayload},
		{"telegram_token", RulePayload},
		{"imp_credential", RulePayload},
		{"imp_persistence", RulePayload},
		{"combo_stealer_stack", RulePayload},
		{"wallet_browser_target", RulePayload},
		{"script_reverse_shell", RulePayload},
		{"script_crypto_miner", RulePayload},
		{"behav_network_connect", RulePayload},
		{"eicar", RulePayload},
		{"double_extension", RulePayload},
		{"yara:gc_hardcoded_c2", RulePayload},

		// Dual-use: a checksum verifier, an archive tool and a crack
		// launcher all do these. Putting them in the payload bucket is
		// what made the adjudicator call legitimate tools trojans.
		{"imp_clipboard", RuleNeutral},
		{"imp_destructive", RuleNeutral},
		{"imp_exfil", RuleNeutral},
		{"base64_blob", RuleNeutral},
		{"script_hidden_exec", RuleNeutral},
		{"script_obfuscation", RuleNeutral},
		{"script_exfil", RuleNeutral},
		{"script_download_exec", RuleNeutral},
		{"shortcut_exec", RuleNeutral},
		{"sandbox_check", RuleNeutral},
		{"some_rule_nobody_classified", RuleNeutral},
	}
	for _, c := range cases {
		if got := ClassifyRule(c.rule); got != c.want {
			t.Errorf("ClassifyRule(%q) = %v, want %v", c.rule, got, c.want)
		}
	}
}
