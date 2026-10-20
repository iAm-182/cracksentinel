package rules

import "testing"

// TestClassifyEvidence pins the three buckets the semantic adjudicator is
// given. The split matters: a model that sees an import-based finding in the
// payload bucket concludes that a legitimate installer intends to persist,
// and calls it a trojan. The scoring classification is deliberately
// different - a run key in a crack folder still counts there.
func TestClassifyEvidence(t *testing.T) {
	crackExpected := []string{
		"imp_keylogger", "imp_injection", "imp_input", "imp_exfil",
		"imp_clipboard", "imp_destructive", "imp_persistence",
		"crack_whitelist", "emu_steamapi", "packer", "dotnet",
		"keylog_word2", "base64_blob", "sandbox_check",
		"crypter_no_raw_sections", "encrypted_payload", "nonstandard_sections",
		"no_readable_strings",
	}
	for _, r := range crackExpected {
		if got := ClassifyEvidence(r); got != EvidenceCrackExpected {
			t.Errorf("ClassifyEvidence(%q) = %v, want EvidenceCrackExpected", r, got)
		}
	}

	payload := []string{
		"discord_webhook", "telegram_token", "wallet_browser_target",
		"imp_credential", "ps_encoded", "download_cradle",
		"script_cred_paths", "script_defender_bypass", "script_crypto_miner",
		"script_reverse_shell", "persistence_string",
		"behav_network_connect", "behav_file_drop", "behav_child_process",
		"double_extension", "archive_double_ext", "shortcut_remote",
		"doc_macro", "doc_dde", "eicar",
	}
	for _, r := range payload {
		if got := ClassifyEvidence(r); got != EvidencePayload {
			t.Errorf("ClassifyEvidence(%q) = %v, want EvidencePayload", r, got)
		}
	}

	neutral := []string{
		"ip_port", "script_hidden_exec", "script_obfuscation",
		"script_exfil", "script_download_exec", "script_persistence",
		"shortcut_exec", "combo_keylog_exfil", "combo_stealer_stack",
		"judge_verdict", "jev_claims_reviewed", "some_new_rule",
	}
	for _, r := range neutral {
		if got := ClassifyEvidence(r); got != EvidenceNeutral {
			t.Errorf("ClassifyEvidence(%q) = %v, want EvidenceNeutral", r, got)
		}
	}
}

// TestEvidenceAndScoringClassesDiffer documents that the two
// classifications are intentionally not the same.
func TestEvidenceAndScoringClassesDiffer(t *testing.T) {
	// A run key import counts for the score: in a crack folder it is
	// worth points.
	if ClassifyRule("imp_persistence") != RulePayload {
		t.Error("imp_persistence must count as payload for the score")
	}
	// But it is presented to the model as ordinary behaviour.
	if ClassifyEvidence("imp_persistence") != EvidenceCrackExpected {
		t.Error("imp_persistence must be presented as crack-expected behaviour")
	}

	// The same holds for the keylogger terminology: it is worth points
	// for the score, but the word alone is weak evidence, and a TLS
	// keylog helper or a game tool can carry it too.
	if ClassifyRule("keylog_word") != RulePayload {
		t.Error("keylog_word must count as payload for the score")
	}
	if ClassifyEvidence("keylog_word") != EvidenceCrackExpected {
		t.Error("keylog_word must be presented as crack-expected behaviour")
	}
}
