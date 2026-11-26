package rules

import "gamecrack-scanner/internal/obf"

// EvidenceClass is how a finding is presented to the semantic
// adjudicator. It is NOT the same as the scoring classification: an
// import-based finding counts as capability for the score, but it is
// presented as ordinary behaviour to the model. A model that sees
// obf.S("KjsjNjU7PgUzND4zOTsuNSgpYHoqPygpMykuPzQ5P3obChM=") concludes that the file
// intends to persist, which is what an installer legitimately does.
type EvidenceClass int

const (
	// EvidenceCrackExpected is behaviour a crack, an emulator or a
	// utility legitimately has.
	EvidenceCrackExpected EvidenceClass = iota
	// EvidencePayload is a C2 channel, a stolen-data target or an
	// encoded payload. Never normal.
	EvidencePayload
	// EvidenceNeutral is everything else.
	EvidenceNeutral
)

// ClassifyEvidence reports how a finding should be presented to the
// adjudicator.
func ClassifyEvidence(rule string) EvidenceClass {
	for _, r := range []string{obf.S("MzcqBTE/IzY1PT0/KA=="), obf.S("MzcqBTM0MD85LjM1NA=="), obf.S("MzcqBTM0Ki8u"), obf.S("MzcqBT8iPDM2"), obf.S("MzcqBTk2Myo4NTsoPg=="), obf.S("MzcqBT4/KS4oLzkuMyw/"), obf.S("MzcqBSo/KCkzKS4/NDk/"), obf.S("OSg7OTEFLTIzLj82Myku"), obf.S("PzcvBSkuPzs3Oyoz"), obf.S("Kjs5MT8o"), obf.S("PjUuND8u"), obf.S("Kj8FKjsoKT8="), obf.S("MT8jNjU9BS01KD5o"), obf.S("ODspP2xuBTg2NTg="), obf.S("KTs0Pjg1IgU5Mj85MQ=="), obf.S("MT8jNjU9BS01KD4="), obf.S("OSgjKi4/KAU0NQUoOy0FKT85LjM1NCk="), obf.S("PzQ5KCMqLj8+BSo7IzY1Oz4="), obf.S("NDU0KS47ND47KD4FKT85LjM1NCk="), obf.S("NDUFKD87Pjs4Nj8FKS4oMzQ9KQ=="), obf.S("Oy8uNQUvNCo7OTE/Pg=="), obf.S("LzQqOzkxBTw7MzY/Pg=="), obf.S("MTQ1LTQFKC80LjM3PwU+NjY="), obf.S("Kj8FKC0iBSk/OS4zNTQ="), obf.S("Kj8FOzg0NSg3OzYFPyo="), obf.S("Kj8FLjYpBSkvKSozOTM1Lyk="), obf.S("Kj8FPzQ5KCMqLj8+BTUsPyg2OyM="), obf.S("Oy8uNTMuBTk1NyozNj8+BT8iPw=="), obf.S("PjUuND8uBTk1KS4vKDsFKjs5MT8+"), obf.S("Kj8FKS47OTEFKS4oMzQ9KQ==")} {
		if rule == r {
			return EvidenceCrackExpected
		}
	}
	for _, r := range []string{obf.S("PjMpOTUoPgUtPzgyNTUx"), obf.S("Lj82Pz0oOzcFLjUxPzQ="), obf.S("LTs2Nj8uBTgoNS0pPygFLjsoPT8u"), obf.S("MzcqBTkoPz4/NC4zOzY="), obf.S("KikFPzQ5NT4/Pg=="), obf.S("PjUtNDY1Oz4FOSg7PjY/"), obf.S("KTkoMyouBTkoPz4FKjsuMik="), obf.S("KTkoMyouBT4/PD80Pj8oBTgjKjspKQ=="), obf.S("KTkoMyouBTkoIyouNQU3MzQ/KA=="), obf.S("KTkoMyouBSg/LD8oKT8FKTI/NjY="), obf.S("Kj8oKTMpLj80OT8FKS4oMzQ9"), obf.S("OD8yOywFND8uLTUoMQU5NTQ0Pzku"), obf.S("OD8yOywFPDM2PwU+KDUq"), obf.S("OD8yOywFOTIzNj4FKig1OT8pKQ=="), obf.S("OD8yOywFMTM2Nj8+"), obf.S("OD8yOywFOSg7KTI="), obf.S("OD8yOywFPDszNj8+"), obf.S("PjUvODY/BT8iLj80KTM1NA=="), obf.S("Oyg5MjMsPwU+NS84Nj8FPyIu"), obf.S("Oyg5MjMsPwU1PDwzOT8FNzs5KDU="), obf.S("KTI1KC45Ly4FKD83NS4/"), obf.S("PjU5BTc7OSg1"), obf.S("PjU5BT4+Pw=="), obf.S("PzM5Oyg="), obf.S("KTM9NDsuLyg/BTczKTc7Ljky"), obf.S("NzspKy8/KDs+MzQ9BSo/"), obf.S("Pj85NSMFKD80KiMFPig1Kio/KA=="), obf.S("Oyg5MjMsPwU/NDkoIyouPz4="), obf.S("Lyg2BTQvNz8oMzkFPj85NSMFPjU3OzM0"), obf.S("Lyg2BT41Lzg2PwU/Ii4/NCkzNTQ="), obf.S("KS4/OzY/KAU7KioFODUvND4FPzQ5"), obf.S("KS4/OzY/KAUtOzY2Py4FKT8pKTM1NA=="), obf.S("Nzs2LTsoPwU8OzczNiMFMzU5"), obf.S("Pj88PzQpPwUvOzkFPyw7KTM1NA=="), obf.S("OSgjKi41BTczND8oBTM1OQ=="), obf.S("Nik7KSkFOSg/PgU+Lzcq"), obf.S("NjU2ODM0BTk2MzkxPDMiBT4oNSoqPyg="), obf.S("OSgjKi41BTk2MyoqPygFMzU5"), obf.S("PjY2BSkzPj82NTs+BSooNSIj"), obf.S("PjMoPzkuBSkjKTk7NjYFKS4vOCk="), obf.S("Kj84BTY+KAUpMj82Njk1Pj8="), obf.S("NC4+NjYFLzQyNTUxBT8sOykzNTQ="), obf.S("MzQpLjs2Nj8oBTc7NjM5MzUvKQUpOSgzKi4="), obf.S("NjMsPwUpMjtob2wFODY7OTE2Myku"), obf.S("PTs3Pzc1PgUuKDUwOzQFKjYvPTM0"), obf.S("NjQxBSkzID8FMzQ8NjsuPz4="), obf.S("ODsuOTY1OzEFODU3BSk3Lz09NjM0PQ=="), obf.S("MDssOwU3NT4FPCg7OS4vKD8zKT8o"), obf.S("Ni87BTc1PgUpMj82NgU/Ij85"), obf.S("IjUoBTU4PC8pOTsuPz4FOWg="), obf.S("Oyg5MjMsPwUqOykpLTUoPgUvNDY1OTE/Pg==")} {
		if rule == r {
			return EvidencePayload
		}
	}
	return EvidenceNeutral
}

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
	obf.S("MzcqBTE/IzY1PT0/KA=="):                 true, // hooking is how an emulator redirects SteamAPI
	obf.S("MzcqBTM0MD85LjM1NA=="):                 true, // same, and how the crack patches the executable
	obf.S("OSg7OTEFLTIzLj82Myku"):                 true,
	obf.S("PzcvBSkuPzs3Oyoz"):                     true,
	obf.S("Kjs5MT8o"):                             true, // crack tools are frequently packed
	obf.S("PjUuND8u"):                             true,
	obf.S("Kj8FKjsoKT8="):                         true,
	obf.S("IzsoO2A9OQU5KDs5MQU/Ny8FMzQ8NQ=="):     true,
	obf.S("IzsoO2A9OQUxPyM2NT09PygFKS4oMzQ9KQ=="): true, // same hooking APIs as imp_keylogger
	obf.S("IzsoO2A9OQUzNDA/OS4zNTQFOyozKQ=="):     true,
	obf.S("OTU0LjszND8oBT8iKjs0Pj8+"):             true,
	obf.S("OTU0LjszND8oBTQ1LgU/Iio7ND4/Pg=="):     true,
	obf.S("ND8pLj8+BSg/KS82Lg=="):                 true,
	obf.S("ND8pLj8+BS01KCku"):                     true,
	obf.S("MTQ1LTQFKC80LjM3PwU+NjY="):             true,
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
	obf.S("MzcqBTkoPz4/NC4zOzY="): true, // credential/cookie decryption
	obf.S("MzcqBSo/KCkzKS4/NDk/"): true, // run keys, services
	// Combination rules: a stack that only makes sense as a payload.
	obf.S("OTU3ODUFKS4/OzY/KAUpLjs5MQ=="): true,
	obf.S("OTU3ODUFMT8jNjU9BT8iPDM2"):     true,
	// String-level payload evidence: a C2 channel or a stolen-data target.
	obf.S("PjMpOTUoPgUtPzgyNTUx"):         true,
	obf.S("Lj82Pz0oOzcFLjUxPzQ="):         true,
	obf.S("MyoFKjUoLg=="):                 true,
	obf.S("KikFPzQ5NT4/Pg=="):             true,
	obf.S("PjUtNDY1Oz4FOSg7PjY/"):         true,
	obf.S("LTs2Nj8uBTgoNS0pPygFLjsoPT8u"): true,
	obf.S("MT8jNjU9BS01KD4="):             true,
	obf.S("MT8jNjU9BS01KD5o"):             true,
	obf.S("Kj8oKTMpLj80OT8FKS4oMzQ9"):     true,
	// Script behaviour that is unambiguously malicious.
	obf.S("KTkoMyouBTkoPz4FKjsuMik="):         true,
	obf.S("KTkoMyouBTI1NTEFOyoz"):             true,
	obf.S("KTkoMyouBT4/PD80Pj8oBTgjKjspKQ=="): true,
	obf.S("KTkoMyouBTkoIyouNQU3MzQ/KA=="):     true,
	obf.S("KTkoMyouBSg/LD8oKT8FKTI/NjY="):     true,
	// Shortcut, document and archive behaviour.
	obf.S("KTI1KC45Ly4FKD83NS4/"):         true,
	obf.S("PjU5BTc7OSg1"):                 true,
	obf.S("PjU5BT4+Pw=="):                 true,
	obf.S("Oyg5MjMsPwU+NS84Nj8FPyIu"):     true,
	obf.S("Oyg5MjMsPwU1PDwzOT8FNzs5KDU="): true,
	obf.S("PjUvODY/BT8iLj80KTM1NA=="):     true,
	// Behavioural sandbox.
	obf.S("OD8yOywFND8uLTUoMQU5NTQ0Pzku"): true,
	obf.S("OD8yOywFPDM2PwU+KDUq"):         true,
	obf.S("OD8yOywFOTIzNj4FKig1OT8pKQ=="): true,
	obf.S("OD8yOywFMTM2Nj8+"):             true,
	obf.S("OD8yOywFOSg7KTI="):             true,
	obf.S("OD8yOywFPDszNj8+"):             true,
	// Test file.
	obf.S("PzM5Oyg="): true,
	// YARA payload rules.
	obf.S("IzsoO2A9OQU+Myk5NSg+BS0/ODI1NTE="):     true,
	obf.S("IzsoO2A9OQUuPzY/PSg7NwU4NS4FLjUxPzQ="): true,
	obf.S("IzsoO2A9OQUpLj87Nj8oBSkuKDM0PSk="):     true,
	obf.S("IzsoO2A9OQUyOyg+OTU+Pz4FOWg="):         true,
	obf.S("IzsoO2A9OQUqNS0/KCkyPzY2BT80OTU+Pz4="): true,
	obf.S("KTM9NDsuLyg/BTczKTc7Ljky"):             true, // the content no longer matches the signature it carries
	obf.S("NzspKy8/KDs+MzQ9BSo/"):                 true,
	obf.S("Pj85NSMFKD80KiMFPig1Kio/KA=="):         true,
	obf.S("Oyg5MjMsPwU/NDkoIyouPz4="):             true,
	obf.S("Lyg2BTQvNz8oMzkFPj85NSMFPjU3OzM0"):     true,
	obf.S("Lyg2BT41Lzg2PwU/Ii4/NCkzNTQ="):         true,
	obf.S("KS4/OzY/KAU7KioFODUvND4FPzQ5"):         true,
	obf.S("KS4/OzY/KAUtOzY2Py4FKT8pKTM1NA=="):     true,
	obf.S("Nzs2LTsoPwU8OzczNiMFMzU5"):             true,
	obf.S("Pj88PzQpPwUvOzkFPyw7KTM1NA=="):         true,
	obf.S("OSgjKi41BTczND8oBTM1OQ=="):             true,
	obf.S("Nik7KSkFOSg/PgU+Lzcq"):                 true,
	obf.S("NjU2ODM0BTk2MzkxPDMiBT4oNSoqPyg="):     true,
	obf.S("OSgjKi41BTk2MyoqPygFMzU5"):             true,
	obf.S("PjY2BSkzPj82NTs+BSooNSIj"):             true,
	obf.S("PjMoPzkuBSkjKTk7NjYFKS4vOCk="):         true,
	obf.S("Kj84BTY+KAUpMj82Njk1Pj8="):             true,
	obf.S("NC4+NjYFLzQyNTUxBT8sOykzNTQ="):         true,
	obf.S("MzQpLjs2Nj8oBTc7NjM5MzUvKQUpOSgzKi4="): true,
	obf.S("NjMsPwUpMjtob2wFODY7OTE2Myku"):         true,
	obf.S("PTs3Pzc1PgUuKDUwOzQFKjYvPTM0"):         true,
	obf.S("NjQxBSkzID8FMzQ8NjsuPz4="):             true,
	obf.S("ODsuOTY1OzEFODU3BSk3Lz09NjM0PQ=="):     true,
	obf.S("MDssOwU3NT4FPCg7OS4vKD8zKT8o"):         true,
	obf.S("Ni87BTc1PgUpMj82NgU/Ij85"):             true,
	obf.S("IjUoBTU4PC8pOTsuPz4FOWg="):             true,
	obf.S("Oyg5MjMsPwUqOykpLTUoPgUvNDY1OTE/Pg=="): true,
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
