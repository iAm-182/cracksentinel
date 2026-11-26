package online

import "testing"

func TestParseVT(t *testing.T) {
	body := []byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":12,"suspicious":1,"undetected":8,"harmless":20,"timeout":0,"failure":0,"type-unsupported":0},"popular_threat_classification":{"suggested_threat_label":"trojan.malicious/stealer"}}}}`)
	r, err := parseVT(body)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Found || r.Malicious != 12 || r.Suspicious != 1 || r.Total != 41 || r.Label != "trojan.malicious/stealer" {
		t.Fatalf("bad parse: %+v", r)
	}
	if d := ScoreDelta(r); d != 60 {
		t.Fatalf("expected delta 60 for 12 engines, got %d", d)
	}
}

func TestParseVTSmallDetection(t *testing.T) {
	body := []byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"suspicious":0,"undetected":3,"harmless":30},"popular_threat_classification":{"suggested_threat_label":""}}}}`)
	r, _ := parseVT(body)
	if d := ScoreDelta(r); d != 6 {
		t.Fatalf("expected delta 6 for 1 engine noise, got %d", d)
	}
	if ForceMalicious(r, false) {
		t.Fatalf("1/34 VT must not force MALICIOUS")
	}
}

func TestVTThreeEngineNoiseDoesNotForceMalicious(t *testing.T) {
	// Mirrors QuickSFV.EXE (3/70 gwhv/krap) and TENOKE steam_api64.dll (3/63 unlabeled).
	qsfv := Result{Provider: "virustotal", Found: true, Malicious: 3, Undetected: 67, Label: "gwhv/krap"}
	if d := ScoreDelta(qsfv); d != 15 {
		t.Fatalf("QuickSFV 3/70 delta = %d, want 15", d)
	}
	if ForceMalicious(qsfv, false) {
		t.Fatalf("3/70 unlabeled/generic must NOT force MALICIOUS")
	}

	// Real stealer consensus (7/70 trojan.lumma) MUST force MALICIOUS.
	lumma := Result{Provider: "virustotal", Found: true, Malicious: 7, Undetected: 63, Label: "trojan.lumma/stealer"}
	if !ForceMalicious(lumma, false) {
		t.Fatalf("7/70 trojan.lumma MUST force MALICIOUS")
	}
	if d := ScoreDelta(lumma); d < 50 {
		t.Fatalf("lumma delta = %d, want >= 50", d)
	}

	// MalwareBazaar confirmed sample MUST always force MALICIOUS.
	mb := Result{Provider: "malwarebazaar", Found: true, Malicious: 1, Label: "RedLineStealer"}
	if !ForceMalicious(mb, true) || ScoreDelta(mb) != 70 {
		t.Fatalf("MalwareBazaar hit must force MALICIOUS with +70")
	}

	// Short token guard: "pirate" / "generator" must NOT false-match "rat", while "trojan.rat/async" MUST match.
	if IsHighRiskFamilyLabel("generic.pirate/generator") {
		t.Fatalf("'pirate/generator' must not match 'rat' substring")
	}
	if !IsHighRiskFamilyLabel("win32.rat/agent") {
		t.Fatalf("'win32.rat/agent' should match standalone 'rat' token")
	}
}

func TestPUACapped(t *testing.T) {
	body := []byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":8,"suspicious":0,"undetected":20,"harmless":30},"popular_threat_classification":{"suggested_threat_label":"pua.crack/pseb"}}}}`)
	r, _ := parseVT(body)
	if d := ScoreDelta(r); d != 10 {
		t.Fatalf("pua label should cap delta at 10, got %d", d)
	}
	if ForceMalicious(r, true) {
		t.Fatalf("8/58 pua.crack on emulator must not force MALICIOUS")
	}
}

func TestParseVTClean(t *testing.T) {
	body := []byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":5,"harmless":60},"popular_threat_classification":{}}}}`)
	r, _ := parseVT(body)
	if d := ScoreDelta(r); d != -10 {
		t.Fatalf("expected -10 for 65-engine clean consensus, got %d", d)
	}
	if Describe(r) == "" {
		t.Fatal("describe empty for clean")
	}
}
