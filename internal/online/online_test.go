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
	if d := ScoreDelta(r); d != 20 {
		t.Fatalf("expected delta 20 for 1 engine, got %d", d)
	}
}

func TestPUACapped(t *testing.T) {
	body := []byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":8,"suspicious":0,"undetected":20,"harmless":30},"popular_threat_classification":{"suggested_threat_label":"pua.crack/pseb"}}}}`)
	r, _ := parseVT(body)
	if d := ScoreDelta(r); d != 10 {
		t.Fatalf("pua label should cap delta at 10, got %d", d)
	}
}

func TestParseVTClean(t *testing.T) {
	body := []byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":5,"harmless":60},"popular_threat_classification":{}}}}`)
	r, _ := parseVT(body)
	if d := ScoreDelta(r); d != -5 {
		t.Fatalf("expected -5 for clean hash, got %d", d)
	}
	if Describe(r) == "" {
		t.Fatal("describe empty for clean")
	}
}
