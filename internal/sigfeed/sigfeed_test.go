package sigfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestStoreDefaultAndSync(t *testing.T) {
	localFile := filepath.Join(t.TempDir(), "live-signatures.json")
	st := New(localFile)

	s0 := st.Status()
	if s0.Version == "" || s0.PatternCount < 2 {
		t.Fatalf("expected embedded baseline loaded, got %+v", s0)
	}

	// Verify embedded ACRStealer pattern matches.
	hits := st.Match("", []string{"build_tag=ACRStealer_v2"})
	if len(hits) == 0 || hits[0].Rule != "live_acr_stealer_marker" {
		t.Fatalf("expected live_acr_stealer_marker hit, got %+v", hits)
	}

	// Serve a newer signature feed over httptest and verify hot-swap + persistence.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"version": "2099.01.01.1",
			"updated_at": "2099-01-01T00:00:00Z",
			"hashes": [{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "family": "TestTrojan", "severity": 95}],
			"patterns": [{"id": "new_c2_family", "category": "stealer", "severity": 70, "pattern": "(?i)evil_zero_day_marker", "description": "Zero day marker"}]
		}`))
	}))
	defer srv.Close()

	s1, changed, err := st.Sync(context.Background(), srv.URL)
	if err != nil || !changed || s1.Version != "2099.01.01.1" {
		t.Fatalf("Sync failed: status=%+v changed=%v err=%v", s1, changed, err)
	}

	hHits := st.Match("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if len(hHits) != 1 || hHits[0].Rule != "live_sha256_blacklist" {
		t.Fatalf("expected SHA256 blacklist hit, got %+v", hHits)
	}

	pHits := st.Match("", []string{"hello evil_zero_day_marker world"})
	if len(pHits) != 1 || pHits[0].Rule != "live_new_c2_family" {
		t.Fatalf("expected hot-reloaded pattern hit, got %+v", pHits)
	}

	// Reload from persisted local file in a fresh Store instance.
	st2 := New(localFile)
	if st2.Status().Version != "2099.01.01.1" {
		t.Fatalf("expected persisted version 2099.01.01.1, got %s", st2.Status().Version)
	}
}
