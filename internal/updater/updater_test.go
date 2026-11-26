package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.0.0", "1.9.3", 1},
		{"v2.0.1", "2.0.0", 1},
		{"1.9.3", "v1.9.3", 0},
		{"1.9.2", "1.9.3", -1},
		{"1.10.0", "1.9.9", 1},
		{"2.0.0-dev", "2.0.0", 0},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	raw := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  CrackSentinel.exe\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *dist/scanner.exe\n"
	m := ParseChecksums(raw)
	if m["cracksentinel.exe"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("missing cracksentinel.exe checksum: %+v", m)
	}
	if m["scanner.exe"] != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("missing scanner.exe checksum: %+v", m)
	}
}

func TestCheckLatestFromMockGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"tag_name": "v2.1.0",
			"html_url": "https://github.com/iAm-182/cracksentinel/releases/tag/v2.1.0",
			"body": "Big update release notes",
			"published_at": "2026-11-26T00:00:00Z",
			"assets": [
				{"name": "CrackSentinel.exe", "browser_download_url": "https://example.invalid/CrackSentinel.exe"},
				{"name": "scanner.exe", "browser_download_url": "https://example.invalid/scanner.exe"},
				{"name": "checksums.txt", "browser_download_url": "https://example.invalid/checksums.txt"}
			]
		}`))
	}))
	defer srv.Close()

	info := checkLatestFrom(context.Background(), srv.URL, "2.0.0", DefaultRepo)
	if info.Error != "" {
		t.Fatalf("unexpected error: %s", info.Error)
	}
	if !info.Available || info.LatestVersion != "2.1.0" {
		t.Fatalf("expected available 2.1.0, got %+v", info)
	}
	if info.DesktopURL == "" || info.ChecksumsURL == "" {
		t.Fatalf("expected asset URLs populated: %+v", info)
	}
}
