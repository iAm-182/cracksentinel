package ui

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUIOriginGuardBlocksForeignSites(t *testing.T) {
	srv := New(Options{TempDir: t.TempDir(), CachePath: filepath.Join(t.TempDir(), "c.jsonl")})
	h := srv.Handler()

	// Foreign website origin MUST be blocked (CSRF / DNS-rebinding guard).
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Origin", "https://evil-game-site.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign origin status = %d, want 403", rec.Code)
	}

	// Browser extension origin MUST be allowed.
	req2 := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req2.Header.Set("Origin", "chrome-extension://abcdefghijklmnop")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("extension origin status = %d, want 200", rec2.Code)
	}
}

func TestUIUploadAndCheckURLAndScanPaths(t *testing.T) {
	tmp := t.TempDir()
	srv := New(Options{Workers: 1, TempDir: tmp, CachePath: filepath.Join(tmp, "c.jsonl"), CorpusPath: filepath.Join(tmp, "corpus.json")})
	h := srv.Handler()

	// 1. Drag-and-drop multipart upload of a malicious script.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "stealer.ps1")
	fw.Write([]byte("https://discord.com/api/webhooks/12345678901234567/" + strings.Repeat("aB3-_", 15) + "\nStart-Process -WindowStyle Hidden\nSet-MpPreference -DisableRealtimeMonitoring $true\n"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d body=%s", rec.Code, rec.Body.String())
	}
	var item HistoryItem
	if err := json.Unmarshal(rec.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.TopVerdict != "MALICIOUS" {
		t.Errorf("upload verdict = %s (score=%d), want MALICIOUS", item.TopVerdict, item.MaxScore)
	}

	// 2. URL pre-check API (non-probing instant mode).
	urlReq := httptest.NewRequest(http.MethodPost, "/api/check-url", strings.NewReader(`{"url":"https://get.192169451.com/share/Far_Cry_Repack.zip","referrer":"https://mroat0j0w.store/x","size":25000000,"probe":false}`))
	urlRec := httptest.NewRecorder()
	h.ServeHTTP(urlRec, urlReq)
	if urlRec.Code != http.StatusOK {
		t.Fatalf("check-url status = %d", urlRec.Code)
	}
	if !strings.Contains(urlRec.Body.String(), `"MALICIOUS"`) {
		t.Errorf("expected MALICIOUS URL assessment, got %s", urlRec.Body.String())
	}

	// 3. Scan local paths (mass scan + extension source_url enrichment).
	cleanFile := filepath.Join(tmp, "notes.txt")
	os.WriteFile(cleanFile, []byte("hello world"), 0o644)
	spReq := httptest.NewRequest(http.MethodPost, "/api/scan-paths", strings.NewReader(`{"paths":[`+jsonString(cleanFile)+`],"source":"extension"}`))
	spRec := httptest.NewRecorder()
	h.ServeHTTP(spRec, spReq)
	if spRec.Code != http.StatusOK {
		t.Fatalf("scan-paths status = %d body=%s", spRec.Code, spRec.Body.String())
	}
	if !strings.Contains(spRec.Body.String(), `"CLEAN"`) {
		t.Errorf("expected CLEAN, got %s", spRec.Body.String())
	}
}

func TestUIPublicModeAndAccessKeyHardening(t *testing.T) {
	tmp := t.TempDir()
	srv := New(Options{
		Workers:        1,
		TempDir:        tmp,
		CachePath:      filepath.Join(tmp, "c.jsonl"),
		PublicMode:     true,
		AllowedOrigins: []string{"https://sentinel.breakthematrix.id"},
		AccessKey:      "top-secret-key",
		MaxUploadMB:    1,
	})
	h := srv.Handler()

	// Health stays open and advertises public_mode + auth_required.
	hr := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	hr.Header.Set("Origin", "https://sentinel.breakthematrix.id")
	hrec := httptest.NewRecorder()
	h.ServeHTTP(hrec, hr)
	if hrec.Code != http.StatusOK || !strings.Contains(hrec.Body.String(), `"public_mode":true`) || !strings.Contains(hrec.Body.String(), `"auth_required":true`) {
		t.Fatalf("health = %d %s", hrec.Code, hrec.Body.String())
	}

	// Missing access key gets 401.
	r401 := httptest.NewRequest(http.MethodPost, "/api/check-url", strings.NewReader(`{"url":"https://example.com/a.zip"}`))
	rec401 := httptest.NewRecorder()
	h.ServeHTTP(rec401, r401)
	if rec401.Code != http.StatusUnauthorized {
		t.Fatalf("missing key status = %d, want 401", rec401.Code)
	}

	// Local-only endpoints MUST be blocked (403) in public mode even with valid key.
	for _, ep := range []string{
		"/api/scan-paths", "/api/jobs/scan-paths", "/api/pick",
		"/api/quarantine", "/api/quarantine/list", "/api/quarantine/restore", "/api/quarantine/delete",
		"/api/watch/start", "/api/corpus/label", "/api/settings", "/api/cache/clear",
		"/api/history/clear", "/api/open-explorer", "/api/desktop/shortcut", "/api/app/quit", "/api/update/apply", "/api/signatures/sync",
		"/api/audit/run", "/api/sandbox/launch", "/api/windows/integration",
	} {
		req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(`{}`))
		req.Header.Set("X-Access-Key", "top-secret-key")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("public mode %s = %d, want 403", ep, rec.Code)
		}
	}

	// Valid key on /api/check-url succeeds.
	rOK := httptest.NewRequest(http.MethodPost, "/api/check-url", strings.NewReader(`{"url":"https://example.com/a.zip","probe":false}`))
	rOK.Header.Set("X-Access-Key", "top-secret-key")
	recOK := httptest.NewRecorder()
	h.ServeHTTP(recOK, rOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("valid key check-url = %d %s", recOK.Code, recOK.Body.String())
	}
}

func TestDesktopDashboardJobsQuarantineAndSettings(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	quarDir := filepath.Join(tmp, "quarantine")
	srv := New(Options{
		Workers:       1,
		TempDir:       tmp,
		DataDir:       dataDir,
		QuarantineDir: quarDir,
		CachePath:     filepath.Join(tmp, "cache.jsonl"),
		DesktopMode:   true,
	})
	h := srv.Handler()

	// 1. Settings update & persistence.
	setReq := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"workers":2,"extract_depth":1,"skip_assets":true}`))
	setRec := httptest.NewRecorder()
	h.ServeHTTP(setRec, setReq)
	if setRec.Code != http.StatusOK {
		t.Fatalf("settings save = %d %s", setRec.Code, setRec.Body.String())
	}
	getSetReq := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getSetRec := httptest.NewRecorder()
	h.ServeHTTP(getSetRec, getSetReq)
	if !strings.Contains(getSetRec.Body.String(), `"workers":2`) {
		t.Fatalf("expected persisted workers=2, got %s", getSetRec.Body.String())
	}

	// 2. Async live scan job on a malicious local script.
	badFile := filepath.Join(tmp, "bad_dropper.ps1")
	os.WriteFile(badFile, []byte("https://discord.com/api/webhooks/12345678901234567/"+strings.Repeat("xY9_-", 15)+"\nStart-Process -WindowStyle Hidden\nSet-MpPreference -DisableRealtimeMonitoring $true\n"), 0o644)

	jobReq := httptest.NewRequest(http.MethodPost, "/api/jobs/scan-paths", strings.NewReader(`{"paths":[`+jsonString(badFile)+`]}`))
	jobRec := httptest.NewRecorder()
	h.ServeHTTP(jobRec, jobReq)
	if jobRec.Code != http.StatusOK {
		t.Fatalf("start job = %d %s", jobRec.Code, jobRec.Body.String())
	}
	var started struct {
		ID string `json:"id"`
	}
	json.Unmarshal(jobRec.Body.Bytes(), &started)
	if started.ID == "" {
		t.Fatalf("missing job id: %s", jobRec.Body.String())
	}

	// Poll until job completes.
	var jobBody string
	for i := 0; i < 120; i++ {
		pollReq := httptest.NewRequest(http.MethodGet, "/api/jobs/"+started.ID, nil)
		pollRec := httptest.NewRecorder()
		h.ServeHTTP(pollRec, pollReq)
		jobBody = pollRec.Body.String()
		if strings.Contains(jobBody, `"status":"done"`) {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !strings.Contains(jobBody, `"status":"done"`) || !strings.Contains(jobBody, `"MALICIOUS"`) {
		t.Fatalf("job did not finish malicious: %s", jobBody)
	}

	// 3. Quarantine -> list -> restore -> re-quarantine -> delete.
	qReq := httptest.NewRequest(http.MethodPost, "/api/quarantine", strings.NewReader(`{"path":`+jsonString(badFile)+`}`))
	qRec := httptest.NewRecorder()
	h.ServeHTTP(qRec, qReq)
	if qRec.Code != http.StatusOK {
		t.Fatalf("quarantine = %d %s", qRec.Code, qRec.Body.String())
	}
	if _, err := os.Stat(badFile); !os.IsNotExist(err) {
		t.Fatalf("expected original file moved out to quarantine")
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/quarantine/list", nil)
	listRec := httptest.NewRecorder()
	h.ServeHTTP(listRec, listReq)
	var ql struct {
		Items []QuarantineItem `json:"items"`
	}
	json.Unmarshal(listRec.Body.Bytes(), &ql)
	if len(ql.Items) != 1 {
		t.Fatalf("quarantine list count = %d, want 1 (%s)", len(ql.Items), listRec.Body.String())
	}

	resReq := httptest.NewRequest(http.MethodPost, "/api/quarantine/restore", strings.NewReader(`{"quarantined_path":`+jsonString(ql.Items[0].QuarantinedPath)+`}`))
	resRec := httptest.NewRecorder()
	h.ServeHTTP(resRec, resReq)
	if resRec.Code != http.StatusOK {
		t.Fatalf("restore = %d %s", resRec.Code, resRec.Body.String())
	}
	if _, err := os.Stat(badFile); err != nil {
		t.Fatalf("expected restored file at %s: %v", badFile, err)
	}

	// 4. Dashboard summary reflects scan & desktop mode.
	dashReq := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	dashRec := httptest.NewRecorder()
	h.ServeHTTP(dashRec, dashReq)
	if dashRec.Code != http.StatusOK || !strings.Contains(dashRec.Body.String(), `"desktop_mode":true`) || !strings.Contains(dashRec.Body.String(), `"total_scans":1`) {
		t.Fatalf("dashboard = %d %s", dashRec.Code, dashRec.Body.String())
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
