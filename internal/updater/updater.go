package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gamecrack-scanner/internal/filetype"
)

const (
	DefaultRepo    = "iAm-182/cracksentinel"
	defaultAPIBase = "https://api.github.com"
)

// ReleaseInfo describes the latest GitHub Release compared to the running build.
type ReleaseInfo struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Available      bool   `json:"available"`
	ReleaseURL     string `json:"release_url"`
	PublishedAt    string `json:"published_at,omitempty"`
	Notes          string `json:"notes,omitempty"`
	DesktopURL     string `json:"desktop_url,omitempty"`
	ScannerURL     string `json:"scanner_url,omitempty"`
	ChecksumsURL   string `json:"checksums_url,omitempty"`
	CheckedAt      string `json:"checked_at"`
	Error          string `json:"error,omitempty"`
}

type ghRelease struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckLatest queries GitHub Releases API for the newest published version.
func CheckLatest(ctx context.Context, currentVersion, repo string) ReleaseInfo {
	return checkLatestFrom(ctx, defaultAPIBase, currentVersion, repo)
}

func checkLatestFrom(ctx context.Context, apiBase, currentVersion, repo string) ReleaseInfo {
	if repo == "" {
		repo = DefaultRepo
	}
	info := ReleaseInfo{
		CurrentVersion: normalizeVer(currentVersion),
		CheckedAt:      time.Now().Format("2006-01-02 15:04:05"),
	}
	url := strings.TrimRight(apiBase, "/") + "/repos/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "CrackSentinel/"+info.CurrentVersion)

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		info.Error = "gagal menghubungi GitHub Releases: " + err.Error()
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		info.LatestVersion = info.CurrentVersion
		info.Error = "belum ada rilis di GitHub"
		return info
	}
	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("GitHub API HTTP %d", resp.StatusCode)
		return info
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&rel); err != nil {
		info.Error = "invalid GitHub response: " + err.Error()
		return info
	}
	info.LatestVersion = normalizeVer(rel.TagName)
	info.ReleaseURL = rel.HTMLURL
	info.PublishedAt = rel.PublishedAt
	info.Notes = strings.TrimSpace(rel.Body)
	if len(info.Notes) > 2000 {
		info.Notes = info.Notes[:2000] + "\n..."
	}
	for _, a := range rel.Assets {
		low := strings.ToLower(a.Name)
		switch low {
		case "cracksentinel.exe":
			info.DesktopURL = a.BrowserDownloadURL
		case "scanner.exe":
			info.ScannerURL = a.BrowserDownloadURL
		case "checksums.txt", "sha256sums.txt":
			info.ChecksumsURL = a.BrowserDownloadURL
		}
	}
	info.Available = CompareVersions(info.LatestVersion, info.CurrentVersion) > 0
	return info
}

// CompareVersions compares two semver strings (e.g. "2.0.0" vs "1.9.3").
// Returns 1 if a > b, -1 if a < b, 0 if equal.
func CompareVersions(a, b string) int {
	pa := parseVer(a)
	pb := parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] > pb[i] {
			return 1
		}
		if pa[i] < pb[i] {
			return -1
		}
	}
	return 0
}

func normalizeVer(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if i := strings.IndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	return v
}

func parseVer(v string) [3]int {
	var out [3]int
	parts := strings.Split(normalizeVer(v), ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		out[i], _ = strconv.Atoi(parts[i])
	}
	return out
}

// ApplyWindowsUpdate downloads the verified release binary, verifies its
// SHA-256 against checksums.txt (mandatory when checksums.txt is published),
// performs a safe atomic rename swap on Windows, and optionally updates
// sibling scanner.exe too. Caller should launch exePath and exit.
func ApplyWindowsUpdate(ctx context.Context, info ReleaseInfo, exePath string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("auto-update binary swap hanya didukung di Windows")
	}
	if !info.Available {
		return fmt.Errorf("sudah menggunakan versi terbaru (%s)", info.CurrentVersion)
	}
	targetAssetName := "CrackSentinel.exe"
	downloadURL := info.DesktopURL
	if strings.EqualFold(filepath.Base(exePath), "scanner.exe") {
		targetAssetName = "scanner.exe"
		downloadURL = info.ScannerURL
	}
	if downloadURL == "" {
		return fmt.Errorf("file %s tidak ditemukan di rilis GitHub %s", targetAssetName, info.LatestVersion)
	}

	checksums := map[string]string{}
	if info.ChecksumsURL != "" {
		var err error
		checksums, err = fetchChecksums(ctx, info.ChecksumsURL)
		if err != nil {
			return fmt.Errorf("gagal mengunduh checksums.txt: %w", err)
		}
	}

	expected := checksums[strings.ToLower(targetAssetName)]
	if len(checksums) > 0 && expected == "" {
		return fmt.Errorf("checksum SHA-256 untuk %s tidak ditemukan di checksums.txt", targetAssetName)
	}

	if err := downloadAndSwapPE(ctx, downloadURL, exePath, expected); err != nil {
		return err
	}

	// Best-effort update of sibling scanner.exe when updating CrackSentinel.exe.
	if strings.EqualFold(targetAssetName, "CrackSentinel.exe") && info.ScannerURL != "" {
		sib := filepath.Join(filepath.Dir(exePath), "scanner.exe")
		if _, err := os.Stat(sib); err == nil {
			_ = downloadAndSwapPE(ctx, info.ScannerURL, sib, checksums["scanner.exe"])
		}
	}
	return nil
}

func downloadAndSwapPE(ctx context.Context, url, dstPath, expectedSHA string) error {
	tmpPath := dstPath + ".new"
	_ = os.Remove(tmpPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "CrackSentinel-Updater")
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download gagal: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, 128<<20))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}

	gotSHA := hex.EncodeToString(h.Sum(nil))
	if expectedSHA != "" && !strings.EqualFold(gotSHA, expectedSHA) {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("verifikasi SHA-256 GAGAL (diharapkan %s, didapat %s)", expectedSHA[:12], gotSHA[:12])
	}
	if !filetype.HasValidPEHeader(tmpPath) {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("file update yang diunduh bukan executable Windows (PE) yang valid")
	}

	oldPath := dstPath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(dstPath, oldPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("gagal mengganti binary berjalan: %w", err)
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		// Roll back cleanly if final move failed.
		_ = os.Rename(oldPath, dstPath)
		_ = os.Remove(tmpPath)
		return fmt.Errorf("gagal memasang binary baru: %w", err)
	}
	return nil
}

func fetchChecksums(ctx context.Context, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CrackSentinel-Updater")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}
	return ParseChecksums(string(body)), nil
}

// ParseChecksums parses standard sha256sum output ("<hash>  <filename>").
func ParseChecksums(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		hash := strings.ToLower(fields[0])
		if len(hash) != 64 {
			continue
		}
		name := strings.ToLower(filepath.Base(strings.TrimPrefix(fields[1], "*")))
		out[name] = hash
	}
	return out
}

// CleanupOldBinary removes leftover *.old binaries left behind after a self-update.
func CleanupOldBinary(exePath string) {
	if exePath == "" {
		return
	}
	_ = os.Remove(exePath + ".old")
	_ = os.Remove(filepath.Join(filepath.Dir(exePath), "scanner.exe.old"))
}

// Relaunch starts the updated executable cleanly.
func Relaunch(exePath string) error {
	cmd := exec.Command(exePath)
	cmd.Dir = filepath.Dir(exePath)
	return cmd.Start()
}
