package motw

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gamecrack-scanner/internal/model"
)

// ZoneNames maps Windows URLZONE values from :Zone.Identifier ADS.
var zoneNames = map[int]string{
	0: "Local Machine",
	1: "Local Intranet",
	2: "Trusted Sites",
	3: "Internet",
	4: "Restricted Sites",
}

// Read inspects the Windows NTFS Alternate Data Stream "<path>:Zone.Identifier"
// (Mark of the Web). On non-NTFS volumes or non-Windows OSes this returns nil.
func Read(path string) *model.DownloadSource {
	data, err := os.ReadFile(path + ":Zone.Identifier")
	if err != nil || len(data) == 0 {
		return nil
	}
	return ParseZoneIdentifier(string(data))
}

// ParseZoneIdentifier parses the INI-like contents of a Zone.Identifier stream.
func ParseZoneIdentifier(content string) *model.DownloadSource {
	src := &model.DownloadSource{ZoneID: -1}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "zoneid":
			if id, err := strconv.Atoi(v); err == nil {
				src.ZoneID = id
				src.ZoneName = zoneNames[id]
			}
		case "hosturl":
			src.HostURL = v
			src.HostDomain = extractDomain(v)
		case "referrerurl":
			src.ReferrerURL = v
		}
	}
	if src.ZoneID < 0 && src.HostURL == "" && src.ReferrerURL == "" {
		return nil
	}
	if src.HostDomain == "" && src.ReferrerURL != "" {
		src.HostDomain = extractDomain(src.ReferrerURL)
	}
	return src
}

func extractDomain(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	return strings.TrimPrefix(h, "www.")
}

// URLAssessment is the pre-download / download-origin risk report shared by
// the MOTW scanner, the local Web UI URL pre-checker, and the browser extension.
type URLAssessment struct {
	URL           string          `json:"url"`
	Referrer      string          `json:"referrer,omitempty"`
	Filename      string          `json:"filename,omitempty"`
	FinalURL      string          `json:"final_url,omitempty"`
	Domain        string          `json:"domain,omitempty"`
	RedirectChain []string        `json:"redirect_chain,omitempty"`
	ContentLength int64           `json:"content_length,omitempty"`
	ContentType   string          `json:"content_type,omitempty"`
	Score         int             `json:"score"`
	Verdict       string          `json:"verdict"`
	Findings      []model.Finding `json:"findings,omitempty"`
}

var (
	reNumericSLD  = regexp.MustCompile(`^[0-9]{7,}$`)
	reGibberish   = regexp.MustCompile(`^[a-z0-9]{8,}$`)
	reRepackWords = regexp.MustCompile(`(?i)(repack|fitgirl|dodi|elamigos|deluxe|edition|multi[0-9]+|goty|crack|full[\s._-]?game)`)
)

var riskyTLDs = map[string]bool{
	"store": true, "top": true, "xyz": true, "click": true, "shop": true,
	"buzz": true, "cfd": true, "sbs": true, "cyou": true, "icu": true,
	"tk": true, "ml": true, "ga": true, "cf": true, "gq": true,
	"vip": true, "club": true, "loan": true, "work": true, "cam": true,
}

var trustedDomains = map[string]bool{
	"steampowered.com": true, "steamstatic.com": true, "epicgames.com": true,
	"gog.com": true, "itch.io": true, "microsoft.com": true, "windows.com": true,
	"github.com": true, "objects.githubusercontent.com": true, "gitlab.com": true,
	"nexusmods.com": true, "moddb.com": true, "archive.org": true,
}

var abusedDropHosts = map[string]string{
	"cdn.discordapp.com":        "Discord CDN (commonly abused to host stealer payloads)",
	"media.discordapp.net":      "Discord media CDN (commonly abused to host payloads)",
	"api.telegram.org":          "Telegram Bot API file host",
	"pastebin.com":              "Pastebin raw payload host",
	"paste.ee":                  "Paste.ee raw payload host",
	"raw.githubusercontent.com": "GitHub raw file (unverified direct binary/script download)",
}

var highRiskScriptWebExts = map[string]bool{
	".hta": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true,
	".wsf": true, ".bat": true, ".cmd": true, ".ps1": true, ".lnk": true,
	".pif": true, ".scr": true, ".cpl": true, ".msi": true,
}

var docExts = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".txt": true,
	".mp4": true, ".mp3": true, ".zip": true, ".rar": true, ".iso": true,
}

var execExts = map[string]bool{
	".exe": true, ".scr": true, ".com": true, ".pif": true, ".bat": true,
	".cmd": true, ".ps1": true, ".vbs": true, ".js": true, ".hta": true,
	".msi": true, ".lnk": true,
}

// AnalyzeURL evaluates a download URL, optional referrer, filename and byte
// size without downloading or executing the target.
func AnalyzeURL(rawURL, referrer, filename string, sizeBytes int64) URLAssessment {
	out := URLAssessment{
		URL:           rawURL,
		Referrer:      referrer,
		Filename:      filename,
		ContentLength: sizeBytes,
		Verdict:       "CLEAN",
	}
	u, err := url.Parse(rawURL)
	if err == nil && u.Hostname() != "" {
		out.Domain = strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
		if out.Filename == "" && u.Path != "" {
			base := filepath.Base(u.Path)
			if base != "." && base != "/" && base != "\\" {
				out.Filename = base
			}
		}
	}
	refDomain := extractDomain(referrer)

	// Trusted publisher check (only when URL is https and host matches exactly or subdomain).
	if u != nil && strings.EqualFold(u.Scheme, "https") && isTrustedDomain(out.Domain) {
		out.Findings = append(out.Findings, model.Finding{
			Rule: "url_trusted_host", Category: "info", Severity: 0,
			Detail: "downloaded from known legitimate host: " + out.Domain,
		})
	} else {
		checkHostRisk(&out.Findings, out.Domain, "download host")
	}

	if refDomain != "" && refDomain != out.Domain && !isTrustedDomain(refDomain) {
		checkHostRisk(&out.Findings, refDomain, "referrer")
	}

	// Abused file-drop hosts serving executables/scripts.
	if desc, ok := abusedDropHosts[out.Domain]; ok {
		ext := strings.ToLower(filepath.Ext(out.Filename))
		if execExts[ext] || ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == "" {
			out.Findings = append(out.Findings, model.Finding{
				Rule: "url_abused_host", Category: "download", Severity: 25,
				Detail: desc + " (" + out.Domain + ")",
			})
		}
	}

	// Plain HTTP download of executable/archive.
	if u != nil && strings.EqualFold(u.Scheme, "http") {
		ext := strings.ToLower(filepath.Ext(out.Filename))
		if execExts[ext] || ext == ".zip" || ext == ".rar" || ext == ".7z" {
			out.Findings = append(out.Findings, model.Finding{
				Rule: "url_insecure_http", Category: "download", Severity: 10,
				Detail: "executable/archive served over unencrypted HTTP (vulnerable to MITM replacement)",
			})
		}
	}

	// Filename checks.
	if out.Filename != "" {
		low := strings.ToLower(filepath.Base(out.Filename))
		ext := filepath.Ext(low)
		if hasDoubleExtName(low) {
			out.Findings = append(out.Findings, model.Finding{
				Rule: "url_double_extension", Category: "dropper", Severity: 45,
				Detail: "double extension in download filename: " + out.Filename,
			})
		}
		if highRiskScriptWebExts[ext] {
			out.Findings = append(out.Findings, model.Finding{
				Rule: "url_high_risk_ext", Category: "dropper", Severity: 30,
				Detail: "high-risk script/launcher downloaded directly from web: " + ext,
			})
		}
		// Decoy small repack heuristic (e.g. fake 25 MB "Far Cry Repack.zip" from decoy mirrors).
		if sizeBytes > 0 && sizeBytes < 45*1024*1024 && sizeBytes > 512*1024 &&
			(ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == ".exe") &&
			reRepackWords.MatchString(low) {
			out.Findings = append(out.Findings, model.Finding{
				Rule: "url_suspicious_small_repack", Category: "dropper", Severity: 20,
				Detail: fmt.Sprintf("file claims to be a game repack/edition (%s) but is only %.1f MB — common web decoy dropper pattern", out.Filename, float64(sizeBytes)/(1<<20)),
			})
		}
		// Password hint inside filename or URL query (classic AV-evasion dropper).
		if strings.Contains(low, "pass") && (strings.Contains(low, "123") || strings.Contains(low, "pw")) && (ext == ".zip" || ext == ".rar" || ext == ".7z") {
			out.Findings = append(out.Findings, model.Finding{
				Rule: "url_password_hint_archive", Category: "evasion", Severity: 25,
				Detail: "archive filename hints at a password — common web malware trick to evade antivirus",
			})
		}
	}

	score := 0
	for _, f := range out.Findings {
		score += f.Severity
	}
	if score > 100 {
		score = 100
	}
	out.Score = score
	switch {
	case score >= 70:
		out.Verdict = "MALICIOUS"
	case score >= 30:
		out.Verdict = "SUSPICIOUS"
	default:
		out.Verdict = "CLEAN"
	}
	return out
}

func checkHostRisk(findings *[]model.Finding, domain, role string) {
	if domain == "" {
		return
	}
	// Raw IP address as host.
	if net.ParseIP(domain) != nil {
		*findings = append(*findings, model.Finding{
			Rule: "url_raw_ip_host", Category: "download", Severity: 35,
			Detail: fmt.Sprintf("%s is a raw IP address (%s) instead of a domain", role, domain),
		})
		return
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return
	}
	tld := parts[len(parts)-1]
	sld := parts[len(parts)-2]

	// Numeric IP-lookalike domains like 192169531.com / 192169451.com (seen in fake game mirror chains).
	if reNumericSLD.MatchString(sld) {
		*findings = append(*findings, model.Finding{
			Rule: "url_numeric_decoy_domain", Category: "download", Severity: 40,
			Detail: fmt.Sprintf("%s uses a numeric IP-lookalike domain (%s) — classic malware redirect chain", role, domain),
		})
		return
	}
	// Disposable/risky TLD with random-looking SLD (high digit/consonant mix like mroat0j0w.store).
	if riskyTLDs[tld] && looksRandomLabel(sld) {
		*findings = append(*findings, model.Finding{
			Rule: "url_random_risky_domain", Category: "download", Severity: 30,
			Detail: fmt.Sprintf("%s uses a random-looking domain on high-abuse TLD .%s (%s)", role, tld, domain),
		})
	} else if riskyTLDs[tld] {
		*findings = append(*findings, model.Finding{
			Rule: "url_risky_tld", Category: "download", Severity: 12,
			Detail: fmt.Sprintf("%s uses high-abuse TLD .%s (%s)", role, tld, domain),
		})
	}
}

func looksRandomLabel(s string) bool {
	if !reGibberish.MatchString(s) {
		return false
	}
	digits, vowels := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == 'a' || r == 'e' || r == 'i' || r == 'o' || r == 'u':
			vowels++
		}
	}
	// Mix of digits + letters with low vowel ratio, or long low-vowel string.
	if digits >= 2 && vowels <= len(s)/4 {
		return true
	}
	return len(s) >= 9 && vowels <= 1
}

func isTrustedDomain(domain string) bool {
	if trustedDomains[domain] {
		return true
	}
	for td := range trustedDomains {
		if strings.HasSuffix(domain, "."+td) {
			return true
		}
	}
	return false
}

func hasDoubleExtName(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return false
	}
	return docExts["."+parts[len(parts)-2]] && execExts["."+parts[len(parts)-1]]
}

// ProbeURL performs a safe, non-executing HEAD request to trace redirect hops
// and inspect Content-Length / Content-Type / final destination before download.
func ProbeURL(ctx context.Context, rawURL, referrer string) URLAssessment {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		a := AnalyzeURL(rawURL, referrer, "", 0)
		a.Findings = append(a.Findings, model.Finding{
			Rule: "url_invalid", Category: "info", Severity: 0,
			Detail: "only http:// and https:// URLs can be probed",
		})
		return a
	}

	var chain []string
	chain = append(chain, rawURL)
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	tr := &http.Transport{
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(dctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if isBlockedSSRFIP(ip.IP) {
					return nil, fmt.Errorf("blocked private/internal IP %s", ip.IP.String())
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP resolved for %s", host)
			}
			return dialer.DialContext(dctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("blocked non-http redirect scheme %q", req.URL.Scheme)
			}
			chain = append(chain, req.URL.String())
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var finalURL = rawURL
	var contentLen int64
	var contentType string
	var cdFilename string

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	var probeErr string
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CrackSentinel-PreCheck/1.0")
		if referrer != "" {
			req.Header.Set("Referer", referrer)
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			finalURL = resp.Request.URL.String()
			contentLen = resp.ContentLength
			contentType = resp.Header.Get("Content-Type")
			cdFilename = parseContentDispositionFilename(resp.Header.Get("Content-Disposition"))
		} else if strings.Contains(err.Error(), "blocked private/internal IP") {
			probeErr = err.Error()
		}
	}

	a := AnalyzeURL(finalURL, referrer, cdFilename, contentLen)
	a.URL = rawURL
	a.FinalURL = finalURL
	a.RedirectChain = chain
	a.ContentType = contentType
	if probeErr != "" {
		a.Findings = append(a.Findings, model.Finding{
			Rule: "url_probe_blocked_private", Category: "info", Severity: 0,
			Detail: "HEAD probe blocked for safety: " + probeErr,
		})
	}

	// Multi-hop redirect chain across distinct domains is a major web decoy signal.
	uniqueDomains := map[string]bool{}
	for _, hop := range chain {
		if d := extractDomain(hop); d != "" {
			uniqueDomains[d] = true
		}
	}
	if len(chain) >= 4 && len(uniqueDomains) >= 3 {
		a.Findings = append(a.Findings, model.Finding{
			Rule: "url_deep_redirect_chain", Category: "download", Severity: 25,
			Detail: fmt.Sprintf("download bounced across %d hops (%d distinct domains) — typical malware/ad-network dropper chain", len(chain), len(uniqueDomains)),
		})
		a.Score += 25
		if a.Score > 100 {
			a.Score = 100
		}
		if a.Score >= 70 {
			a.Verdict = "MALICIOUS"
		} else if a.Score >= 30 {
			a.Verdict = "SUSPICIOUS"
		}
	}
	return a
}

func isBlockedSSRFIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// Block CGNAT / Tailscale range 100.64.0.0/10.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4[0] == 0 {
			return true
		}
	}
	return false
}

func parseContentDispositionFilename(cd string) string {
	for _, part := range strings.Split(cd, ";") {
		p := strings.TrimSpace(part)
		low := strings.ToLower(p)
		if strings.HasPrefix(low, "filename=") {
			v := strings.TrimSpace(p[len("filename="):])
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}
