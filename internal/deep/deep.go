package deep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gamecrack-scanner/internal/mcpclient"
	"gamecrack-scanner/internal/model"
)

var iocPatterns = []string{
	"webhook", "discord", "telegram", "GetAsyncKeyState", "SetWindowsHookEx",
	"wallet.dat", "Login Data", "cookies.sqlite", "CryptUnprotectData",
	"URLDownloadToFile", "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
	"powershell", "cmd.exe", "schtasks", "copy-item", "http://",
}

var suspiciousFuncs = []string{
	"GetAsyncKeyState", "SetWindowsHookEx", "WriteProcessMemory", "CreateRemoteThread",
	"VirtualAllocEx", "CryptUnprotectData", "URLDownloadToFile", "WinExec",
}

func reaCommand() []string {
	if v := os.Getenv("REA_MCP_COMMAND"); v != "" {
		return strings.Fields(v)
	}
	return []string{"cmd.exe", "/d", "/c", "npx", "-y", "rea-agents@6.5.0", "mcp"}
}

func RunReport(path string, timeout time.Duration) (*model.DeepReport, error) {
	t0 := time.Now()
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	rep := &model.DeepReport{}

	c, err := mcpclient.Spawn(reaCommand(), nil, timeout)
	if err != nil {
		return rep, fmt.Errorf("spawn REA MCP: %w", err)
	}
	defer c.Close()

	if err := c.Initialize("gamecrack-deep"); err != nil {
		return rep, fmt.Errorf("initialize REA MCP: %w", err)
	}
	tools, err := c.ListTools()
	if err != nil {
		return rep, fmt.Errorf("tools/list: %w", err)
	}
	rep.ServerTools = len(tools)
	rep.Available = len(tools) > 0

	find := func(sub string) string {
		for _, t := range tools {
			if strings.Contains(strings.ToLower(t.Name), strings.ToLower(sub)) {
				return t.Name
			}
		}
		return ""
	}

	open := find("open_binary")
	if open == "" {
		open = find("open_")
	}
	if open != "" {
		txt, err := c.CallToolText(open, map[string]any{"path": path})
		rep.OpenOut = truncate(txt, 2000)
		if err != nil {
			rep.Errors = append(rep.Errors, "open_binary: "+truncate(txt, 200))
		}
	} else {
		rep.Errors = append(rep.Errors, "no open_binary tool on REA server")
	}

	ss := find("search_strings")
	if ss == "" {
		ss = find("strings")
	}
	if ss != "" {
		for _, p := range iocPatterns {
			txt, err := c.CallToolText(ss, tryArgs("pattern", p))
			if err != nil {
				continue
			}
			if strings.TrimSpace(txt) == "" {
				continue
			}
			rep.StringHits = append(rep.StringHits, model.DeepStringHit{Pattern: p, Output: truncate(txt, 600)})
		}
	} else {
		rep.Errors = append(rep.Errors, "no string-search tool on REA server")
	}

	lp := find("list_procedures")
	if lp != "" {
		txt, _ := c.CallToolText(lp, map[string]any{"limit": 1000})
		rep.Procedures = procCount(txt)
	}

	sp := find("search_procedures")
	pc := find("procedure_pseudo_code")
	if pc == "" {
		pc = find("pseudo_code")
	}
	if pc == "" {
		pc = find("analyze_function")
	}
	if sp != "" && pc != "" {
		for _, fn := range suspiciousFuncs {
			txt, err := c.CallToolText(sp, tryArgs("pattern", fn))
			if err != nil || strings.TrimSpace(txt) == "" || !hasMatches(txt) {
				continue
			}
			for _, name := range procNames(txt) {
				code, _ := c.CallToolText(pc, tryArgs("procedure", name))
				rep.FuncHits = append(rep.FuncHits, model.DeepFuncHit{Name: name, Pseudcode: truncate(code, 1500)})
			}
		}
	} else {
		rep.Errors = append(rep.Errors, "procedure search/pseudocode tools not found")
	}

	if gob := find("go_binary"); gob != "" {
		txt, _ := c.CallToolText(gob, map[string]any{"path": path})
		if strings.Contains(txt, "Go build ID") || strings.Contains(txt, "module") {
			rep.Errors = append(rep.Errors, "GOBIN_INFO: "+truncate(firstLine(txt, 400), 400))
		}
	}
	if mfa := find("managed_artifact"); mfa != "" {
		txt, _ := c.CallToolText(mfa, map[string]any{"path": path})
		if strings.Contains(txt, ".NET") || strings.Contains(txt, "assembly") || strings.Contains(txt, "CLR") {
			rep.Errors = append(rep.Errors, "MANAGED_INFO: "+truncate(firstLine(txt, 400), 400))
		}
	}

	rep.ElapsedMs = time.Since(t0).Milliseconds()
	return rep, nil
}

func Run(path string, timeout time.Duration, outPath string) error {
	rep, err := RunReport(path, timeout)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	if outPath != "" {
		if err := os.WriteFile(outPath, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write deep report error:", err)
		} else {
			fmt.Println("Deep report:", outPath)
		}
	}
	fmt.Printf("REA deep-dive: %s\n", path)
	fmt.Printf("  tools on server : %d\n", rep.ServerTools)
	fmt.Printf("  procedures      : %d\n", rep.Procedures)
	fmt.Printf("  string IOC hits : %d\n", len(rep.StringHits))
	for _, h := range rep.StringHits {
		fmt.Printf("    - %-22s %s\n", h.Pattern, firstLine(h.Output, 90))
	}
	fmt.Printf("  suspicious funcs: %d\n", len(rep.FuncHits))
	for _, f := range rep.FuncHits {
		fmt.Printf("    - %s (%d chars pseudocode)\n", f.Name, len(f.Pseudcode))
	}
	if len(rep.Errors) > 0 {
		fmt.Printf("  warnings: %s\n", strings.Join(rep.Errors, "; "))
	}
	fmt.Printf("  elapsed: %d ms\n", rep.ElapsedMs)
	return nil
}

func tryArgs(key, val string) map[string]any {
	return map[string]any{key: val}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func firstLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return truncate(s, n)
}

func hasMatches(s string) bool {
	if strings.Contains(s, `"raw_result":[]`) || strings.Contains(s, `"normalized_result":[]`) {
		return strings.Contains(s, `"raw_result":[{`) || strings.Contains(s, `"normalized_result":[{`)
	}
	return s != ""
}

var reProcName = regexp.MustCompile(`"name"\s*:\s*"([^"]{1,120})"`)

func procNames(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reProcName.FindAllStringSubmatch(s, -1) {
		n := m[1]
		if seen[n] || strings.Contains(n, ".exe") {
			continue
		}
		seen[n] = true
		out = append(out, n)
		if len(out) >= 4 {
			break
		}
	}
	return out
}

func procCount(s string) int {
	if m := regexp.MustCompile(`"count"\s*:\s*(\d+)`).FindStringSubmatch(s); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			return n
		}
	}
	return countLines(s)
}

func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
