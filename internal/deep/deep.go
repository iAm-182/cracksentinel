package deep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gamecrack-scanner/internal/mcpclient"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/pe"
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

	if gob := find("go_binary"); gob != "" && looksLikeGo(path) {
		txt, err := c.CallToolText(gob, map[string]any{"path": path})
		if err != nil {
			rep.Errors = append(rep.Errors, "inspect_go_binary: "+truncate(txt, 200))
		} else if gi := parseGoInfo(txt); gi != nil {
			rep.Go = gi
		} else {
			rep.Errors = append(rep.Errors, "inspect_go_binary: unrecognized output")
		}
	}
	if mfa := find("managed_artifact"); mfa != "" && looksLikeDotnet(path) {
		txt, err := c.CallToolText(mfa, map[string]any{"path": path, "detail": "summary"})
		if err != nil {
			// Fall back to the default (complete) detail level.
			txt, err = c.CallToolText(mfa, map[string]any{"path": path})
		}
		if err != nil {
			rep.Errors = append(rep.Errors, "inspect_managed_artifact: "+truncate(txt, 200))
		} else if di := parseDotnetInfo(txt); di != nil {
			rep.Dotnet = di
		} else {
			rep.Errors = append(rep.Errors, "inspect_managed_artifact: unrecognized output")
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
	if rep.Go != nil {
		fmt.Printf("  go: %s module=%s deps=%d\n", rep.Go.GoVersion, rep.Go.ModulePath, len(rep.Go.Deps))
	}
	if rep.Dotnet != nil {
		fmt.Printf("  dotnet: assembly=%s version=%s target=%s\n", rep.Dotnet.Assembly, rep.Dotnet.Version, rep.Dotnet.Target)
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

// looksLikeGo reports whether the file carries a Go build-info stamp, so the
// (slow) inspect_go_binary call is only made when it can succeed. The stamp
// can sit anywhere in the file, so stream the whole thing for the needle.
func looksLikeGo(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	needle := []byte("Go buildinf:")
	// 12-byte needle: keep a 15-byte overlap between 1MB windows.
	const win = 1 << 20
	buf := make([]byte, win+15)
	var carry int
	for {
		n, err := f.Read(buf[carry:])
		total := carry + n
		if total >= len(needle) {
			for i := 0; i+len(needle) <= total; i++ {
				match := true
				for j := range needle {
					if buf[i+j] != needle[j] {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
		if err != nil {
			return false
		}
		copy(buf, buf[total-15:total])
		carry = 15
	}
}

// looksLikeDotnet reports whether the PE has a CLR header (dd[14]).
func looksLikeDotnet(path string) bool {
	info, err := pe.Analyze(path)
	if err != nil {
		return false
	}
	return info.Dotnet
}

type goEvidence struct {
	NormalizedResult struct {
		BuildInfo struct {
			GoVersion string `json:"go_version"`
			Module    struct {
				Path string `json:"path"`
				Main struct {
					Path    string `json:"path"`
					Version string `json:"version"`
				} `json:"main"`
				Dependencies []struct {
					Path    string `json:"path"`
					Version string `json:"version"`
				} `json:"dependencies"`
				Settings []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"settings"`
			} `json:"module"`
		} `json:"build_info"`
	} `json:"normalized_result"`
}

func parseGoInfo(txt string) *model.GoInfo {
	var ev goEvidence
	if err := json.Unmarshal([]byte(txt), &ev); err != nil {
		return nil
	}
	bi := ev.NormalizedResult.BuildInfo
	if bi.GoVersion == "" && bi.Module.Path == "" {
		return nil
	}
	gi := &model.GoInfo{
		GoVersion:  bi.GoVersion,
		ModulePath: bi.Module.Path,
		MainPath:   bi.Module.Main.Path,
		MainVer:    bi.Module.Main.Version,
		Settings:   map[string]string{},
	}
	for _, d := range bi.Module.Dependencies {
		gi.Deps = append(gi.Deps, model.GoDep{Path: d.Path, Ver: d.Version})
	}
	for _, s := range bi.Module.Settings {
		gi.Settings[s.Key] = s.Value
	}
	return gi
}

// parseDotnetInfo extracts the widely-present managed fields without assuming
// an exact schema (shapes vary by detail level). Anything unrecognized stays
// in Summary so no evidence is lost.
func parseDotnetInfo(txt string) *model.DotnetInfo {
	var raw map[string]any
	if err := json.Unmarshal([]byte(txt), &raw); err != nil {
		return nil
	}
	nr, _ := raw["normalized_result"].(map[string]any)
	if nr == nil {
		nr = raw
	}
	di := &model.DotnetInfo{
		Assembly: findKey(nr, "assembly_name", "assembly", "name"),
		Version:  findKey(nr, "assembly_version", "version", "assemblyversion"),
		Target:   findKey(nr, "target_framework", "framework", "targetframework"),
		Module:   findKey(nr, "module", "module_name", "modulename"),
		MVID:     findKey(nr, "mvid", "module_version_id"),
	}
	if s := findKey(nr, "summary", "description"); s != "" {
		di.Summary = truncate(s, 400)
	} else {
		di.Summary = truncate(firstLine(txt, 400), 400)
	}
	if di.Assembly == "" && di.Version == "" && di.Target == "" && di.Module == "" && di.MVID == "" {
		return nil
	}
	return di
}

// findKey searches a nested structure for a key with a scalar string value.
//
// The names are a PRIORITY LIST: "assembly_name" is preferred over
// "assembly", which is preferred over "name". The previous implementation
// treated the list as a set and walked the tree in Go's randomized map
// iteration order, so a structure holding both identity.assembly and
// module.name returned one or the other at random — the same binary could
// report a different assembly name on every run, and the result differed
// between Windows and Linux.
//
// The search is breadth-first (a shallower match wins) and the keys within
// a level are visited in sorted order, so the result is deterministic.
func findKey(m map[string]any, names ...string) string {
	for _, name := range names {
		if s := findKeyOne(m, strings.ToLower(name), 0); s != "" {
			return s
		}
	}
	return ""
}

// findKeyOne finds a single key name anywhere in the tree.
func findKeyOne(m map[string]any, name string, depth int) string {
	if depth > 6 {
		return ""
	}
	level := []map[string]any{m}
	for d := 0; d <= 6 && len(level) > 0; d++ {
		var next []map[string]any
		for _, obj := range level {
			keys := make([]string, 0, len(obj))
			for k := range obj {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if strings.ToLower(k) == name {
					if s, ok := obj[k].(string); ok && s != "" {
						return s
					}
				}
			}
			for _, k := range keys {
				if sub, ok := obj[k].(map[string]any); ok {
					next = append(next, sub)
				}
			}
		}
		level = next
	}
	return ""
}
