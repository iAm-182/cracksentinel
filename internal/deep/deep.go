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
	"gamecrack-scanner/internal/obf"
	"gamecrack-scanner/internal/pe"
)

var iocPatterns = []string{
	obf.S("LT84MjU1MQ=="), obf.S("PjMpOTUoPg=="), obf.S("Lj82Pz0oOzc="), obf.S("HT8uGykjNDkRPyMJLjsuPw=="), obf.S("CT8uDTM0PjUtKRI1NTEfIg=="),
	obf.S("LTs2Nj8udD47Lg=="), obf.S("FjU9MzR6HjsuOw=="), obf.S("OTU1MTM/KXQpKzYzLj8="), obf.S("GSgjKi4PNCooNS4/OS4eOy47"),
	obf.S("DwgWHjUtNDY1Oz4ONRwzNj8="), obf.S("GSg/Oy4/CD83NS4/DjIoPzs+"), obf.S("DSgzLj8KKDU5PykpFz83NSgj"), obf.S("DDMoLi87Nhs2NjU5HyI="),
	obf.S("KjUtPygpMj82Ng=="), obf.S("OTc+dD8iPw=="), obf.S("KTkyLjspMSk="), obf.S("OTUqI3czLj83"), obf.S("Mi4uKmB1dQ=="),
}

var suspiciousFuncs = []string{
	obf.S("HT8uGykjNDkRPyMJLjsuPw=="), obf.S("CT8uDTM0PjUtKRI1NTEfIg=="), obf.S("DSgzLj8KKDU5PykpFz83NSgj"), obf.S("GSg/Oy4/CD83NS4/DjIoPzs+"),
	obf.S("DDMoLi87Nhs2NjU5HyI="), obf.S("GSgjKi4PNCooNS4/OS4eOy47"), obf.S("DwgWHjUtNDY1Oz4ONRwzNj8="), obf.S("DTM0HyI/OQ=="),
}

func reaCommand() []string {
	if v := os.Getenv(obf.S("CB8bBRcZCgUZFRcXGxQe")); v != obf.S("") {
		return strings.Fields(v)
	}
	return []string{obf.S("OTc+dD8iPw=="), obf.S("dT4="), obf.S("dTk="), obf.S("NCoi"), obf.S("dyM="), obf.S("KD87dzs9PzQuKRpsdG90ag=="), obf.S("Nzkq")}
}

func RunReport(path string, timeout time.Duration) (*model.DeepReport, error) {
	t0 := time.Now()
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	rep := &model.DeepReport{}

	c, err := mcpclient.Spawn(reaCommand(), nil, timeout)
	if err != nil {
		return rep, fmt.Errorf(obf.S("KSo7LTR6CB8behcZCmB6fy0="), err)
	}
	defer c.Close()

	if err := c.Initialize(obf.S("PTs3PzkoOzkxdz4/Pyo=")); err != nil {
		return rep, fmt.Errorf(obf.S("MzQzLjM7NjMgP3oIHxt6FxkKYHp/LQ=="), err)
	}
	tools, err := c.ListTools()
	if err != nil {
		return rep, fmt.Errorf(obf.S("LjU1Nil1NjMpLmB6fy0="), err)
	}
	rep.ServerTools = len(tools)
	rep.Available = len(tools) > 0

	find := func(sub string) string {
		for _, t := range tools {
			if strings.Contains(strings.ToLower(t.Name), strings.ToLower(sub)) {
				return t.Name
			}
		}
		return obf.S("")
	}

	open := find(obf.S("NSo/NAU4MzQ7KCM="))
	if open == obf.S("") {
		open = find(obf.S("NSo/NAU="))
	}
	if open != obf.S("") {
		txt, err := c.CallToolText(open, map[string]any{obf.S("KjsuMg=="): path})
		rep.OpenOut = truncate(txt, 2000)
		if err != nil {
			rep.Errors = append(rep.Errors, obf.S("NSo/NAU4MzQ7KCNgeg==")+truncate(txt, 200))
		}
	} else {
		rep.Errors = append(rep.Errors, obf.S("NDV6NSo/NAU4MzQ7KCN6LjU1Nno1NHoIHxt6KT8oLD8o"))
	}

	ss := find(obf.S("KT87KDkyBSkuKDM0PSk="))
	if ss == obf.S("") {
		ss = find(obf.S("KS4oMzQ9KQ=="))
	}
	if ss != obf.S("") {
		for _, p := range iocPatterns {
			txt, err := c.CallToolText(ss, tryArgs(obf.S("KjsuLj8oNA=="), p))
			if err != nil {
				continue
			}
			if strings.TrimSpace(txt) == obf.S("") {
				continue
			}
			rep.StringHits = append(rep.StringHits, model.DeepStringHit{Pattern: p, Output: truncate(txt, 600)})
		}
	} else {
		rep.Errors = append(rep.Errors, obf.S("NDV6KS4oMzQ9dyk/Oyg5MnouNTU2ejU0eggfG3opPygsPyg="))
	}

	lp := find(obf.S("NjMpLgUqKDU5Pz4vKD8p"))
	if lp != obf.S("") {
		txt, _ := c.CallToolText(lp, map[string]any{obf.S("NjM3My4="): 1000})
		rep.Procedures = procCount(txt)
	}

	sp := find(obf.S("KT87KDkyBSooNTk/Pi8oPyk="))
	pc := find(obf.S("Kig1OT8+Lyg/BSopPy8+NQU5NT4/"))
	if pc == obf.S("") {
		pc = find(obf.S("Kik/Lz41BTk1Pj8="))
	}
	if pc == obf.S("") {
		pc = find(obf.S("OzQ7NiMgPwU8LzQ5LjM1NA=="))
	}
	if sp != obf.S("") && pc != obf.S("") {
		for _, fn := range suspiciousFuncs {
			txt, err := c.CallToolText(sp, tryArgs(obf.S("KjsuLj8oNA=="), fn))
			if err != nil || strings.TrimSpace(txt) == obf.S("") || !hasMatches(txt) {
				continue
			}
			for _, name := range procNames(txt) {
				code, _ := c.CallToolText(pc, tryArgs(obf.S("Kig1OT8+Lyg/"), name))
				rep.FuncHits = append(rep.FuncHits, model.DeepFuncHit{Name: name, Pseudcode: truncate(code, 1500)})
			}
		}
	} else {
		rep.Errors = append(rep.Errors, obf.S("Kig1OT8+Lyg/eik/Oyg5MnUqKT8vPjU5NT4/ei41NTYpejQ1Lno8NS80Pg=="))
	}

	if gob := find(obf.S("PTUFODM0Oygj")); gob != obf.S("") && looksLikeGo(path) {
		txt, err := c.CallToolText(gob, map[string]any{obf.S("KjsuMg=="): path})
		if err != nil {
			rep.Errors = append(rep.Errors, obf.S("MzQpKj85LgU9NQU4MzQ7KCNgeg==")+truncate(txt, 200))
		} else if gi := parseGoInfo(txt); gi != nil {
			rep.Go = gi
		} else {
			rep.Errors = append(rep.Errors, obf.S("MzQpKj85LgU9NQU4MzQ7KCNgei80KD85NT00MyA/Pno1Ly4qLy4="))
		}
	}
	if mfa := find(obf.S("Nzs0Oz0/PgU7KC4zPDs5Lg==")); mfa != obf.S("") && looksLikeDotnet(path) {
		txt, err := c.CallToolText(mfa, map[string]any{obf.S("KjsuMg=="): path, obf.S("Pj8uOzM2"): obf.S("KS83NzsoIw==")})
		if err != nil {
			// Fall back to the default (complete) detail level.
			txt, err = c.CallToolText(mfa, map[string]any{obf.S("KjsuMg=="): path})
		}
		if err != nil {
			rep.Errors = append(rep.Errors, obf.S("MzQpKj85LgU3OzQ7PT8+BTsoLjM8OzkuYHo=")+truncate(txt, 200))
		} else if di := parseDotnetInfo(txt); di != nil {
			rep.Dotnet = di
		} else {
			rep.Errors = append(rep.Errors, obf.S("MzQpKj85LgU3OzQ7PT8+BTsoLjM8OzkuYHovNCg/OTU9NDMgPz56NS8uKi8u"))
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
	b, _ := json.MarshalIndent(rep, obf.S(""), obf.S("eno="))
	if outPath != obf.S("") {
		if err := os.WriteFile(outPath, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, obf.S("LSgzLj96Pj8/KnooPyo1KC56PygoNShg"), err)
		} else {
			fmt.Println(obf.S("Hj8/KnooPyo1KC5g"), outPath)
		}
	}
	fmt.Printf(obf.S("CB8bej4/Pyp3PjMsP2B6fylQ"), path)
	fmt.Printf(obf.S("enouNTU2KXo1NHopPygsPyh6YHp/PlA="), rep.ServerTools)
	fmt.Printf(obf.S("enoqKDU5Pz4vKD8penp6enp6YHp/PlA="), rep.Procedures)
	fmt.Printf(obf.S("enopLigzND16ExUZejIzLil6YHp/PlA="), len(rep.StringHits))
	for _, h := range rep.StringHits {
		fmt.Printf(obf.S("enp6end6f3doaCl6fylQ"), h.Pattern, firstLine(h.Output, 90))
	}
	fmt.Printf(obf.S("enopLykqMzkzNS8pejwvNDkpYHp/PlA="), len(rep.FuncHits))
	for _, f := range rep.FuncHits {
		fmt.Printf(obf.S("enp6end6fyl6cn8+ejkyOygpeiopPy8+NTk1Pj9zUA=="), f.Name, len(f.Pseudcode))
	}
	if rep.Go != nil {
		fmt.Printf(obf.S("eno9NWB6fyl6NzU+LzY/Z38pej4/Kilnfz5Q"), rep.Go.GoVersion, rep.Go.ModulePath, len(rep.Go.Deps))
	}
	if rep.Dotnet != nil {
		fmt.Printf(obf.S("eno+NS40Py5gejspKT83ODYjZ38peiw/KCkzNTRnfyl6LjsoPT8uZ38pUA=="), rep.Dotnet.Assembly, rep.Dotnet.Version, rep.Dotnet.Target)
	}
	if len(rep.Errors) > 0 {
		fmt.Printf(obf.S("enotOyg0MzQ9KWB6fylQ"), strings.Join(rep.Errors, obf.S("YXo=")))
	}
	fmt.Printf(obf.S("eno/NjsqKT8+YHp/Pno3KVA="), rep.ElapsedMs)
	return nil
}

func tryArgs(key, val string) map[string]any {
	return map[string]any{key: val}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + obf.S("dHR0")
}

func firstLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return truncate(s, n)
}

func hasMatches(s string) bool {
	if strings.Contains(s, obf.S("eCg7LQUoPykvNi54YAEH")) || strings.Contains(s, obf.S("eDQ1KDc7NjMgPz4FKD8pLzYueGABBw==")) {
		return strings.Contains(s, obf.S("eCg7LQUoPykvNi54YAEh")) || strings.Contains(s, obf.S("eDQ1KDc7NjMgPz4FKD8pLzYueGABIQ=="))
	}
	return s != obf.S("")
}

var reProcName = regexp.MustCompile(obf.S("eDQ7Nz94BilwYAYpcHhyAQR4ByFrdmtoaidzeA=="))

func procNames(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reProcName.FindAllStringSubmatch(s, -1) {
		n := m[1]
		if seen[n] || strings.Contains(n, obf.S("dD8iPw==")) {
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
	if m := regexp.MustCompile(obf.S("eDk1LzQueAYpcGAGKXByBj5xcw==")).FindStringSubmatch(s); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			return n
		}
	}
	return countLines(s)
}

func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, obf.S("UA==")) {
		if strings.TrimSpace(line) != obf.S("") {
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
	needle := []byte(obf.S("HTV6OC8zNj4zNDxg"))
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
	if bi.GoVersion == obf.S("") && bi.Module.Path == obf.S("") {
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
	nr, _ := raw[obf.S("NDUoNzs2MyA/PgUoPykvNi4=")].(map[string]any)
	if nr == nil {
		nr = raw
	}
	di := &model.DotnetInfo{
		Assembly: findKey(nr, obf.S("OykpPzc4NiMFNDs3Pw=="), obf.S("OykpPzc4NiM="), obf.S("NDs3Pw==")),
		Version:  findKey(nr, obf.S("OykpPzc4NiMFLD8oKTM1NA=="), obf.S("LD8oKTM1NA=="), obf.S("OykpPzc4NiMsPygpMzU0")),
		Target:   findKey(nr, obf.S("LjsoPT8uBTwoOzc/LTUoMQ=="), obf.S("PCg7Nz8tNSgx"), obf.S("LjsoPT8uPCg7Nz8tNSgx")),
		Module:   findKey(nr, obf.S("NzU+LzY/"), obf.S("NzU+LzY/BTQ7Nz8="), obf.S("NzU+LzY/NDs3Pw==")),
		MVID:     findKey(nr, obf.S("NywzPg=="), obf.S("NzU+LzY/BSw/KCkzNTQFMz4=")),
	}
	if s := findKey(nr, obf.S("KS83NzsoIw=="), obf.S("Pj8pOSgzKi4zNTQ=")); s != obf.S("") {
		di.Summary = truncate(s, 400)
	} else {
		di.Summary = truncate(firstLine(txt, 400), 400)
	}
	if di.Assembly == obf.S("") && di.Version == obf.S("") && di.Target == obf.S("") && di.Module == obf.S("") && di.MVID == obf.S("") {
		return nil
	}
	return di
}

// findKey searches a nested structure for a key with a scalar string value.
//
// The names are a PRIORITY LIST: obf.S("OykpPzc4NiMFNDs3Pw==") is preferred over
// obf.S("OykpPzc4NiM="), which is preferred over obf.S("NDs3Pw=="). The previous implementation
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
		if s := findKeyOne(m, strings.ToLower(name), 0); s != obf.S("") {
			return s
		}
	}
	return obf.S("")
}

// findKeyOne finds a single key name anywhere in the tree.
func findKeyOne(m map[string]any, name string, depth int) string {
	if depth > 6 {
		return obf.S("")
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
					if s, ok := obj[k].(string); ok && s != obf.S("") {
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
	return obf.S("")
}
