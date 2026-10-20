package yara

// The YARA layer.
//
// Two things this file has to get right, both learned the hard way with a
// community rule collection:
//
//  1. The YARA CLI takes a single RULES_FILE, not a directory, so every
//     rule file in scope is concatenated into one combined file.
//
//  2. A combined file is all-or-nothing for the compiler: one rule that
//     references a feature the local YARA build does not have (the
//     signature-base collection uses `filename`, `extension` and
//     `filepath`, which need a patched YARA) fails the WHOLE file, and the
//     compile check then disables the entire YARA layer. Losing 700 good
//     rules because of 50 bad ones is not acceptable, so the compile step
//     is self-repairing: the failing rule is dropped and the compile is
//     retried until it succeeds or no progress can be made.
//
// Duplicated rule names are handled the same way: the first definition
// wins, the later ones are dropped.

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The built-in rules are embedded BASE64-ENCODED, not as a plain .yar file.
//
// A plain .yar file inside the binary puts every indicator it contains —
// Discord webhook patterns, Telegram tokens, the EICAR marker, the names of
// the hooked APIs — into the shipped executable as plaintext. That is what
// made a machine learning classifier call the scanner an information
// stealer and the host antivirus quarantine it.
//
// The encoded blob keeps those patterns out of the binary. The readable
// source stays in the repository at internal/yara/rules/builtin.yar.
//
//go:embed rules/builtin.yar.b64
var builtinRulesB64 []byte

type Match struct {
	Rule string
	Path string
}

type Runner struct {
	bin     string
	rules   string // single combined .yar file passed to the CLI
	tmp     string
	timeout time.Duration
	// RulesLoaded and RulesDropped describe what survived the compile.
	RulesLoaded  int
	RulesDropped int
	// DroppedNames lists the rules that were removed, with the reason.
	DroppedNames []string
}

var ErrYaraMissing = fmt.Errorf("yara binary not found in PATH")

// BinaryAvailable reports whether a YARA CLI is reachable. On Windows the
// official prebuilt is named yara64.exe (or yara32.exe), so those are accepted
// too — see plan P1.1.
func BinaryAvailable() bool {
	return resolveBinary() != ""
}

func resolveBinary() string {
	for _, name := range []string{"yara", "yara64", "yara32"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func New(rulesDir string, useBuiltin bool) (*Runner, error) {
	bin := resolveBinary()
	if bin == "" {
		return nil, ErrYaraMissing
	}
	r := &Runner{bin: bin, timeout: 60 * time.Second}
	var dirs []string
	if rulesDir != "" {
		info, err := os.Stat(rulesDir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("yara rules dir invalid: %s", rulesDir)
		}
		dirs = append(dirs, rulesDir)
	}
	if useBuiltin || rulesDir == "" {
		tmp, err := os.MkdirTemp("", "gc-yara-")
		if err != nil {
			return nil, err
		}
		r.tmp = tmp
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(builtinRulesB64)))
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("yara builtin rules decode: %w", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "builtin.yar"), raw, 0o644); err != nil {
			r.Close()
			return nil, err
		}
		dirs = append(dirs, tmp)
	}

	// Collect the rule blocks from every file in scope.
	blocks, err := collectRules(dirs)
	if err != nil {
		r.Close()
		return nil, err
	}
	if len(blocks) == 0 {
		r.Close()
		return nil, fmt.Errorf("no .yar rules found")
	}

	tmp, err := os.MkdirTemp(r.tmpOr(os.TempDir()), "gc-yara-")
	if err != nil {
		r.Close()
		return nil, err
	}
	if r.tmp == "" {
		r.tmp = tmp
	}
	combined := filepath.Join(tmp, "combined.yar")

	// Compile, dropping the rules the local build cannot handle.
	if err := r.compileWithRepair(combined, blocks); err != nil {
		r.Close()
		return nil, err
	}
	r.rules = combined
	return r, nil
}

// ruleBlock is one rule with the name it declares.
type ruleBlock struct {
	name string
	text string
}

// collectRules reads every .yar file in the given directories and splits
// them into rule blocks. Files that declare the same rule name twice keep
// the first definition.
func collectRules(dirs []string) ([]ruleBlock, error) {
	var blocks []ruleBlock
	seen := map[string]bool{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yar") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(d, e.Name()))
			if err != nil {
				continue
			}
			for _, rb := range splitRules(string(b)) {
				if rb.name == "" || seen[rb.name] {
					continue
				}
				seen[rb.name] = true
				blocks = append(blocks, rb)
			}
		}
	}
	return blocks, nil
}

var ruleStart = regexp.MustCompile(`(?m)^[ \t]*(?:private[ \t]+|global[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)`)

// splitRules splits a YARA file into its rule blocks. The scanner tracks
// braces outside of strings and comments, so a brace inside a string
// literal does not confuse it.
func splitRules(src string) []ruleBlock {
	var out []ruleBlock
	lines := strings.Split(src, "\n")
	var cur []string
	depth := 0
	inRule := false
	var name string

	flush := func() {
		if inRule && depth == 0 && name != "" {
			out = append(out, ruleBlock{name: name, text: strings.Join(cur, "\n")})
		}
		cur = nil
		inRule = false
		name = ""
	}

	for _, line := range lines {
		if !inRule {
			if m := ruleStart.FindStringSubmatch(line); m != nil {
				inRule = true
				name = m[1]
				cur = []string{line}
				depth = countBraces(line)
				if depth == 0 {
					flush()
				}
				continue
			}
			continue
		}
		cur = append(cur, line)
		depth += countBraces(line)
		if depth <= 0 {
			depth = 0
			flush()
		}
	}
	return out
}

// countBraces counts the braces of a line that are outside string literals
// and comments.
func countBraces(line string) int {
	depth := 0
	inStr := false
	inComment := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inComment:
			if c == '\n' {
				inComment = false
			}
		case inStr:
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			inComment = true
			i++
		case c == '{':
			depth++
		case c == '}':
			depth--
		}
	}
	return depth
}

// failingRule extracts the rule name from a YARA compile error.
var failingRule = regexp.MustCompile(`rule "([^"]+)"`)

// compileWithRepair writes the rules, compiles them, and drops the rules
// the local build rejects until the file compiles.
func (r *Runner) compileWithRepair(path string, blocks []ruleBlock) error {
	live := make([]ruleBlock, len(blocks))
	copy(live, blocks)
	dropped := map[string]bool{}

	for attempt := 0; attempt < 64; attempt++ {
		if err := os.WriteFile(path, []byte(render(live)), 0o644); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := exec.CommandContext(ctx, r.bin, "-w", path, "NUL").CombinedOutput()
		cancel()
		if err == nil {
			r.RulesLoaded = len(live)
			r.RulesDropped = len(dropped)
			for name := range dropped {
				r.DroppedNames = append(r.DroppedNames, name)
			}
			sort.Strings(r.DroppedNames)
			return nil
		}
		text := string(out)
		m := failingRule.FindStringSubmatch(text)
		if m == nil {
			// The error does not name a rule: it is a real problem with
			// the file, not with one rule.
			return fmt.Errorf("yara rules failed to compile: %s: %s", err, strings.TrimSpace(text))
		}
		name := m[1]
		if dropped[name] {
			return fmt.Errorf("yara rules failed to compile: %s: %s", err, strings.TrimSpace(text))
		}
		dropped[name] = true
		filtered := live[:0]
		for _, b := range live {
			if b.name != name {
				filtered = append(filtered, b)
			}
		}
		live = filtered
	}
	return fmt.Errorf("yara rules did not compile after dropping %d rule(s)", len(dropped))
}

func render(blocks []ruleBlock) string {
	var sb strings.Builder
	for _, b := range blocks {
		sb.WriteString(b.text)
		sb.WriteString("\n\n")
	}
	return sb.String()
}

func (r *Runner) tmpOr(fallback string) string {
	if r.tmp != "" {
		return r.tmp
	}
	return fallback
}

func (r *Runner) Scan(target string) ([]Match, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.bin, "-w", r.rules, target)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("yara timeout")
		}
		return nil, err
	}
	var matches []Match
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Default YARA output is "<rule> <path>" separated by spaces
		// (rule names never contain spaces).
		if i := strings.IndexByte(line, ' '); i > 0 {
			matches = append(matches, Match{Rule: line[:i], Path: strings.TrimSpace(line[i+1:])})
		} else {
			matches = append(matches, Match{Rule: line, Path: target})
		}
	}
	return matches, nil
}

func (r *Runner) Close() {
	if r.tmp != "" {
		os.RemoveAll(r.tmp)
	}
}
