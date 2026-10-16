package yara

import (
	"embed"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed rules/*.yar
var builtinFS embed.FS

type Match struct {
	Rule string
	Path string
}

type Runner struct {
	bin      string
	rules    string // single combined .yar file passed to the CLI
	tmp      string
	timeout  time.Duration
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
		entries, err := builtinFS.ReadDir("rules")
		if err != nil {
			r.Close()
			return nil, err
		}
		for _, e := range entries {
			b, err := builtinFS.ReadFile("rules/" + e.Name())
			if err != nil {
				continue
			}
			os.WriteFile(filepath.Join(tmp, e.Name()), b, 0o644)
		}
		dirs = append(dirs, tmp)
	}
	// The YARA CLI takes a single RULES_FILE, not a directory (and has no -C
	// flag), so concatenate every .yar in scope into one combined file.
	// NOTE: files must not declare the same rule name twice.
	combined := filepath.Join(r.tmpOr(os.TempDir()), "combined.yar")
	var sb strings.Builder
	files := 0
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
			sb.WriteString("\n// ---- " + e.Name() + " ----\n")
			sb.Write(b)
			sb.WriteByte('\n')
			files++
		}
	}
	if files == 0 {
		r.Close()
		return nil, fmt.Errorf("no .yar rules found")
	}
	if r.tmp == "" {
		tmp, err := os.MkdirTemp("", "gc-yara-")
		if err != nil {
			return nil, err
		}
		r.tmp = tmp
		combined = filepath.Join(tmp, "combined.yar")
	}
	if err := os.WriteFile(combined, []byte(sb.String()), 0o644); err != nil {
		r.Close()
		return nil, err
	}
	r.rules = combined
	// Compile-check now so a broken rule surfaces as a loud init warning
	// instead of silently disabling the whole YARA layer on every file.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, bin, "-w", combined, "NUL").CombinedOutput(); err != nil {
		r.Close()
		return nil, fmt.Errorf("yara rules failed to compile: %s: %s", err, strings.TrimSpace(string(out)))
	}
	return r, nil
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
