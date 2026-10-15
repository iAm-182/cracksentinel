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
	rulesDir string
	tmp      string
	timeout  time.Duration
}

var ErrYaraMissing = fmt.Errorf("yara binary not found in PATH")

func BinaryAvailable() bool {
	_, err := exec.LookPath("yara")
	return err == nil
}

func New(rulesDir string, useBuiltin bool) (*Runner, error) {
	if !BinaryAvailable() {
		return nil, ErrYaraMissing
	}
	r := &Runner{timeout: 60 * time.Second}
	if rulesDir != "" {
		info, err := os.Stat(rulesDir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("yara rules dir invalid: %s", rulesDir)
		}
		r.rulesDir = rulesDir
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
		if r.rulesDir == "" {
			r.rulesDir = tmp
		}
	}
	return r, nil
}

func (r *Runner) Scan(target string) ([]Match, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "yara", "-r", "-w", "-C", r.rulesDir, target)
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
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) >= 2 {
			matches = append(matches, Match{Rule: strings.TrimSpace(fields[0]), Path: strings.TrimSpace(fields[1])})
		} else if len(fields) == 1 && fields[0] != "" {
			matches = append(matches, Match{Rule: fields[0], Path: target})
		}
	}
	return matches, nil
}

func (r *Runner) Close() {
	if r.tmp != "" {
		os.RemoveAll(r.tmp)
	}
}
