package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Report struct {
	ExitCode     string   `json:"exit_code"`
	Connects     []string `json:"connects,omitempty"`
	FilesDropped []string `json:"files_dropped,omitempty"`
	ChildProcs   []string `json:"child_procs,omitempty"`
	StdoutNote   string   `json:"stdout_note,omitempty"`
	ElapsedMs    int64    `json:"elapsed_ms"`
	Error        string   `json:"error,omitempty"`
}

func ImageExists(image string) bool {
	cmd := exec.Command("docker", "image", "inspect", image)
	return cmd.Run() == nil
}

func BuildImage(tag, contextDir string) error {
	if _, err := os.Stat(filepath.Join(contextDir, "Dockerfile")); err != nil {
		// Fall back to the detonator dir shipped next to the scanner binary,
		// so `-detonate` works regardless of the caller's working directory.
		if exe, e := os.Executable(); e == nil {
			alt := filepath.Join(filepath.Dir(exe), filepath.Base(contextDir))
			if _, e2 := os.Stat(filepath.Join(alt, "Dockerfile")); e2 == nil {
				contextDir = alt
			}
		}
		if _, err := os.Stat(filepath.Join(contextDir, "Dockerfile")); err != nil {
			return fmt.Errorf("detonator dir missing Dockerfile: %s", contextDir)
		}
	}
	cmd := exec.Command("docker", "build", "-t", tag, contextDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func Detonate(targetPath, image string, timeoutSec int) (*Report, error) {
	abs, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, err
	}
	if !ImageExists(image) {
		return nil, fmt.Errorf("image %s not built", image)
	}
	outDir, err := os.MkdirTemp("", "gc-detonate-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outDir)
	// Stage the target as /det/target.exe: run.sh expects exactly that path,
	// and mounting the parent dir does not guarantee the file name matches.
	stageDir, err := os.MkdirTemp("", "gc-detonate-in-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stageDir)
	if err := copyFile(abs, filepath.Join(stageDir, "target.exe")); err != nil {
		return nil, fmt.Errorf("stage target: %w", err)
	}

	if timeoutSec <= 0 || timeoutSec > 300 {
		timeoutSec = 150
	}
	args := []string{
		"run", "--rm",
		"--network", "none",
		"--security-opt", "seccomp=unconfined",
		"--cap-add", "SYS_PTRACE",
		"--memory", "1g",
		"--pids-limit", "512",
		"-v", filepath.ToSlash(outDir) + ":/out",
		"-v", filepath.ToSlash(stageDir) + ":/det:ro",
		image,
	}
	cmd := exec.Command("docker", args...)
	done := make(chan error, 1)
	t0 := time.Now()
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			return &Report{Error: "docker run: " + err.Error(), ElapsedMs: time.Since(t0).Milliseconds()}, nil
		}
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		exec.Command("docker", "kill").Run()
		return &Report{Error: "detonation timeout", ElapsedMs: time.Since(t0).Milliseconds()}, nil
	}
	rep := &Report{ElapsedMs: time.Since(t0).Milliseconds()}
	if b, err := os.ReadFile(filepath.Join(outDir, "exit.log")); err == nil {
		rep.ExitCode = strings.TrimSpace(strings.TrimPrefix(string(b), "exit="))
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "stdout.log")); err == nil {
		if len(strings.TrimSpace(string(b))) > 0 {
			rep.StdoutNote = truncateStr(strings.TrimSpace(string(b)), 200)
		}
	}
	sysFiles, _ := filepath.Glob(filepath.Join(outDir, "sys.*"))
	for _, sf := range sysFiles {
		b, err := os.ReadFile(sf)
		if err != nil {
			continue
		}
		parseSyscalls(string(b), rep)
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "files.log")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			rep.FilesDropped = appendUnique(rep.FilesDropped, wineToWindows(line), 50)
		}
	}
	return rep, nil
}

var (
	reConnect = regexp.MustCompile(`connect\([^)]*?sin_addr=inet_addr\("([0-9.]+)"\), sin_port=htons\(([0-9]+)\)`)
	reExecve  = regexp.MustCompile(`execve\("([^"]+)"`)
	reOpenat  = regexp.MustCompile(`openat\([^,]*, "([^"]+)", O_(WRONLY|RDWR)[^)]*\)`)
)

func parseSyscalls(content string, rep *Report) {
	for _, line := range strings.Split(content, "\n") {
		if m := reConnect.FindStringSubmatch(line); m != nil {
			rep.Connects = appendUnique(rep.Connects, m[1]+":"+m[2], 20)
			continue
		}
		if m := reExecve.FindStringSubmatch(line); m != nil {
			p := m[1]
			if !isNoise(p) {
				rep.ChildProcs = appendUnique(rep.ChildProcs, p, 20)
			}
			continue
		}
		if m := reOpenat.FindStringSubmatch(line); m != nil {
			p := m[1]
			if isNoise(p) {
				continue
			}
			if strings.Contains(p, "/wine/drive_c/") {
				rep.FilesDropped = appendUnique(rep.FilesDropped, wineToWindows(p), 50)
			}
		}
	}
}

func isNoise(p string) bool {
	for _, n := range []string{"/proc", "/dev", "/sys", "/etc", "/var", "/usr", "/lib", "/bin", "/sbin", "/root/.cache", "/tmp/."} {
		if strings.HasPrefix(p, n) {
			return true
		}
	}
	return false
}

func wineToWindows(p string) string {
	p = strings.ReplaceAll(p, "/wine/drive_c/", `C:\`)
	p = strings.ReplaceAll(p, "/", `\`)
	return p
}

func appendUnique(list []string, v string, cap int) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	if len(list) >= cap {
		return list
	}
	return append(list, v)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

var _ = strconv.Itoa
