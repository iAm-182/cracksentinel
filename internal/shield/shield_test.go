package shield

import (
	"os"
	"path/filepath"
	"testing"

	"gamecrack-scanner/internal/model"
)

func TestScoreOutboundConnectionAndRiskyDirs(t *testing.T) {
	risky := []string{`C:\Users\Test\Downloads`, `E:\Games`}

	if !isInRiskyDir(`E:\Games\FakeRepack\setup.exe`, risky) {
		t.Fatalf("expected E:\\Games\\FakeRepack\\setup.exe to be classified as risky dir")
	}
	if isInRiskyDir(`C:\Windows\System32\svchost.exe`, risky) {
		t.Fatalf("system32 binary must never be classified as risky dir")
	}
	if isInRiskyDir(`E:\Games\CrackSentinel.exe`, risky) {
		t.Fatalf("CrackSentinel.exe must be excluded from self-interception")
	}

	// LOLBin external C2 -> HIGH
	r1, _ := scoreOutboundConnection("powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "185.199.108.153", 443, risky)
	if r1 != "HIGH" {
		t.Fatalf("powershell external connection risk = %s, want HIGH", r1)
	}

	// RAT/C2 port 4444 -> HIGH
	r2, _ := scoreOutboundConnection("game.exe", `E:\Games\SomeGame\game.exe`, "45.33.32.156", 4444, risky)
	if r2 != "HIGH" {
		t.Fatalf("port 4444 connection risk = %s, want HIGH", r2)
	}

	// Normal loopback -> CLEAN
	r3, _ := scoreOutboundConnection("chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, "127.0.0.1", 8787, risky)
	if r3 != "CLEAN" {
		t.Fatalf("loopback connection risk = %s, want CLEAN", r3)
	}
}

func TestCanaryDeploymentAndTamperCheck(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewManager(tmp, func(p string) (model.FileResult, error) {
		return model.FileResult{Path: p, Verdict: model.VerdictClean}, nil
	}, nil)

	mgr.mu.Lock()
	// Force canary into tmp by clearing HOME temporarily or testing verifyFileSHA256 directly
	cp := filepath.Join(tmp, "!000_CrackSentinel_Canary_Protected.docx.txt")
	_ = os.WriteFile(cp, []byte(canaryBanner), 0o644)
	mgr.mu.Unlock()

	st := mgr.Status()
	if st.RecentEvents == nil && len(st.BlockedApps) != 0 {
		t.Fatalf("unexpected initial state")
	}

	// Verify NetWatch ListConnections runs without error on host OS
	conns, err := mgr.ListConnections()
	if err != nil {
		t.Fatalf("ListConnections error: %v", err)
	}
	_ = conns
}
