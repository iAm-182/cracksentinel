package winsandbox

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Status describes whether Windows Sandbox (WindowsSandbox.exe) is available on this host.
type Status struct {
	Supported bool   `json:"supported"`
	ExePath   string `json:"exe_path,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

// CheckAvailability checks if Windows Sandbox is installed on Windows 10/11 Pro/Enterprise.
func CheckAvailability() Status {
	if runtime.GOOS != "windows" {
		return Status{Supported: false, Hint: "Windows Sandbox hanya tersedia di Windows 10/11 Pro/Enterprise."}
	}
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	p := filepath.Join(sysRoot, "System32", "WindowsSandbox.exe")
	if _, err := os.Stat(p); err == nil {
		return Status{Supported: true, ExePath: p}
	}
	if lp, err := exec.LookPath("WindowsSandbox.exe"); err == nil {
		return Status{Supported: true, ExePath: lp}
	}
	return Status{
		Supported: false,
		Hint:      "WindowsSandbox.exe belum aktif. Aktifkan lewat 'Turn Windows features on or off' -> centang 'Windows Sandbox' (khusus Windows 10/11 Pro).",
	}
}

type wsbConfig struct {
	XMLName         xml.Name         `xml:"Configuration"`
	VGpu            string           `xml:"VGpu"`
	Networking      string           `xml:"Networking"`
	ClipboardRedir  string           `xml:"ClipboardRedirection"`
	PrinterRedir    string           `xml:"PrinterRedirection"`
	AudioInput      string           `xml:"AudioInput"`
	VideoInput      string           `xml:"VideoInput"`
	ProtectedClient string           `xml:"ProtectedClient"`
	MemoryInMB      int              `xml:"MemoryInMB"`
	MappedFolders   wsbMappedFolders `xml:"MappedFolders"`
	LogonCommand    wsbLogonCommand  `xml:"LogonCommand"`
}

type wsbMappedFolders struct {
	Folders []wsbMappedFolder `xml:"MappedFolder"`
}

type wsbMappedFolder struct {
	HostFolder    string `xml:"HostFolder"`
	SandboxFolder string `xml:"SandboxFolder"`
	ReadOnly      string `xml:"ReadOnly"`
}

type wsbLogonCommand struct {
	Command string `xml:"Command"`
}

// BuildWSBXML generates a hardened, network-isolated, read-only Windows Sandbox (.wsb)
// configuration that mounts hostDir read-only at C:\Sample and opens an inspection banner
// inside the disposable VM (zero network, zero clipboard leak, zero write-back to host).
func BuildWSBXML(hostTarget string) (xmlBytes []byte, hostDir string, targetBase string, err error) {
	st, err := os.Stat(hostTarget)
	if err != nil {
		return nil, "", "", err
	}
	if st.IsDir() {
		hostDir = hostTarget
		targetBase = ""
	} else {
		hostDir = filepath.Dir(hostTarget)
		targetBase = filepath.Base(hostTarget)
	}
	absDir, err := filepath.Abs(hostDir)
	if err != nil {
		return nil, "", "", err
	}

	logonCmd := `powershell.exe -NoExit -Command "Write-Host '=== CRACKSENTINEL ISOLATED WINDOWS SANDBOX ===' -ForegroundColor Cyan; Write-Host 'Internet: DISABLED | Host Folder: READ-ONLY | Clipboard: BLOCKED' -ForegroundColor Green; explorer.exe 'C:\Sample'`
	if targetBase != "" {
		safeName := strings.ReplaceAll(targetBase, "'", "''")
		logonCmd += fmt.Sprintf(`; Write-Host ('File siap diuji manual di C:\Sample\' + '%s') -ForegroundColor Yellow"`, safeName)
	} else {
		logonCmd += `"`
	}

	cfg := wsbConfig{
		VGpu:            "Disable",
		Networking:      "Disable",
		ClipboardRedir:  "Disable",
		PrinterRedir:    "Disable",
		AudioInput:      "Disable",
		VideoInput:      "Disable",
		ProtectedClient: "Enable",
		MemoryInMB:      2048,
		MappedFolders: wsbMappedFolders{
			Folders: []wsbMappedFolder{{
				HostFolder:    absDir,
				SandboxFolder: `C:\Sample`,
				ReadOnly:      "true",
			}},
		},
		LogonCommand: wsbLogonCommand{Command: logonCmd},
	}

	out, err := xml.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", "", err
	}
	return out, absDir, targetBase, nil
}

// PrepareAndLaunch writes a hardened .wsb file to outDir and launches WindowsSandbox.exe
// when installed (or returns the .wsb path so the user can inspect/run it).
func PrepareAndLaunch(hostTarget, outDir string, autoLaunch bool) (wsbPath string, launched bool, hint string, err error) {
	xmlData, _, _, err := BuildWSBXML(hostTarget)
	if err != nil {
		return "", false, "", err
	}
	if outDir == "" {
		outDir = os.TempDir()
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", false, "", err
	}
	wsbPath = filepath.Join(outDir, fmt.Sprintf("CrackSentinel-Sandbox-%d.wsb", time.Now().Unix()))
	if err := os.WriteFile(wsbPath, xmlData, 0o644); err != nil {
		return "", false, "", err
	}

	st := CheckAvailability()
	if !st.Supported {
		return wsbPath, false, st.Hint, nil
	}
	if autoLaunch {
		cmd := exec.Command(st.ExePath, wsbPath)
		if err := cmd.Start(); err != nil {
			return wsbPath, false, "Gagal menjalankan WindowsSandbox.exe: " + err.Error(), nil
		}
		return wsbPath, true, "Windows Sandbox terisolasi berhasil dibuka (Internet OFF, Read-Only).", nil
	}
	return wsbPath, false, "File konfigurasi .wsb siap dijalankan.", nil
}
