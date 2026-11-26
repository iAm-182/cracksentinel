package wininteg

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gamecrack-scanner/internal/procutil"
)

// ContextMenuStatus reports whether "Scan with CrackSentinel" is registered in HKCU\Software\Classes.
type ContextMenuStatus struct {
	Supported        bool   `json:"supported"`
	ContextMenu      bool   `json:"context_menu_enabled"`
	AutostartGuard   bool   `json:"autostart_guard_enabled"`
	RegisteredTarget string `json:"registered_target,omitempty"`
}

// Status queries HKCU registry keys (no Admin/UAC required!) for Explorer right-click & background guard autostart.
func Status() ContextMenuStatus {
	if runtime.GOOS != "windows" {
		return ContextMenuStatus{Supported: false}
	}
	ps := `
$ErrorActionPreference = 'SilentlyContinue'
$cm = Test-Path 'HKCU:\Software\Classes\Directory\shell\CrackSentinel\command'
$tgt = ''
if ($cm) {
  $tgt = (Get-ItemProperty 'HKCU:\Software\Classes\Directory\shell\CrackSentinel\command').'(default)'
}
$runVal = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run').CrackSentinelGuard
Write-Output ("CM=" + [int]$cm)
Write-Output ("AUTO=" + [int]([bool]$runVal))
Write-Output ("TGT=" + [string]$tgt)
`
	cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
	procutil.HideWindow(cmd)
	out, _ := cmd.Output()
	st := ContextMenuStatus{Supported: true}
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == "CM=1":
			st.ContextMenu = true
		case ln == "AUTO=1":
			st.AutostartGuard = true
		case strings.HasPrefix(ln, "TGT="):
			st.RegisteredTarget = strings.TrimPrefix(ln, "TGT=")
		}
	}
	return st
}

// SetContextMenu registers or removes "Scan with CrackSentinel" on files (*), folders (Directory),
// and folder backgrounds (Directory\Background) under HKCU\Software\Classes (zero UAC required).
func SetContextMenu(enable bool, exePath string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("fitur klik-kanan Explorer hanya tersedia di Windows")
	}
	if enable {
		absExe, err := filepath.Abs(exePath)
		if err != nil {
			return err
		}
		ps := `
$ErrorActionPreference = 'Stop'
$exe = $env:CS_EXE
$roots = @(
  @{ path = 'HKCU:\Software\Classes\*\shell\CrackSentinel'; arg = '"%1"' },
  @{ path = 'HKCU:\Software\Classes\Directory\shell\CrackSentinel'; arg = '"%1"' },
  @{ path = 'HKCU:\Software\Classes\Directory\Background\shell\CrackSentinel'; arg = '"%V"' }
)
foreach ($r in $roots) {
  New-Item -Path ($r.path + '\command') -Force | Out-Null
  Set-ItemProperty -Path $r.path -Name '(default)' -Value 'Scan with CrackSentinel'
  Set-ItemProperty -Path $r.path -Name 'Icon' -Value "$exe,0"
  $cmdStr = '"' + $exe + '" ' + $r.arg
  Set-ItemProperty -Path ($r.path + '\command') -Name '(default)' -Value $cmdStr
}
`
		cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
		procutil.HideWindow(cmd)
		cmd.Env = append(os.Environ(), "CS_EXE="+absExe)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	psDel := `
$ErrorActionPreference = 'SilentlyContinue'
Remove-Item -Path 'HKCU:\Software\Classes\*\shell\CrackSentinel' -Recurse -Force
Remove-Item -Path 'HKCU:\Software\Classes\Directory\shell\CrackSentinel' -Recurse -Force
Remove-Item -Path 'HKCU:\Software\Classes\Directory\Background\shell\CrackSentinel' -Recurse -Force
`
	cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psDel)
	procutil.HideWindow(cmd)
	_, _ = cmd.CombinedOutput()
	return nil
}

// SetBackgroundGuardAutostart registers or removes `CrackSentinel.exe --background` in HKCU\...\Run
// so Real-Time Download Guard protects the PC silently on Windows login without opening any window.
func SetBackgroundGuardAutostart(enable bool, exePath string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("fitur autostart hanya tersedia di Windows")
	}
	if enable {
		absExe, err := filepath.Abs(exePath)
		if err != nil {
			return err
		}
		ps := `
$ErrorActionPreference = 'Stop'
$val = '"' + $env:CS_EXE + '" --background'
New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Force | Out-Null
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'CrackSentinelGuard' -Value $val
`
		cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
		procutil.HideWindow(cmd)
		cmd.Env = append(os.Environ(), "CS_EXE="+absExe)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	psDel := `Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'CrackSentinelGuard' -ErrorAction SilentlyContinue`
	cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psDel)
	procutil.HideWindow(cmd)
	_, _ = cmd.CombinedOutput()
	return nil
}
