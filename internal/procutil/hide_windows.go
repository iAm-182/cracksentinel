//go:build windows

package procutil

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

// HideWindow prevents a spawned CLI tool (7z, yara, powershell, upx) from
// flashing a black console window when running from a GUI desktop app.
func HideWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
