//go:build !windows

package sysaudit

func scanInjectedProcesses() ([]Finding, int) {
	return nil, 0
}
