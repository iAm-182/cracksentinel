//go:build !windows

package shield

import (
	"context"
	"fmt"
)

func platformSupported() bool { return false }
func isProcessElevated() bool { return false }
func hideCanaryFile(_ string) {}

func SuspendProcess(_ uint32) error { return fmt.Errorf("unsupported on non-windows") }
func ResumeProcess(_ uint32) error  { return fmt.Errorf("unsupported on non-windows") }
func KillProcess(_ uint32) error    { return fmt.Errorf("unsupported on non-windows") }

func (m *Manager) runProcessShieldLoop(ctx context.Context) { <-ctx.Done() }
func (m *Manager) runRansomGuardLoop(ctx context.Context)   { <-ctx.Done() }

func (m *Manager) ListConnections() ([]NetConnection, error) { return nil, nil }
func (m *Manager) BlockAppWFP(_ string, _ uint32, _ bool) error {
	return fmt.Errorf("Windows WFP Firewall hanya tersedia di Windows")
}
func (m *Manager) UnblockAppWFP(_ string) error {
	return fmt.Errorf("Windows WFP Firewall hanya tersedia di Windows")
}
func (m *Manager) SetDefenderCFA(_ bool) error {
	return fmt.Errorf("Windows Defender Minifilter hanya tersedia di Windows")
}
func queryKernelDriversStatus() (bool, bool, bool) { return false, false, false }
