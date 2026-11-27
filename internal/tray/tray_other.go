//go:build !windows

package tray

type Callbacks struct {
	Tooltip         string
	OnOpenDashboard func(view string)
	GetShieldState  func() (procShieldOn, ransomGuardOn, downloadGuardOn bool)
	OnToggleProcess func()
	OnToggleRansom  func()
	OnQuit          func()
}

type Instance struct{}

func Start(_ Callbacks) *Instance { return &Instance{} }
func (inst *Instance) Stop()      {}
