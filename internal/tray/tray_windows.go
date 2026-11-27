//go:build windows

package tray

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// Callbacks wires the Windows System Tray icon to CrackSentinel's desktop controller.
type Callbacks struct {
	Tooltip         string
	OnOpenDashboard func(view string)
	GetShieldState  func() (procShieldOn, ransomGuardOn, downloadGuardOn bool)
	OnToggleProcess func()
	OnToggleRansom  func()
	OnQuit          func()
}

type Instance struct {
	mu      sync.Mutex
	hwnd    syscall.Handle
	nid     notifyIconDataW
	running bool
}

const (
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmApp           = 0x8000
	wmTrayCallback  = wmApp + 1
	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmContextMenu   = 0x007B

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	mfString    = 0x00000000
	mfChecked   = 0x00000008
	mfSeparator = 0x00000800

	tpmRightButton = 0x0002
	tpmNonotify    = 0x0080
	tpmReturnCmd   = 0x0100

	imageIcon      = 1
	lrLoadFromFile = 0x00000010
	idiShield      = 32518

	cmdOpenDash   = 1001
	cmdToggleProc = 1002
	cmdToggleRans = 1003
	cmdOpenAudit  = 1004
	cmdQuitApp    = 1005
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type notifyIconDataW struct {
	CbSize           uint32
	HWnd             syscall.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            syscall.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         guid
	HBalloonIcon     syscall.Handle
}

type wndClassExW struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   syscall.Handle
	Icon       syscall.Handle
	Cursor     syscall.Handle
	Background syscall.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     syscall.Handle
}

type point struct {
	X int32
	Y int32
}

type winMsg struct {
	HWnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

var (
	modUser32               = syscall.NewLazyDLL("user32.dll")
	modShell32              = syscall.NewLazyDLL("shell32.dll")
	modKernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleW    = modKernel32.NewProc("GetModuleHandleW")
	procRegisterClassExW    = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW     = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW      = modUser32.NewProc("DefWindowProcW")
	procGetMessageW         = modUser32.NewProc("GetMessageW")
	procTranslateMessage    = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW    = modUser32.NewProc("DispatchMessageW")
	procPostMessageW        = modUser32.NewProc("PostMessageW")
	procPostQuitMessage     = modUser32.NewProc("PostQuitMessage")
	procLoadIconW           = modUser32.NewProc("LoadIconW")
	procLoadImageW          = modUser32.NewProc("LoadImageW")
	procCreatePopupMenu     = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW         = modUser32.NewProc("AppendMenuW")
	procTrackPopupMenu      = modUser32.NewProc("TrackPopupMenu")
	procDestroyMenu         = modUser32.NewProc("DestroyMenu")
	procGetCursorPos        = modUser32.NewProc("GetCursorPos")
	procSetForegroundWindow = modUser32.NewProc("SetForegroundWindow")
	procShellNotifyIconW    = modShell32.NewProc("Shell_NotifyIconW")
	procExtractIconExW      = modShell32.NewProc("ExtractIconExW")

	activeCallbacks Callbacks
	activeInst      *Instance
)

// Start launches the native Windows System Tray icon on a dedicated OS thread.
func Start(cb Callbacks) *Instance {
	inst := &Instance{}
	activeCallbacks = cb
	activeInst = inst
	ready := make(chan struct{})

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		hInst, _, _ := procGetModuleHandleW.Call(0)
		clsName, _ := syscall.UTF16PtrFromString("CrackSentinelTrayWndClass")

		wc := wndClassExW{
			WndProc:   syscall.NewCallback(trayWndProc),
			Instance:  syscall.Handle(hInst),
			ClassName: clsName,
		}
		wc.Size = uint32(unsafe.Sizeof(wc))
		procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

		wndTitle, _ := syscall.UTF16PtrFromString("CrackSentinelTray")
		hwnd, _, _ := procCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(clsName)),
			uintptr(unsafe.Pointer(wndTitle)),
			0,
			0, 0, 0, 0,
			0, 0, hInst, 0,
		)
		if hwnd == 0 {
			close(ready)
			return
		}

		hIcon := loadTrayIcon()
		tip := cb.Tooltip
		if tip == "" {
			tip = "CrackSentinel — Game Malware Guard"
		}

		var nid notifyIconDataW
		nid.CbSize = uint32(unsafe.Sizeof(nid))
		nid.HWnd = syscall.Handle(hwnd)
		nid.UID = 1
		nid.UFlags = nifMessage | nifIcon | nifTip
		nid.UCallbackMessage = wmTrayCallback
		nid.HIcon = hIcon
		copyUTF16(nid.SzTip[:], tip)

		procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))

		inst.mu.Lock()
		inst.hwnd = syscall.Handle(hwnd)
		inst.nid = nid
		inst.running = true
		inst.mu.Unlock()
		close(ready)

		var msg winMsg
		for {
			ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if int32(ret) <= 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
		}

		inst.mu.Lock()
		if inst.running {
			procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&inst.nid)))
			inst.running = false
		}
		inst.mu.Unlock()
	}()

	select {
	case <-ready:
	}
	return inst
}

// Stop removes the system tray icon from the Windows notification area cleanly.
func (inst *Instance) Stop() {
	if inst == nil {
		return
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if !inst.running {
		return
	}
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&inst.nid)))
	inst.running = false
	if inst.hwnd != 0 {
		procPostMessageW.Call(uintptr(inst.hwnd), wmClose, 0, 0)
	}
}

func trayWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTrayCallback:
		ev := uint32(lParam) & 0xFFFF
		switch ev {
		case wmLButtonDblClk, wmLButtonUp:
			if activeCallbacks.OnOpenDashboard != nil {
				go activeCallbacks.OnOpenDashboard("")
			}
		case wmRButtonUp, wmContextMenu:
			showContextMenu(syscall.Handle(hwnd))
		}
		return 0
	case wmClose, wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func showContextMenu(hwnd syscall.Handle) {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	var procOn, ransomOn bool
	if activeCallbacks.GetShieldState != nil {
		procOn, ransomOn, _ = activeCallbacks.GetShieldState()
	}

	appendMenuItem(hMenu, mfString, cmdOpenDash, "Buka Dashboard CrackSentinel")
	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	fProc := uintptr(mfString)
	if procOn {
		fProc |= mfChecked
	}
	appendMenuItem(hMenu, fProc, cmdToggleProc, "Active Process Shield (NtSuspendProcess)")

	fRans := uintptr(mfString)
	if ransomOn {
		fRans |= mfChecked
	}
	appendMenuItem(hMenu, fRans, cmdToggleRans, "Anti-Ransomware Canary Guard")

	appendMenuItem(hMenu, mfString, cmdOpenAudit, "Audit Keamanan PC & Discord/Steam")
	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	appendMenuItem(hMenu, mfString, cmdQuitApp, "Keluar (Tutup CrackSentinel)")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(uintptr(hwnd))

	cmd, _, _ := procTrackPopupMenu.Call(
		hMenu,
		tpmRightButton|tpmReturnCmd|tpmNonotify,
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		uintptr(hwnd),
		0,
	)

	switch uint32(cmd) {
	case cmdOpenDash:
		if activeCallbacks.OnOpenDashboard != nil {
			go activeCallbacks.OnOpenDashboard("")
		}
	case cmdToggleProc:
		if activeCallbacks.OnToggleProcess != nil {
			go activeCallbacks.OnToggleProcess()
		}
	case cmdToggleRans:
		if activeCallbacks.OnToggleRansom != nil {
			go activeCallbacks.OnToggleRansom()
		}
	case cmdOpenAudit:
		if activeCallbacks.OnOpenDashboard != nil {
			go activeCallbacks.OnOpenDashboard("audit")
		}
	case cmdQuitApp:
		if activeInst != nil {
			activeInst.Stop()
		}
		if activeCallbacks.OnQuit != nil {
			go activeCallbacks.OnQuit()
		}
	}
}

func appendMenuItem(hMenu, flags, id uintptr, label string) {
	p, err := syscall.UTF16PtrFromString(label)
	if err != nil {
		return
	}
	procAppendMenuW.Call(hMenu, flags, id, uintptr(unsafe.Pointer(p)))
}

func loadTrayIcon() syscall.Handle {
	if exe, err := os.Executable(); err == nil {
		// 1. Extract the embedded resource icon directly from CrackSentinel.exe
		if p, err := syscall.UTF16PtrFromString(exe); err == nil {
			var hLarge, hSmall syscall.Handle
			procExtractIconExW.Call(
				uintptr(unsafe.Pointer(p)),
				0,
				uintptr(unsafe.Pointer(&hLarge)),
				uintptr(unsafe.Pointer(&hSmall)),
				1,
			)
			if hSmall != 0 {
				return hSmall
			}
			if hLarge != 0 {
				return hLarge
			}
		}
		// 2. Fallback to assets/cracksentinel.ico next to executable
		icoPath := filepath.Join(filepath.Dir(exe), "assets", "cracksentinel.ico")
		if p, err := syscall.UTF16PtrFromString(icoPath); err == nil {
			h, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), imageIcon, 16, 16, lrLoadFromFile)
			if h != 0 {
				return syscall.Handle(h)
			}
		}
	}
	h, _, _ := procLoadIconW.Call(0, idiShield)
	return syscall.Handle(h)
}

func copyUTF16(dst []uint16, s string) {
	u, err := syscall.UTF16FromString(s)
	if err != nil {
		return
	}
	n := len(u)
	if n >= len(dst) {
		n = len(dst) - 1
	}
	copy(dst[:n], u[:n])
	dst[n] = 0
}
