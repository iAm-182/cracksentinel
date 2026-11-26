//go:build windows

package sysaudit

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// Pure-Go PE-sieve / HollowsHunter style live memory scanner ("内存跑马" detector).
// Scans accessible running processes via Read-Only Win32 APIs (VirtualQueryEx +
// ReadProcessMemory) to detect unbacked `MEM_PRIVATE` executable (`PAGE_EXECUTE_READWRITE` /
// `PAGE_EXECUTE_READ`) memory regions carrying an injected `MZ` + `PE\x00\x00` image
// (Reflective DLL Injection / Process Hollowing / Donut / CobaltStrike / AsyncRAT RunPE).
//
// Zero false-positive design:
// - JIT engines (browsers, .NET CLR, Java, Node, Discord/Electron) allocate RWX pages
//   for native JIT machine code, NOT raw unmapped PE headers (`MZ` -> `e_lfanew` -> `PE\0\0`).
// - Requiring a structurally valid DOS + NT `PE\0\0` + COFF Machine signature inside
//   `MEM_PRIVATE` (not `MEM_IMAGE` backed by a legitimate DLL on disk) specifically
//   pinpoints reflective PE loaders & hollowed processes!

const (
	th32csSnapProcess       = 0x00000002
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
	memCommit               = 0x1000
	memPrivate              = 0x20000
	pageExecuteRead         = 0x20
	pageExecuteReadWrite    = 0x40
	pageExecuteWriteCopy    = 0x80
)

type processEntry32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type memoryBasicInformation64 struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	Alignment1        uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	Alignment2        uint32
}

var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
	procVirtualQueryEx           = modKernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory        = modKernel32.NewProc("ReadProcessMemory")
	procGetCurrentProcessId      = modKernel32.NewProc("GetCurrentProcessId")
)

func scanInjectedProcesses() (findings []Finding, scannedCount int) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, 0
	}
	selfPID, _, _ := procGetCurrentProcessId.Call()

	snap, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return nil, 0
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	r1, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return nil, 0
	}

	for {
		pid := entry.ProcessID
		exeName := syscall.UTF16ToString(entry.ExeFile[:])
		lowName := strings.ToLower(filepath.Base(exeName))

		if pid > 4 && uintptr(pid) != selfPID && !skipMemoryScanProc(lowName) {
			if f, ok := inspectProcessMemory(pid, exeName); ok {
				findings = append(findings, f...)
			}
			scannedCount++
		}
		if scannedCount >= 180 || len(findings) >= 12 {
			break
		}

		entry.Size = uint32(unsafe.Sizeof(entry))
		rn, _, _ := procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if rn == 0 {
			break
		}
	}
	return findings, scannedCount
}

func skipMemoryScanProc(lowName string) bool {
	// Skip security/sandbox/AV processes and our own scanner CLI
	switch lowName {
	case "cracksentinel.exe", "scanner.exe", "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "memory compression":
		return true
	}
	return false
}

func inspectProcessMemory(pid uint32, exeName string) ([]Finding, bool) {
	h, err := syscall.OpenProcess(processQueryInformation|processVMRead, false, pid)
	if err != nil || h == 0 {
		return nil, false
	}
	defer syscall.CloseHandle(h)

	var out []Finding
	var addr uintptr
	var mbi memoryBasicInformation64
	mbiSize := unsafe.Sizeof(mbi)

	regionsChecked := 0
	for regionsChecked < 4096 {
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(h),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			mbiSize,
		)
		if ret == 0 || mbi.RegionSize == 0 {
			break
		}
		regionsChecked++

		isExec := (mbi.Protect == pageExecuteReadWrite) || (mbi.Protect == pageExecuteRead) || (mbi.Protect == pageExecuteWriteCopy)
		// MEM_PRIVATE + Executable + Committed = unbacked executable memory (not loaded via LoadLibrary MEM_IMAGE!)
		if mbi.State == memCommit && mbi.Type == memPrivate && isExec && mbi.RegionSize >= 4096 && mbi.RegionSize <= 64<<20 {
			var hdr [1024]byte
			var bytesRead uintptr
			okRead, _, _ := procReadProcessMemory.Call(
				uintptr(h),
				mbi.BaseAddress,
				uintptr(unsafe.Pointer(&hdr[0])),
				uintptr(len(hdr)),
				uintptr(unsafe.Pointer(&bytesRead)),
			)
			if okRead != 0 && bytesRead >= 256 && isGenuineInjectedPEHeader(hdr[:bytesRead]) {
				protStr := "RX"
				if mbi.Protect == pageExecuteReadWrite {
					protStr = "RWX"
				}
				out = append(out, Finding{
					Category: "memory",
					Risk:     "HIGH",
					Title:    fmt.Sprintf("Injeksi Memori / Process Hollowing Terdeteksi di %s (PID %d)!", exeName, pid),
					Location: fmt.Sprintf("PID %d (%s) @ 0x%X (%s, MEM_PRIVATE %d KB)", pid, exeName, mbi.BaseAddress, protStr, mbi.RegionSize/1024),
					Command:  fmt.Sprintf("Unbacked PE image (MZ->PE) inside private %s memory", protStr),
					Reason:   "Ditemukan program .exe/.dll utuh berjalan langsung di memori privat tanpa file di harddisk (Reflective DLL Injection / RunPE / Process Hollowing)!",
				})
				if len(out) >= 2 {
					break
				}
			}
		}

		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	return out, true
}

func isGenuineInjectedPEHeader(b []byte) bool {
	if len(b) < 256 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	lfanew := int(uint32(b[0x3C]) | uint32(b[0x3D])<<8 | uint32(b[0x3E])<<16 | uint32(b[0x3F])<<24)
	if lfanew < 0x40 || lfanew+24 > len(b) {
		return false
	}
	if b[lfanew] != 'P' || b[lfanew+1] != 'E' || b[lfanew+2] != 0 || b[lfanew+3] != 0 {
		return false
	}
	machine := uint16(b[lfanew+4]) | uint16(b[lfanew+5])<<8
	numSec := uint16(b[lfanew+6]) | uint16(b[lfanew+7])<<8
	return (machine == 0x8664 || machine == 0x014C || machine == 0xAA64) && numSec >= 1 && numSec <= 32
}
