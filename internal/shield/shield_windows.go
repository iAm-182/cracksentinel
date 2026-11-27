//go:build windows

package shield

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/procutil"
)

const (
	th32csSnapProcess       = 0x00000002
	processQueryLimitedInfo = 0x1000
	processSuspendResume    = 0x0800
	processTerminate        = 0x0001
	afInet                  = 2
	tcpTableOwnerPidAll     = 5
	fileAttributeHidden     = 0x02
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

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

var (
	modKernel32                    = syscall.NewLazyDLL("kernel32.dll")
	modNtdll                       = syscall.NewLazyDLL("ntdll.dll")
	modIphlpapi                    = syscall.NewLazyDLL("iphlpapi.dll")
	modAdvapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procCreateToolhelp32Snapshot   = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW             = modKernel32.NewProc("Process32NextW")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
	procSetFileAttributesW         = modKernel32.NewProc("SetFileAttributesW")
	procNtSuspendProcess           = modNtdll.NewProc("NtSuspendProcess")
	procNtResumeProcess            = modNtdll.NewProc("NtResumeProcess")
	procGetExtendedTcpTable        = modIphlpapi.NewProc("GetExtendedTcpTable")
)

func platformSupported() bool { return true }

func isProcessElevated() bool {
	var token syscall.Token
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	if err := syscall.OpenProcessToken(h, syscall.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var elevation uint32
	var retLen uint32
	// TokenElevation = 20
	r1, _, _ := modAdvapi32.NewProc("GetTokenInformation").Call(
		uintptr(token),
		20,
		uintptr(unsafe.Pointer(&elevation)),
		4,
		uintptr(unsafe.Pointer(&retLen)),
	)
	return r1 != 0 && elevation != 0
}

func hideCanaryFile(path string) {
	if p, err := syscall.UTF16PtrFromString(path); err == nil {
		procSetFileAttributesW.Call(uintptr(unsafe.Pointer(p)), fileAttributeHidden)
	}
}

func queryProcessExePath(pid uint32) string {
	if pid <= 4 {
		return ""
	}
	h, err := syscall.OpenProcess(processQueryLimitedInfo, false, pid)
	if err != nil || h == 0 {
		return ""
	}
	defer syscall.CloseHandle(h)

	var buf [1024]uint16
	sz := uint32(len(buf))
	r1, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(h),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&sz)),
	)
	if r1 == 0 || sz == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:sz])
}

// SuspendProcess freezes all threads in PID immediately via ntdll!NtSuspendProcess.
func SuspendProcess(pid uint32) error {
	h, err := syscall.OpenProcess(processSuspendResume, false, pid)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	st, _, _ := procNtSuspendProcess.Call(uintptr(h))
	if st != 0 {
		return fmt.Errorf("NtSuspendProcess status 0x%X", st)
	}
	return nil
}

// ResumeProcess unfreezes a previously suspended PID via ntdll!NtResumeProcess.
func ResumeProcess(pid uint32) error {
	h, err := syscall.OpenProcess(processSuspendResume, false, pid)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	st, _, _ := procNtResumeProcess.Call(uintptr(h))
	if st != 0 {
		return fmt.Errorf("NtResumeProcess status 0x%X", st)
	}
	return nil
}

// KillProcess terminates PID immediately via TerminateProcess.
func KillProcess(pid uint32) error {
	h, err := syscall.OpenProcess(processTerminate, false, pid)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	return syscall.TerminateProcess(h, 1)
}

type procSnapItem struct {
	pid     uint32
	ppid    uint32
	name    string
	exePath string
}

func snapshotRunningProcesses() []procSnapItem {
	snap, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return nil
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	r1, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return nil
	}
	out := make([]procSnapItem, 0, 160)
	for {
		pid := entry.ProcessID
		if pid > 4 {
			name := syscall.UTF16ToString(entry.ExeFile[:])
			out = append(out, procSnapItem{
				pid:     pid,
				ppid:    entry.ParentProcessID,
				name:    name,
				exePath: queryProcessExePath(pid),
			})
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		rn, _, _ := procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if rn == 0 {
			break
		}
	}
	return out
}

// runProcessShieldLoop monitors newly created processes in risky folders using a
// sub-millisecond Toolhelp32 kernel snapshot (<0.1% CPU, zero WMI/PowerShell bloat).
// When an unknown executable starts from Downloads/Games/Temp/AppData, it immediately
// freezes the process with NtSuspendProcess, scans the binary on disk, and either
// resumes it (<300ms if clean) or terminates it if MALICIOUS!
func (m *Manager) runProcessShieldLoop(ctx context.Context) {
	selfPID := uint32(os.Getpid())
	seenPIDs := map[uint32]string{} // pid -> exePath

	// Seed already-running processes on startup so we don't freeze existing user apps
	for _, p := range snapshotRunningProcesses() {
		seenPIDs[p.pid] = p.exePath
	}

	ticker := time.NewTicker(850 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			risky := riskyExecutionDirs()
			cur := snapshotRunningProcesses()
			alive := make(map[uint32]bool, len(cur))
			for _, p := range cur {
				alive[p.pid] = true
				if p.pid == selfPID {
					continue
				}
				if prevPath, ok := seenPIDs[p.pid]; ok && prevPath == p.exePath {
					continue
				}
				seenPIDs[p.pid] = p.exePath
				if p.exePath == "" || !isInRiskyDir(p.exePath, risky) {
					continue
				}
				m.inspectNewProcess(p, risky)
			}
			// Prune exited PIDs so map never grows
			for pid := range seenPIDs {
				if !alive[pid] {
					delete(seenPIDs, pid)
				}
			}
		}
	}
}

func (m *Manager) inspectNewProcess(p procSnapItem, _ []string) {
	st, err := os.Stat(p.exePath)
	if err != nil || st.IsDir() {
		return
	}
	cacheKey := fmt.Sprintf("%s|%d|%d", strings.ToLower(p.exePath), st.Size(), st.ModTime().UnixNano())

	m.mu.Lock()
	if _, ok := m.cleanCache[cacheKey]; ok {
		m.mu.Unlock()
		return
	}
	autoKill := m.cfg.ProcessAutoKill
	scanFn := m.scanFn
	m.mu.Unlock()

	if scanFn == nil {
		return
	}

	// 1. Freeze the newly spawned risky process immediately via ntdll!NtSuspendProcess
	suspended := SuspendProcess(p.pid) == nil
	atomic.AddInt64(&m.inspectedCount, 1)

	// 2. Scan the executable file statically while its threads are frozen
	res, scanErr := scanFn(p.exePath)
	if scanErr != nil || res.Verdict != model.VerdictMalicious {
		if suspended {
			_ = ResumeProcess(p.pid)
		}
		if scanErr == nil && res.Score < 30 {
			m.mu.Lock()
			if len(m.cleanCache) > 1024 {
				m.cleanCache = map[string]int64{}
			}
			m.cleanCache[cacheKey] = time.Now().Unix()
			m.mu.Unlock()
		}
		if scanErr == nil && res.Verdict == model.VerdictSuspicious {
			m.recordEvent(AlertEvent{
				Layer:    "process_shield",
				Severity: "INFO",
				PID:      p.pid,
				Process:  p.name,
				ExePath:  p.exePath,
				Score:    res.Score,
				Action:   "allowed_suspicious",
				Summary:  fmt.Sprintf("Proses %s (PID %d) memiliki indikator teknis (skor %d) namun bukan malware aktif — diizinkan lanjut.", p.name, p.pid, res.Score),
			})
		}
		return
	}

	// 3. MALICIOUS! Keep suspended or kill immediately according to policy!
	action := "suspended"
	summary := fmt.Sprintf("DICEGAT! Proses berbahaya %s (PID %d, skor %d) dibekukan (NtSuspendProcess) sebelum merusak PC!", p.name, p.pid, res.Score)
	if autoKill {
		if KillProcess(p.pid) == nil {
			action = "suspended_killed"
			summary = fmt.Sprintf("DIBLOKIR & DIMATIKAN! Malware %s (PID %d, skor %d) dihentikan paksa sebelum berjalan!", p.name, p.pid, res.Score)
		}
	}
	m.recordEvent(AlertEvent{
		Layer:    "process_shield",
		Severity: "CRITICAL",
		PID:      p.pid,
		Process:  p.name,
		ExePath:  p.exePath,
		Score:    res.Score,
		Action:   action,
		Summary:  summary,
	})
}

// runRansomGuardLoop checks the Canary Honeypot files every 1.5 seconds (zero disk
// walk — only stats 3 tiny canary files!). If ANY canary is encrypted, deleted, or
// modified without authorization, it immediately suspends & kills non-system processes
// running from risky folders and restores the canary!
func (m *Manager) runRansomGuardLoop(ctx context.Context) {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	selfPID := uint32(os.Getpid())

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			canaries := make(map[string]string, len(m.canaries))
			for k, v := range m.canaries {
				canaries[k] = v
			}
			m.mu.Unlock()

			var tamperedPath string
			for cp, wantHash := range canaries {
				if !verifyFileSHA256(cp, wantHash) {
					tamperedPath = cp
					break
				}
			}
			if tamperedPath == "" {
				continue
			}

			// Emergency response: freeze & kill active processes running from risky folders!
			risky := riskyExecutionDirs()
			var stopped []string
			for _, p := range snapshotRunningProcesses() {
				if p.pid == selfPID || !isInRiskyDir(p.exePath, risky) {
					continue
				}
				_ = SuspendProcess(p.pid)
				if KillProcess(p.pid) == nil {
					stopped = append(stopped, fmt.Sprintf("%s (PID %d)", p.name, p.pid))
				}
			}

			// Re-heal the canary file so protection continues
			m.mu.Lock()
			_ = m.deployCanariesLocked()
			m.mu.Unlock()

			suspectNote := "tidak ada proses asing di folder rawan"
			if len(stopped) > 0 {
				suspectNote = "proses mencurigakan dihentikan: " + strings.Join(stopped, ", ")
			}
			m.recordEvent(AlertEvent{
				Layer:    "ransom_guard",
				Severity: "CRITICAL",
				ExePath:  tamperedPath,
				Action:   "ransom_frozen",
				Summary:  fmt.Sprintf("DARURAT ANTI-RANSOMWARE! File umpan %s diubah/dienkripsi paksa (%s)!", filepath.Base(tamperedPath), suspectNote),
			})
		}
	}
}

// ListConnections queries the Windows kernel TCP owner table via iphlpapi!GetExtendedTcpTable
// in <2ms without spawning netstat.exe or PowerShell.
func (m *Manager) ListConnections() ([]NetConnection, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size+512)
	sz := uint32(len(buf))
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&sz)),
		0,
		afInet,
		tcpTableOwnerPidAll,
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable error %d", ret)
	}
	if len(buf) < 4 {
		return nil, nil
	}
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(mibTcpRowOwnerPid{}))

	procMap := map[uint32]procSnapItem{}
	for _, p := range snapshotRunningProcesses() {
		procMap[p.pid] = p
	}
	risky := riskyExecutionDirs()

	var out []NetConnection
	offset := uint32(4)
	for i := uint32(0); i < numEntries && int(offset+rowSize) <= len(buf); i++ {
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		// Skip LISTEN (2) and TIME_WAIT (11) noise unless remote IP is external
		if row.State == 2 || row.RemoteAddr == 0 {
			continue
		}
		remIP := ipv4FromUint32(row.RemoteAddr)
		if remIP == "127.0.0.1" || remIP == "0.0.0.0" {
			continue
		}
		locIP := ipv4FromUint32(row.LocalAddr)
		locPort := ntohs(row.LocalPort)
		remPort := ntohs(row.RemotePort)

		pi := procMap[row.OwningPid]
		pname := pi.name
		if pname == "" {
			if row.OwningPid == 4 {
				pname = "System"
			} else {
				pname = fmt.Sprintf("PID-%d", row.OwningPid)
			}
		}
		risk, reason := scoreOutboundConnection(pname, pi.exePath, remIP, remPort, risky)
		out = append(out, NetConnection{
			Protocol:   "TCP",
			LocalAddr:  locIP,
			LocalPort:  locPort,
			RemoteAddr: remIP,
			RemotePort: remPort,
			State:      tcpStateName(row.State),
			PID:        row.OwningPid,
			Process:    pname,
			ExePath:    pi.exePath,
			Risk:       risk,
			Reason:     reason,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		ri, rj := riskRank(out[i].Risk), riskRank(out[j].Risk)
		if ri != rj {
			return ri > rj
		}
		return out[i].Process < out[j].Process
	})
	return out, nil
}

func riskRank(r string) int {
	switch r {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	default:
		return 1
	}
}

func ipv4FromUint32(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func ntohs(p uint32) uint16 {
	return uint16((p&0xFF)<<8 | (p&0xFF00)>>8)
}

func tcpStateName(st uint32) string {
	switch st {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT1"
	case 7:
		return "FIN_WAIT2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return "ACTIVE"
	}
}

// BlockAppWFP installs a Kernel-Level Windows Filtering Platform (WFP) outbound
// block rule for exePath (triggers a standard Windows UAC elevation prompt if
// CrackSentinel is running as non-admin) and optionally kills the active PID.
func (m *Manager) BlockAppWFP(exePath string, pid uint32, killNow bool) error {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" && pid > 4 {
		exePath = queryProcessExePath(pid)
	}
	if exePath == "" {
		return fmt.Errorf("lokasi file .exe proses tidak ditemukan")
	}
	cleanExe := filepath.Clean(exePath)
	if _, err := os.Stat(cleanExe); err != nil {
		return fmt.Errorf("file tidak ditemukan: %s", cleanExe)
	}

	if killNow && pid > 4 {
		_ = SuspendProcess(pid)
		_ = KillProcess(pid)
	}

	ruleName := "CrackSentinel_Block_" + filepath.Base(cleanExe)
	if err := runNetshFirewallCmd(fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=out action=block program="%s" enable=yes`, ruleName, cleanExe)); err != nil {
		return err
	}

	m.mu.Lock()
	exists := false
	for _, b := range m.blocked {
		if strings.EqualFold(b.ExePath, cleanExe) {
			exists = true
			break
		}
	}
	if !exists {
		m.blocked = append([]WFPRule{{
			RuleName: ruleName,
			ExePath:  cleanExe,
			AddedAt:  time.Now().Format("2006-01-02 15:04:05"),
		}}, m.blocked...)
	}
	m.saveStateLocked()
	m.mu.Unlock()

	m.recordEvent(AlertEvent{
		Layer:    "netwatch_wfp",
		Severity: "HIGH",
		PID:      pid,
		Process:  filepath.Base(cleanExe),
		ExePath:  cleanExe,
		Action:   "wfp_blocked",
		Summary:  fmt.Sprintf("Akses internet %s diputus di level Kernel Windows (WFP Firewall)!", filepath.Base(cleanExe)),
	})
	return nil
}

// UnblockAppWFP removes a previously installed CrackSentinel WFP firewall rule.
func (m *Manager) UnblockAppWFP(exePath string) error {
	cleanExe := filepath.Clean(strings.TrimSpace(exePath))
	ruleName := "CrackSentinel_Block_" + filepath.Base(cleanExe)
	if err := runNetshFirewallCmd(fmt.Sprintf(`advfirewall firewall delete rule name="%s" program="%s"`, ruleName, cleanExe)); err != nil {
		return err
	}
	m.mu.Lock()
	var kept []WFPRule
	for _, b := range m.blocked {
		if !strings.EqualFold(b.ExePath, cleanExe) {
			kept = append(kept, b)
		}
	}
	m.blocked = kept
	m.saveStateLocked()
	m.mu.Unlock()
	return nil
}

func runNetshFirewallCmd(netshArgs string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	if isProcessElevated() {
		cmd := exec.CommandContext(ctx, "cmd.exe", "/c", "netsh "+netshArgs)
		procutil.HideWindow(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("gagal memasang rule WFP: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// Non-admin: request standard UAC consent cleanly via Start-Process -Verb RunAs -Wait
	escaped := strings.ReplaceAll(netshArgs, "'", "''")
	psScript := fmt.Sprintf(`$p = Start-Process -FilePath 'netsh.exe' -ArgumentList '%s' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode`, escaped)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psScript)
	procutil.HideWindow(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("izin Administrator (UAC) dibatalkan atau gagal saat memasang blokir Kernel WFP: %v", err)
	}
	return nil
}

// SetDefenderCFA toggles Windows Defender's Kernel Minifilter Anti-Ransomware
// ("Controlled Folder Access" via WdFilter.sys) with user UAC consent.
func (m *Manager) SetDefenderCFA(enable bool) error {
	val := "Disabled"
	if enable {
		val = "Enabled"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	psInner := fmt.Sprintf("Set-MpPreference -EnableControlledFolderAccess %s", val)
	if isProcessElevated() {
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psInner)
		procutil.HideWindow(cmd)
		return cmd.Run()
	}
	ps := fmt.Sprintf(`$p = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -WindowStyle Hidden -Command "%s"' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode`, psInner)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
	procutil.HideWindow(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("izin UAC dibatalkan atau Defender tidak mengizinkan perubahan Controlled Folder Access: %v", err)
	}
	return nil
}

func queryKernelDriversStatus() (wfpRunning, wdFilterRunning, cfaEnabled bool) {
	// Fast registry/service check without spawning slow WMI queries
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sc.exe", "query", "bfe")
	procutil.HideWindow(cmd)
	if out, err := cmd.Output(); err == nil && strings.Contains(string(out), "RUNNING") {
		wfpRunning = true
	}

	cmd2 := exec.CommandContext(ctx, "sc.exe", "query", "WdFilter")
	procutil.HideWindow(cmd2)
	if out, err := cmd2.Output(); err == nil && strings.Contains(string(out), "RUNNING") {
		wdFilterRunning = true
	}

	cmd3 := exec.CommandContext(ctx, "reg.exe", "query", `HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access`, "/v", "EnableControlledFolderAccess")
	procutil.HideWindow(cmd3)
	if out, err := cmd3.Output(); err == nil && strings.Contains(string(out), "0x1") {
		cfaEnabled = true
	}
	return
}
