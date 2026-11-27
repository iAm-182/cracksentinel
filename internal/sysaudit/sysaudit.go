package sysaudit

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gamecrack-scanner/internal/procutil"
)

// Finding represents one suspicious post-install persistence or AV-tamper item on the host PC.
type Finding struct {
	Category  string `json:"category"` // "defender", "autorun", "startup", "schtask", "hosts", "memory", "discord_steam"
	Risk      string `json:"risk"`     // "HIGH", "MEDIUM", "INFO"
	Title     string `json:"title"`
	Location  string `json:"location"`
	Command   string `json:"command"`
	Reason    string `json:"reason"`
	FixAction string `json:"fix_action,omitempty"`
	FixTarget string `json:"fix_target,omitempty"`
	FixLabel  string `json:"fix_label,omitempty"`
}

// Report summarizes a read-only Post-Install PC Security & Persistence Audit.
type Report struct {
	ScannedAt          string    `json:"scanned_at"`
	DurationMs         int64     `json:"duration_ms"`
	Supported          bool      `json:"supported"`
	Status             string    `json:"status"` // "SAFE", "WARNING", "CRITICAL"
	HighCount          int       `json:"high_count"`
	MediumCount        int       `json:"medium_count"`
	RealtimeProtection *bool     `json:"realtime_protection,omitempty"`
	CheckedLocations   int       `json:"checked_locations"`
	Findings           []Finding `json:"findings"`
	Error              string    `json:"error,omitempty"`
}

type rawAuditPayload struct {
	RealtimeDisabled *bool    `json:"realtime_disabled"`
	ExclusionPaths   []string `json:"exclusion_paths"`
	ExclusionExts    []string `json:"exclusion_exts"`
	ExclusionProcs   []string `json:"exclusion_procs"`
	Autoruns         []struct {
		Hive string `json:"hive"`
		Name string `json:"name"`
		Val  string `json:"val"`
	} `json:"autoruns"`
	StartupFiles []struct {
		Name   string `json:"name"`
		Path   string `json:"path"`
		Target string `json:"target"`
	} `json:"startup_files"`
	Tasks []struct {
		Name   string `json:"name"`
		Path   string `json:"path"`
		Action string `json:"action"`
	} `json:"tasks"`
	HostsTampered []string `json:"hosts_tampered"`
}

var (
	reSuspUserDropDir = regexp.MustCompile(`(?i)(\\appdata\\roaming\\|\\appdata\\local\\temp\\|\\users\\public\\|\\programdata\\|\\perflogs\\|%temp%|%appdata%)`)
	reSuspLoLBinCmd   = regexp.MustCompile(`(?i)(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|cmd\.exe\s+/c|-enc|-w\s+hidden|frombase64string|http://|https://)`)
	reBroadDefenderEx = regexp.MustCompile(`(?i)^([a-z]:\\?$|.*\\appdata(\\|$)|.*\\temp(\\|$)|.*\\users\\public|.*\\programdata(\\|$)|.*\\downloads(\\|$))`)
	benignAutorunSubs = []string{
		`\microsoft\onedrive\`, `\microsoft\teams\`, `\microsoft\edge\`, `\google\chrome\`,
		`\spotify\`, `\discord\update.exe`, `\valve\steam\`, `\epic games\`, `\riot games\`,
		`\braveSoftware\`, `\mozilla firefox\`, `\nvidia corporation\`, `\amd\`, `\realtek\`,
	}
)

// Run executes a fast (<3s), strictly read-only Windows security & persistence audit.
func Run(ctx context.Context) Report {
	t0 := time.Now()
	rep := Report{
		ScannedAt: t0.Format("2006-01-02 15:04:05"),
		Supported: runtime.GOOS == "windows",
		Status:    "SAFE",
		Findings:  []Finding{},
	}
	if runtime.GOOS != "windows" {
		rep.Error = "Fitur Audit Keamanan PC khusus untuk sistem operasi Windows."
		return rep
	}

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	psScript := `
$ErrorActionPreference = 'SilentlyContinue'
$out = @{
  realtime_disabled = $null
  exclusion_paths   = @()
  exclusion_exts    = @()
  exclusion_procs   = @()
  autoruns          = @()
  startup_files     = @()
  tasks             = @()
  hosts_tampered    = @()
}

try {
  $mp = Get-MpPreference
  if ($null -ne $mp) {
    $out.realtime_disabled = [bool]$mp.DisableRealtimeMonitoring
    if ($mp.ExclusionPath) { $out.exclusion_paths = @($mp.ExclusionPath | Where-Object { $_ }) }
    if ($mp.ExclusionExtension) { $out.exclusion_exts = @($mp.ExclusionExtension | Where-Object { $_ }) }
    if ($mp.ExclusionProcess) { $out.exclusion_procs = @($mp.ExclusionProcess | Where-Object { $_ }) }
  }
} catch {}

$rkPaths = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($rk in $rkPaths) {
  if (Test-Path $rk) {
    $props = Get-ItemProperty -Path $rk
    foreach ($p in $props.PSObject.Properties) {
      if ($p.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' -and $p.Value) {
        $out.autoruns += @{ hive = $rk; name = [string]$p.Name; val = [string]$p.Value }
      }
    }
  }
}

$stDirs = @(
  [Environment]::GetFolderPath('Startup'),
  [Environment]::GetFolderPath('CommonStartup')
)
$ws = New-Object -ComObject WScript.Shell
foreach ($sd in $stDirs) {
  if ($sd -and (Test-Path $sd)) {
    foreach ($f in (Get-ChildItem -Path $sd -File -Force)) {
      if ($f.Name -ieq 'desktop.ini') { continue }
      $tgt = $f.FullName
      if ($f.Extension -ieq '.lnk') {
        try {
          $sc = $ws.CreateShortcut($f.FullName)
          $tgt = ($sc.TargetPath + ' ' + $sc.Arguments).Trim()
        } catch {}
      }
      $out.startup_files += @{ name = $f.Name; path = $f.FullName; target = $tgt }
    }
  }
}

try {
  foreach ($t in (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' })) {
    foreach ($a in $t.Actions) {
      $act = ([string]$a.Execute + ' ' + [string]$a.Arguments).Trim()
      if ($act) {
        $out.tasks += @{ name = $t.TaskName; path = $t.TaskPath; action = $act }
      }
    }
  }
} catch {}

$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hostsFile) {
  foreach ($line in (Get-Content $hostsFile)) {
    $t = $line.Trim()
    if ($t -and -not $t.StartsWith('#')) {
      if ($t -match '(?i)(virustotal|malwarebytes|windowsupdate|defender|kaspersky|bitdefender|avast|eset)') {
        $out.hosts_tampered += $t
      }
    }
  }
}

$out | ConvertTo-Json -Depth 5 -Compress
`
	cmd := exec.CommandContext(cctx, "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psScript)
	procutil.HideWindow(cmd)
	rawBytes, err := cmd.Output()
	if err != nil && len(rawBytes) == 0 {
		rep.Error = "Gagal membaca data audit sistem: " + err.Error()
		rep.DurationMs = time.Since(t0).Milliseconds()
		return rep
	}

	var raw rawAuditPayload
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		rep.Error = "Gagal mem-parsing output audit sistem."
		rep.DurationMs = time.Since(t0).Milliseconds()
		return rep
	}

	rep.CheckedLocations = 8 + len(raw.Autoruns) + len(raw.StartupFiles) + len(raw.Tasks)
	if raw.RealtimeDisabled != nil {
		rtOn := !(*raw.RealtimeDisabled)
		rep.RealtimeProtection = &rtOn
	}
	memFindings, procsScanned := scanInjectedProcesses()
	clientFindings, clientsChecked := scanClientIntegrity()
	rep.CheckedLocations += procsScanned + clientsChecked
	evaluateRawAudit(raw, &rep)
	for _, cf := range clientFindings {
		rep.Findings = append([]Finding{cf}, rep.Findings...)
		if cf.Risk == "HIGH" {
			rep.HighCount++
			rep.Status = "CRITICAL"
		}
	}
	for _, mf := range memFindings {
		rep.Findings = append([]Finding{mf}, rep.Findings...)
		if mf.Risk == "HIGH" {
			rep.HighCount++
			rep.Status = "CRITICAL"
		}
	}
	rep.DurationMs = time.Since(t0).Milliseconds()
	return rep
}

func evaluateRawAudit(raw rawAuditPayload, rep *Report) {
	add := func(f Finding) {
		rep.Findings = append(rep.Findings, f)
		if f.Risk == "HIGH" {
			rep.HighCount++
		} else if f.Risk == "MEDIUM" {
			rep.MediumCount++
		}
	}

	// 1. Windows Defender Real-Time Protection & Exclusions
	if raw.RealtimeDisabled != nil && *raw.RealtimeDisabled {
		add(Finding{
			Category:  "defender",
			Risk:      "HIGH",
			Title:     "Windows Defender Real-Time Protection Mati!",
			Location:  "Windows Security (DisableRealtimeMonitoring = True)",
			Command:   "RealtimeMonitoring: Disabled",
			Reason:    "Proteksi real-time Windows Defender sedang nonaktif (sering dimatikan diam-diam oleh crack bervirus atau jika Anda memakai antivirus pihak ketiga).",
			FixAction: "enable_defender_realtime",
			FixTarget: "true",
			FixLabel:  "Aktifkan Defender",
		})
	}
	for _, ex := range raw.ExclusionPaths {
		exTrim := strings.TrimSpace(ex)
		if exTrim == "" {
			continue
		}
		if reBroadDefenderEx.MatchString(exTrim) {
			add(Finding{
				Category:  "defender",
				Risk:      "HIGH",
				Title:     "Pengecualian Windows Defender Berbahaya (Folder Rawan Malware)",
				Location:  "Defender ExclusionPath",
				Command:   exTrim,
				Reason:    "Malware crack sangat sering menambahkan C:\\, %APPDATA%, %TEMP%, atau ProgramData ke ExclusionPath agar virusnya tidak terdeteksi Defender!",
				FixAction: "remove_defender_exclusion_path",
				FixTarget: exTrim,
				FixLabel:  "Hapus Exclusion",
			})
		} else {
			add(Finding{
				Category:  "defender",
				Risk:      "MEDIUM",
				Title:     "Folder Masuk Daftar Pengecualian Defender",
				Location:  "Defender ExclusionPath",
				Command:   exTrim,
				Reason:    "Pastikan Anda sendiri yang mengecualikan folder ini, bukan ditambahkan otomatis oleh installer mencurigakan.",
				FixAction: "remove_defender_exclusion_path",
				FixTarget: exTrim,
				FixLabel:  "Hapus Exclusion",
			})
		}
	}
	for _, ext := range raw.ExclusionExts {
		low := strings.ToLower(strings.TrimSpace(ext))
		if low == ".exe" || low == "exe" || low == ".dll" || low == "dll" || low == ".ps1" || low == "ps1" || low == ".bat" || low == "bat" {
			add(Finding{
				Category:  "defender",
				Risk:      "HIGH",
				Title:     "Ekstensi Executable Dikecualikan dari Antivirus!",
				Location:  "Defender ExclusionExtension",
				Command:   ext,
				Reason:    "Mengecualikan seluruh file .exe/.dll/.ps1 membuat semua virus kebal terhadap Windows Defender!",
				FixAction: "remove_defender_exclusion_ext",
				FixTarget: ext,
				FixLabel:  "Hapus Exclusion",
			})
		}
	}
	for _, pr := range raw.ExclusionProcs {
		low := strings.ToLower(strings.TrimSpace(pr))
		if strings.Contains(low, "powershell") || strings.Contains(low, "cmd.exe") || strings.Contains(low, "mshta") || strings.Contains(low, "rundll32") || strings.Contains(low, "regsvr32") {
			add(Finding{
				Category:  "defender",
				Risk:      "HIGH",
				Title:     "Proses Sistem Dikecualikan dari Antivirus!",
				Location:  "Defender ExclusionProcess",
				Command:   pr,
				Reason:    "Mengecualikan powershell/cmd/rundll32 dari Defender adalah teknik klasik trojan/RAT!",
				FixAction: "remove_defender_exclusion_proc",
				FixTarget: pr,
				FixLabel:  "Hapus Exclusion",
			})
		}
	}

	// 2. Registry Run / RunOnce Autoruns
	for _, ar := range raw.Autoruns {
		if isKnownBenignAutorun(ar.Val) {
			continue
		}
		hasLOL := reSuspLoLBinCmd.MatchString(ar.Val)
		hasDrop := reSuspUserDropDir.MatchString(ar.Val)
		if hasLOL && hasDrop {
			add(Finding{
				Category:  "autorun",
				Risk:      "HIGH",
				Title:     "Autorun Registry Mencurigakan (Script + Folder Temp/AppData)",
				Location:  ar.Hive + `\` + ar.Name,
				Command:   ar.Val,
				Reason:    "Menjalankan script/LOLBin otomatis saat login Windows dari folder AppData/Temp/Public — pola utama RAT & Stealer!",
				FixAction: "delete_registry_value",
				FixTarget: ar.Hive + "|" + ar.Name,
				FixLabel:  "Hapus Autorun",
			})
		} else if hasLOL || hasDrop {
			add(Finding{
				Category:  "autorun",
				Risk:      "MEDIUM",
				Title:     "Program Startup Registry Non-Standar",
				Location:  ar.Hive + `\` + ar.Name,
				Command:   ar.Val,
				Reason:    "Berjalan otomatis dari lokasi user/script saat Windows menyala — periksa apakah ini aplikasi resmi Anda.",
				FixAction: "delete_registry_value",
				FixTarget: ar.Hive + "|" + ar.Name,
				FixLabel:  "Hapus Autorun",
			})
		}
	}

	// 3. Startup Folder Items
	for _, sf := range raw.StartupFiles {
		if isKnownBenignAutorun(sf.Target) {
			continue
		}
		ext := strings.ToLower(filepath.Ext(sf.Name))
		isScript := ext == ".vbs" || ext == ".vbe" || ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".js" || ext == ".hta" || ext == ".wsf"
		if isScript || reSuspLoLBinCmd.MatchString(sf.Target) || reSuspUserDropDir.MatchString(sf.Target) {
			risk := "MEDIUM"
			if isScript || reSuspLoLBinCmd.MatchString(sf.Target) {
				risk = "HIGH"
			}
			add(Finding{
				Category:  "startup",
				Risk:      risk,
				Title:     "File Mencurigakan di Folder Startup Windows: " + sf.Name,
				Location:  sf.Path,
				Command:   sf.Target,
				Reason:    "File script/shortcut di folder Startup otomatis dieksekusi setiap PC menyala.",
				FixAction: "quarantine_file",
				FixTarget: sf.Path,
				FixLabel:  "Karantina Startup",
			})
		}
	}

	// 4. Non-Microsoft Scheduled Tasks
	for _, tk := range raw.Tasks {
		if isKnownBenignAutorun(tk.Action) {
			continue
		}
		hasLOL := reSuspLoLBinCmd.MatchString(tk.Action)
		hasDrop := reSuspUserDropDir.MatchString(tk.Action)
		if hasLOL && hasDrop {
			add(Finding{
				Category:  "schtask",
				Risk:      "HIGH",
				Title:     "Scheduled Task Berbahaya: " + tk.Name,
				Location:  tk.Path + tk.Name,
				Command:   tk.Action,
				Reason:    "Tugas terjadwal menjalankan PowerShell/LOLBin ke arah AppData/Temp/Public — teknik persistensi favorit Lumma/AsyncRAT/XWorm!",
				FixAction: "delete_scheduled_task",
				FixTarget: tk.Path + tk.Name,
				FixLabel:  "Hapus Task",
			})
		} else if hasLOL {
			add(Finding{
				Category:  "schtask",
				Risk:      "MEDIUM",
				Title:     "Scheduled Task Menjalankan Script/Shell: " + tk.Name,
				Location:  tk.Path + tk.Name,
				Command:   tk.Action,
				Reason:    "Tugas terjadwal memanggil PowerShell/cmd/wscript — pastikan tugas ini milik aplikasi yang Anda kenal.",
				FixAction: "delete_scheduled_task",
				FixTarget: tk.Path + tk.Name,
				FixLabel:  "Hapus Task",
			})
		}
	}

	// 5. Hosts File Antivirus Blocking
	for _, hl := range raw.HostsTampered {
		add(Finding{
			Category:  "hosts",
			Risk:      "HIGH",
			Title:     "File Hosts Memblokir Domain Antivirus / Windows Update!",
			Location:  `C:\Windows\System32\drivers\etc\hosts`,
			Command:   hl,
			Reason:    "Malware membelokkan domain antivirus/VirusTotal/Windows Update di file hosts agar tidak bisa diakses!",
			FixAction: "clean_hosts_file",
			FixTarget: hl,
			FixLabel:  "Pulihkan Hosts",
		})
	}

	if rep.HighCount > 0 {
		rep.Status = "CRITICAL"
	} else if rep.MediumCount > 0 {
		rep.Status = "WARNING"
	} else {
		rep.Status = "SAFE"
	}
}

func isKnownBenignAutorun(cmd string) bool {
	low := strings.ToLower(cmd)
	if reSuspLoLBinCmd.MatchString(low) {
		return false
	}
	for _, sub := range benignAutorunSubs {
		if strings.Contains(low, sub) {
			return true
		}
	}
	return false
}
