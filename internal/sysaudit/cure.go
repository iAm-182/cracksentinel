package sysaudit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gamecrack-scanner/internal/procutil"
)

// ApplyFix executes a 1-Click Remediation ("Auto-Fix / Cure") for an Audit PC finding.
// Backup copies of quarantined startup files or infected Discord index.js scripts are
// preserved in quarantineDir before remediation.
func ApplyFix(ctx context.Context, action, target, quarantineDir string) (string, error) {
	action = strings.TrimSpace(action)
	target = strings.TrimSpace(target)
	if action == "" || target == "" {
		return "", fmt.Errorf("parameter fix_action dan fix_target diperlukan")
	}

	switch action {
	case "reset_discord_index":
		// Back up the infected index.js into quarantineDir for forensic record, then write the clean 1-liner!
		if st, err := os.Stat(target); err != nil || st.IsDir() {
			return "", fmt.Errorf("file Discord index.js tidak ditemukan: %s", target)
		}
		if quarantineDir != "" {
			_ = os.MkdirAll(quarantineDir, 0o755)
			if raw, err := os.ReadFile(target); err == nil {
				bak := filepath.Join(quarantineDir, fmt.Sprintf("discord_injected_index_%d.js.bak", time.Now().Unix()))
				_ = os.WriteFile(bak, raw, 0o600)
			}
		}
		cleanBytes := []byte(cleanDiscordIndexJS + "\n")
		if err := os.WriteFile(target, cleanBytes, 0o644); err != nil {
			return "", fmt.Errorf("gagal membersihkan Discord index.js: %v", err)
		}
		return "Injeksi Discord berhasil dibersihkan! File index.js dikembalikan ke kondisi asli (module.exports = require('./core.asar');). Silakan restart aplikasi Discord.", nil

	case "quarantine_file":
		st, err := os.Stat(target)
		if err != nil || st.IsDir() {
			return "", fmt.Errorf("file target tidak ditemukan: %s", target)
		}
		if quarantineDir == "" {
			if err := os.Remove(target); err != nil {
				return "", fmt.Errorf("gagal menghapus file berbahaya: %v", err)
			}
			return "File berbahaya berhasil dihapus: " + filepath.Base(target), nil
		}
		_ = os.MkdirAll(quarantineDir, 0o755)
		dst := filepath.Join(quarantineDir, fmt.Sprintf("cured_%d_%s.quar", time.Now().Unix(), filepath.Base(target)))
		if err := os.Rename(target, dst); err != nil {
			// Cross-drive fallback: copy + remove
			raw, rerr := os.ReadFile(target)
			if rerr != nil {
				return "", fmt.Errorf("gagal memindahkan file ke karantina: %v", err)
			}
			if werr := os.WriteFile(dst, raw, 0o600); werr != nil {
				return "", fmt.Errorf("gagal menulis ke karantina: %v", werr)
			}
			if rmErr := os.Remove(target); rmErr != nil {
				return "", fmt.Errorf("file memerlukan izin Administrator untuk dihapus: %v", rmErr)
			}
		}
		return fmt.Sprintf("File %s berhasil diisolasi ke Quarantine Vault!", filepath.Base(target)), nil

	case "kill_process":
		pid, err := strconv.ParseUint(target, 10, 32)
		if err != nil || pid <= 4 {
			return "", fmt.Errorf("PID tidak valid: %s", target)
		}
		if runtime.GOOS != "windows" {
			return "", fmt.Errorf("hanya didukung di Windows")
		}
		cmd := exec.CommandContext(ctx, "taskkill.exe", "/F", "/PID", strconv.FormatUint(pid, 10))
		procutil.HideWindow(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("gagal mematikan PID %d: %v (%s)", pid, err, strings.TrimSpace(string(out)))
		}
		return fmt.Sprintf("Proses terinjeksi (PID %d) berhasil dihentikan paksa!", pid), nil

	case "delete_registry_value":
		parts := strings.SplitN(target, "|", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("format target registry tidak valid")
		}
		hivePath, valName := parts[0], parts[1]
		psCmd := fmt.Sprintf(`Remove-ItemProperty -LiteralPath '%s' -Name '%s' -ErrorAction Stop`,
			strings.ReplaceAll(hivePath, "'", "''"),
			strings.ReplaceAll(valName, "'", "''"))
		needsAdmin := strings.HasPrefix(strings.ToUpper(hivePath), "HKLM:")
		if err := runPowerShellCure(ctx, psCmd, needsAdmin); err != nil {
			return "", fmt.Errorf("gagal menghapus registry autorun %s: %v", valName, err)
		}
		return fmt.Sprintf("Autorun Registry %q berhasil dihapus!", valName), nil

	case "delete_scheduled_task":
		taskFull := target
		psCmd := fmt.Sprintf(`Unregister-ScheduledTask -TaskName '%s' -Confirm:$false -ErrorAction Stop`,
			strings.ReplaceAll(filepath.Base(taskFull), "'", "''"))
		if err := runPowerShellCure(ctx, psCmd, false); err != nil {
			if err2 := runPowerShellCure(ctx, psCmd, true); err2 != nil {
				return "", fmt.Errorf("gagal menghapus Scheduled Task %s: %v", taskFull, err2)
			}
		}
		return fmt.Sprintf("Scheduled Task %q berhasil dihapus!", taskFull), nil

	case "enable_defender_realtime":
		psCmd := `Set-MpPreference -DisableRealtimeMonitoring $false`
		if err := runPowerShellCure(ctx, psCmd, true); err != nil {
			return "", fmt.Errorf("gagal mengaktifkan Windows Defender Real-Time Protection: %v", err)
		}
		return "Windows Defender Real-Time Protection berhasil diaktifkan kembali!", nil

	case "remove_defender_exclusion_path":
		psCmd := fmt.Sprintf(`Remove-MpPreference -ExclusionPath '%s'`, strings.ReplaceAll(target, "'", "''"))
		if err := runPowerShellCure(ctx, psCmd, true); err != nil {
			return "", fmt.Errorf("gagal menghapus ExclusionPath Defender: %v", err)
		}
		return fmt.Sprintf("Pengecualian Windows Defender (%s) berhasil dihapus!", target), nil

	case "remove_defender_exclusion_ext":
		psCmd := fmt.Sprintf(`Remove-MpPreference -ExclusionExtension '%s'`, strings.ReplaceAll(target, "'", "''"))
		if err := runPowerShellCure(ctx, psCmd, true); err != nil {
			return "", fmt.Errorf("gagal menghapus ExclusionExtension Defender: %v", err)
		}
		return fmt.Sprintf("Pengecualian ekstensi (%s) di Windows Defender berhasil dihapus!", target), nil

	case "remove_defender_exclusion_proc":
		psCmd := fmt.Sprintf(`Remove-MpPreference -ExclusionProcess '%s'`, strings.ReplaceAll(target, "'", "''"))
		if err := runPowerShellCure(ctx, psCmd, true); err != nil {
			return "", fmt.Errorf("gagal menghapus ExclusionProcess Defender: %v", err)
		}
		return fmt.Sprintf("Pengecualian proses (%s) di Windows Defender berhasil dihapus!", target), nil

	case "clean_hosts_file":
		psCmd := `
$hf = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hf) {
  $lines = Get-Content $hf | Where-Object {
    $t = $_.Trim()
    -not ($t -and -not $t.StartsWith('#') -and ($t -match '(?i)(virustotal|malwarebytes|windowsupdate|defender|kaspersky|bitdefender|avast|eset)'))
  }
  Set-Content -Path $hf -Value $lines -Encoding ASCII -Force
}
`
		if err := runPowerShellCure(ctx, psCmd, true); err != nil {
			return "", fmt.Errorf("gagal membersihkan file hosts: %v", err)
		}
		return "Baris pembajakan domain Antivirus/Windows Update di file hosts berhasil dibersihkan!", nil

	default:
		return "", fmt.Errorf("aksi perbaikan tidak dikenal: %s", action)
	}
}

func runPowerShellCure(ctx context.Context, psCommand string, elevateUAC bool) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("hanya didukung di Windows")
	}
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	if !elevateUAC {
		cmd := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psCommand)
		procutil.HideWindow(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// First try direct execution in case CrackSentinel is already running elevated
	direct := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psCommand)
	procutil.HideWindow(direct)
	if err := direct.Run(); err == nil {
		return nil
	}

	// Request UAC elevation cleanly via Start-Process -Verb RunAs -Wait
	escaped := strings.ReplaceAll(psCommand, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, `'`, `''`)
	uacScript := fmt.Sprintf(`$p = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -WindowStyle Hidden -Command "%s"' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode`, escaped)
	cmd := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", uacScript)
	procutil.HideWindow(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("izin Administrator (UAC) dibatalkan atau perintah ditolak: %v", err)
	}
	return nil
}
