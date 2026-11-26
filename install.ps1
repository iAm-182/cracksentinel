# CrackSentinel 1-Click Windows Installer
# Usage:
#   irm https://raw.githubusercontent.com/iAm-182/cracksentinel/main/install.ps1 | iex
# Optional custom folder:
#   $env:CRACKSENTINEL_DIR = "E:\CrackSentinel"; irm https://raw.githubusercontent.com/iAm-182/cracksentinel/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "iAm-182/cracksentinel"
$InstallDir = if ($env:CRACKSENTINEL_DIR) { $env:CRACKSENTINEL_DIR } else { Join-Path $env:LOCALAPPDATA "CrackSentinel" }
$ToolsDir = Join-Path $InstallDir "tools"
$TmpDir = Join-Path $InstallDir "tmp"

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   CrackSentinel - 1-Click Installer (Windows Desktop)  " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Install folder : $InstallDir"
Write-Host ""

New-Item -ItemType Directory -Force -Path $InstallDir, $ToolsDir, $TmpDir | Out-Null

# 1. Fetch latest release metadata from GitHub
Write-Host "[1/5] Mencari rilis terbaru CrackSentinel di GitHub..." -ForegroundColor Yellow
$headers = @{ "User-Agent" = "CrackSentinel-Installer"; "Accept" = "application/vnd.github+json" }
$rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
$ver = $rel.tag_name
Write-Host "      Versi terbaru: $ver" -ForegroundColor Green

function Get-AssetUrl($release, $name) {
    $a = $release.assets | Where-Object { $_.name -ieq $name } | Select-Object -First 1
    if ($a) { return $a.browser_download_url }
    return $null
}

# 2. Download checksums.txt (GitHub S3 serves release .txt as application/octet-stream -> decode byte[] in PS 5.1)
$checksums = @{}
$csUrl = Get-AssetUrl $rel "checksums.txt"
if (-not $csUrl) { throw "checksums.txt tidak ditemukan pada rilis $ver" }
$csRaw = (Invoke-WebRequest -UseBasicParsing -Uri $csUrl -Headers $headers).Content
$csText = if ($csRaw -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($csRaw) } else { [string]$csRaw }
foreach ($line in ($csText -split "`r?`n")) {
    $parts = ($line.Trim() -split "\s+")
    if ($parts.Length -ge 2 -and $parts[0].Length -eq 64) {
        $fname = [System.IO.Path]::GetFileName($parts[1].TrimStart('*')).ToLower()
        $checksums[$fname] = $parts[0].ToLower()
    }
}
if ($checksums.Count -eq 0) {
    throw "Gagal membaca daftar SHA-256 dari checksums.txt"
}

function Download-Verified($url, $dest, $assetName) {
    $tmp = "$dest.download"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp -Headers $headers
    $expected = $checksums[$assetName.ToLower()]
    if (-not $expected) {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        throw "Checksum SHA-256 untuk $assetName tidak ditemukan di checksums.txt"
    }
    $got = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $expected) {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        throw "SHA-256 mismatch untuk $assetName! (expected $expected, got $got)"
    }
    Write-Host "      SHA-256 terverifikasi: $assetName" -ForegroundColor Green
    if (Test-Path $dest) {
        $old = "$dest.old"
        Remove-Item -Force $old -ErrorAction SilentlyContinue
        Move-Item -Force $dest $old -ErrorAction SilentlyContinue
    }
    Move-Item -Force $tmp $dest
}

# 3. Download CrackSentinel.exe + scanner.exe (or portable bundle)
Write-Host "[2/5] Mengunduh CrackSentinel.exe & scanner.exe ($ver)..." -ForegroundColor Yellow
$deskUrl = Get-AssetUrl $rel "CrackSentinel.exe"
$cliUrl = Get-AssetUrl $rel "scanner.exe"
if (-not $deskUrl) { throw "CrackSentinel.exe tidak ditemukan di rilis $ver" }
Download-Verified $deskUrl (Join-Path $InstallDir "CrackSentinel.exe") "CrackSentinel.exe"
if ($cliUrl) {
    Download-Verified $cliUrl (Join-Path $InstallDir "scanner.exe") "scanner.exe"
}

# 4. Ensure 7-Zip & portable YARA64
Write-Host "[3/5] Memeriksa 7-Zip (untuk bongkar RAR/7z/ISO/MSI)..." -ForegroundColor Yellow
$has7z = (Get-Command 7z -ErrorAction SilentlyContinue) -or (Test-Path "C:\Program Files\7-Zip\7z.exe") -or (Test-Path "C:\Program Files (x86)\7-Zip\7z.exe") -or (Test-Path (Join-Path $ToolsDir "7z.exe"))
if ($has7z) {
    Write-Host "      7-Zip sudah terpasang." -ForegroundColor Green
} elseif (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "      Memasang 7-Zip otomatis via winget..." -ForegroundColor Cyan
    winget install --id 7zip.7zip -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
    Write-Host "      7-Zip selesai dipasang." -ForegroundColor Green
} else {
    Write-Host "      7-Zip tidak ditemukan (winget tidak tersedia). ZIP tetap jalan, install 7-Zip manual untuk RAR/7z/ISO." -ForegroundColor DarkYellow
}

Write-Host "[4/5] Memeriksa YARA engine (yara64.exe portable)..." -ForegroundColor Yellow
$yaraDst = Join-Path $ToolsDir "yara64.exe"
$hasYara = (Get-Command yara64 -ErrorAction SilentlyContinue) -or (Get-Command yara -ErrorAction SilentlyContinue) -or (Test-Path $yaraDst)
if ($hasYara) {
    Write-Host "      YARA sudah tersedia." -ForegroundColor Green
} else {
    try {
        $yRel = Invoke-RestMethod -Uri "https://api.github.com/repos/VirusTotal/yara/releases/latest" -Headers $headers
        $yAsset = $yRel.assets | Where-Object { $_.name -match "win64\.zip$" } | Select-Object -First 1
        if ($yAsset) {
            $yZip = Join-Path $TmpDir "yara-win64.zip"
            $yExt = Join-Path $TmpDir "yara-ext"
            Write-Host "      Mengunduh $($yAsset.name)..." -ForegroundColor Cyan
            Invoke-WebRequest -UseBasicParsing -Uri $yAsset.browser_download_url -OutFile $yZip -Headers $headers
            Remove-Item -Recurse -Force $yExt -ErrorAction SilentlyContinue
            Expand-Archive -Path $yZip -DestinationPath $yExt -Force
            $exeFound = Get-ChildItem -Path $yExt -Recurse -Filter "yara64.exe" | Select-Object -First 1
            if ($exeFound) {
                Copy-Item -Force $exeFound.FullName $yaraDst
                Write-Host "      YARA portable dipasang ke $yaraDst" -ForegroundColor Green
            }
            Remove-Item -Recurse -Force $yZip, $yExt -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "      Lewati download YARA otomatis (engine internal tetap aktif penuh): $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

# 5. Create Desktop & Start Menu Shortcuts
Write-Host "[5/5] Membuat shortcut Desktop & Start Menu..." -ForegroundColor Yellow
$exePath = Join-Path $InstallDir "CrackSentinel.exe"
$ws = New-Object -ComObject WScript.Shell
foreach ($targetLnk in @(
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'CrackSentinel.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Programs')) 'CrackSentinel.lnk')
)) {
    try {
        $lnk = $ws.CreateShortcut($targetLnk)
        $lnk.TargetPath = $exePath
        $lnk.WorkingDirectory = $InstallDir
        $lnk.IconLocation = "$exePath,0"
        $lnk.Description = "CrackSentinel - Game Malware Guard"
        $lnk.Save()
    } catch {}
}

Write-Host ""
Write-Host "SELESAI! CrackSentinel $ver berhasil dipasang di:" -ForegroundColor Green
Write-Host "  $exePath" -ForegroundColor White
Write-Host "  Shortcut Desktop: CrackSentinel.lnk" -ForegroundColor White
Write-Host "  Auto-Update aktif otomatis di dalam Dashboard!" -ForegroundColor Cyan
Write-Host ""

if ($env:CRACKSENTINEL_NO_LAUNCH -ne "1") {
    Start-Process -FilePath $exePath -WorkingDirectory $InstallDir
}
