# CrackSentinel Git-Clone Auto-Setup Script
# Run directly after `git clone https://github.com/iAm-182/cracksentinel.git` (or double-click setup.bat).
# Automatically installs missing dependencies (7-Zip, portable YARA64), builds CrackSentinel.exe + scanner.exe
# (or downloads verified release binaries if Go is not installed), and creates a Desktop shortcut.

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$ToolsDir = Join-Path $Root "tools"
$TmpDir = Join-Path $Root "tmp"
$Repo = "iAm-182/cracksentinel"
$headers = @{ "User-Agent" = "CrackSentinel-Setup"; "Accept" = "application/vnd.github+json" }

New-Item -ItemType Directory -Force -Path $ToolsDir, $TmpDir | Out-Null

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "      CrackSentinel - Automatic Setup & Dependency      " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Folder : $Root"
Write-Host ""

# 1. 7-Zip
Write-Host "[1/4] Memeriksa 7-Zip..." -ForegroundColor Yellow
$has7z = (Get-Command 7z -ErrorAction SilentlyContinue) -or (Test-Path "C:\Program Files\7-Zip\7z.exe") -or (Test-Path "C:\Program Files (x86)\7-Zip\7z.exe") -or (Test-Path (Join-Path $ToolsDir "7z.exe"))
if ($has7z) {
    Write-Host "      OK: 7-Zip tersedia." -ForegroundColor Green
} elseif (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "      Memasang 7-Zip via winget..." -ForegroundColor Cyan
    winget install --id 7zip.7zip -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
    Write-Host "      OK: 7-Zip dipasang." -ForegroundColor Green
} else {
    Write-Host "      Info: 7-Zip belum terpasang (ZIP tetap didukung; pasang 7-Zip untuk RAR/7z/ISO)." -ForegroundColor DarkYellow
}

# 2. YARA portable
Write-Host "[2/4] Memeriksa YARA (yara64.exe)..." -ForegroundColor Yellow
$yaraDst = Join-Path $ToolsDir "yara64.exe"
$hasYara = (Get-Command yara64 -ErrorAction SilentlyContinue) -or (Get-Command yara -ErrorAction SilentlyContinue) -or (Test-Path $yaraDst)
if ($hasYara) {
    Write-Host "      OK: YARA tersedia." -ForegroundColor Green
} else {
    try {
        $yRel = Invoke-RestMethod -Uri "https://api.github.com/repos/VirusTotal/yara/releases/latest" -Headers $headers
        $yAsset = $yRel.assets | Where-Object { $_.name -match "win64\.zip$" } | Select-Object -First 1
        if ($yAsset) {
            $yZip = Join-Path $TmpDir "yara-win64.zip"
            $yExt = Join-Path $TmpDir "yara-ext"
            Write-Host "      Mengunduh YARA portable ($($yAsset.name))..." -ForegroundColor Cyan
            Invoke-WebRequest -UseBasicParsing -Uri $yAsset.browser_download_url -OutFile $yZip -Headers $headers
            Remove-Item -Recurse -Force $yExt -ErrorAction SilentlyContinue
            Expand-Archive -Path $yZip -DestinationPath $yExt -Force
            $exeFound = Get-ChildItem -Path $yExt -Recurse -Filter "yara64.exe" | Select-Object -First 1
            if ($exeFound) {
                Copy-Item -Force $exeFound.FullName $yaraDst
                Write-Host "      OK: YARA portable dipasang di tools\yara64.exe" -ForegroundColor Green
            }
            Remove-Item -Recurse -Force $yZip, $yExt -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "      Info: YARA portable dilewati (engine internal tetap berjalan): $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

# 3. Build from source if Go is installed; otherwise download verified release binaries
Write-Host "[3/4] Menyiapkan CrackSentinel.exe & scanner.exe..." -ForegroundColor Yellow
if (Get-Command go -ErrorAction SilentlyContinue) {
    $ver = "2.0.0"
    $tag = (git describe --tags --abbrev=0 2>$null)
    if ($tag) { $ver = $tag.Trim().TrimStart('v') }
    $commit = (git rev-parse --short HEAD 2>$null)
    if (-not $commit) { $commit = "local" }
    $dt = Get-Date -Format "yyyy-MM-dd"
    $baseLD = "-s -w -X gamecrack-scanner/internal/version.Version=$ver -X gamecrack-scanner/internal/version.Commit=$commit -X gamecrack-scanner/internal/version.BuildDate=$dt"

    $env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
    Write-Host "      Kompilasi CrackSentinel.exe v$ver dari source..." -ForegroundColor Cyan
    go build -trimpath -ldflags "$baseLD -H=windowsgui" -o CrackSentinel.exe ./cmd/desktop
    go build -trimpath -ldflags "$baseLD" -o scanner.exe ./cmd/scanner
    Write-Host "      OK: CrackSentinel.exe & scanner.exe selesai di-build." -ForegroundColor Green
} else {
    Write-Host "      Go tidak terpasang -> mengunduh binary resmi terbaru dari GitHub Releases..." -ForegroundColor Cyan
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
    foreach ($name in @("CrackSentinel.exe", "scanner.exe")) {
        $a = $rel.assets | Where-Object { $_.name -ieq $name } | Select-Object -First 1
        if ($a) {
            Invoke-WebRequest -UseBasicParsing -Uri $a.browser_download_url -OutFile (Join-Path $Root $name) -Headers $headers
            Write-Host "      OK: $name ($($rel.tag_name)) diunduh." -ForegroundColor Green
        }
    }
}

# 4. Desktop Shortcut
Write-Host "[4/4] Membuat shortcut Desktop..." -ForegroundColor Yellow
$exePath = Join-Path $Root "CrackSentinel.exe"
if (Test-Path $exePath) {
    $ws = New-Object -ComObject WScript.Shell
    $desk = [Environment]::GetFolderPath('Desktop')
    $lnk = $ws.CreateShortcut((Join-Path $desk 'CrackSentinel.lnk'))
    $lnk.TargetPath = $exePath
    $lnk.WorkingDirectory = $Root
    $lnk.IconLocation = "$exePath,0"
    $lnk.Description = "CrackSentinel - Game Malware Guard"
    $lnk.Save()
    Write-Host "      OK: Shortcut Desktop dibuat." -ForegroundColor Green
    Write-Host ""
    Write-Host "Setup selesai! Membuka CrackSentinel..." -ForegroundColor Green
    Start-Process -FilePath $exePath -WorkingDirectory $Root
}
