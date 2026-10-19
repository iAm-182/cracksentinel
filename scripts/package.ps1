# Package CrackSentinel into a distributable zip (Windows).
#
#   scripts\package.ps1 [-Version 1.0.0]
#
# Produces dist\cracksentinel-<version>-windows-amd64.zip containing the
# binary, the detonator context, the built-in YARA rules and the README.
param(
  [string]$Version = ""
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

if ([string]::IsNullOrWhiteSpace($Version)) {
  $Version = (Select-String -Path internal\version\version.go -Pattern 'Version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
}
$Commit = (& git rev-parse --short HEAD 2>$null)
if (-not $Commit) { $Commit = "unknown" }
$Date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$GOOS = "windows"
$GOARCH = "amd64"
$Out = "dist\cracksentinel-$Version-$GOOS-$GOARCH"
$Ldflags = "-X gamecrack-scanner/internal/version.Version=$Version -X gamecrack-scanner/internal/version.Commit=$Commit -X gamecrack-scanner/internal/version.BuildDate=$Date"

Write-Host "==> building scanner.exe $Version ($GOOS/$GOARCH, commit $Commit)"
if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$env:CGO_ENABLED = "0"
& go build -trimpath -ldflags $Ldflags -o "$Out\scanner.exe" ./cmd/scanner
if ($LASTEXITCODE -ne 0) { throw "go build failed" }

Write-Host "==> staging payload"
Copy-Item README.md $Out
if (Test-Path detonator) { Copy-Item -Recurse detonator $Out }
New-Item -ItemType Directory -Force -Path "$Out\yara-rules" | Out-Null
Copy-Item internal\yara\rules\builtin.yar "$Out\yara-rules\"

@(
  "CrackSentinel $Version",
  "commit: $Commit",
  "built:  $Date",
  "go:     $GOOS/$GOARCH"
) | Set-Content -Encoding utf8 "$Out\VERSION.txt"

Get-ChildItem $Out -Recurse -File | ForEach-Object {
  $h = Get-FileHash $_.FullName -Algorithm SHA256
  "$($h.Hash.ToLower())  $($_.FullName.Substring((Resolve-Path $Out).Path.Length + 1))"
} | Set-Content -Encoding ascii "$Out\SHA256SUMS.txt"

$Zip = "dist\cracksentinel-$Version-$GOOS-$GOARCH.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path $Out -DestinationPath $Zip -CompressionLevel Optimal

Write-Host "==> done: $Zip"
Get-Item $Zip | Select-Object Name, Length, LastWriteTime
