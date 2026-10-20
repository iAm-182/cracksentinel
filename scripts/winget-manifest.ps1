# Generate the winget manifest for a release.
#
#   scripts\winget-manifest.ps1 -Version 1.3.0
#
# winget is the longest-term answer to the antivirus problem: a package
# manager entry has a KNOWN hash, it is reviewed before it ships, and
# SmartScreen and Defender build a reputation for it over time. A binary
# released as a random zip in a browser download has neither.
#
# The manifest is written to packaging/winget/cracksentinel.yaml with the
# real asset URL and SHA256 filled in. To publish it, open a pull request
# against microsoft/winget-pkgs.

param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Output = "packaging\winget\cracksentinel.yaml",
  [string]$Template = "packaging\winget\cracksentinel.yaml"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$asset = "cracksentinel-$Version-windows-amd64.zip"
$url = "https://github.com/iAm-182/cracksentinel/releases/download/v$Version/$asset"

$tmp = Join-Path $env:TEMP "winget-$Version"
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

Write-Host "==> downloading $url"
Invoke-WebRequest -Uri $url -OutFile (Join-Path $tmp $asset) -UseBasicParsing

$sha = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
Write-Host "    sha256: $sha"

$content = @"
PackageIdentifier: iAm-182.CrackSentinel
PackageVersion: $Version
Publisher: iAm-182
PublisherUrl: https://github.com/iAm-182/cracksentinel
PackageUrl: https://github.com/iAm-182/cracksentinel
License: MIT
LicenseUrl: https://github.com/iAm-182/cracksentinel/blob/main/LICENSE
ShortDescription: Defensive malware scanner for cracked-game folders
Description: |-
  CrackSentinel is a defensive malware scanner for cracked-game folders.
  It walks a folder, scores every file and tells you which ones carry a
  payload: keyloggers, credential stealers, miners, droppers and RATs that
  ship alongside a crack.

  It reads only. It never runs, mounts or installs the files it inspects.
  The only layer that executes anything is the optional behavioural
  detonation sandbox, which runs the sample inside a container with no
  network access.

  Optional extras, all auto-detected: yara, upx, 7z, docker.
PackageTags:
  - security
  - antivirus
  - malware
  - defender
ReleaseNotesUrl: https://github.com/iAm-182/cracksentinel/releases/tag/v$Version
InstallerType: zip
InstallerUrl: $url
InstallerSha256: $sha
NestedInstallerType: portable
NestedInstallerFiles: relative\cracksentinel-$Version-windows-amd64\scanner.exe
FileExtensions:
  - exe
ManifestType: installer
"@

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output) | Out-Null
[System.IO.File]::WriteAllText($Output, $content)
Write-Host "==> wrote $Output"
Write-Host "    next: open a pull request against microsoft/winget-pkgs"
