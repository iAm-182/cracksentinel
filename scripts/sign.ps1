# Prepare CrackSentinel for release signing.
#
#   scripts\sign.ps1 -File dist\cracksentinel-1.3.0-windows-amd64.zip
#
# WHY SIGNING MATTERS HERE
#
# A malware scanner is, to a machine learning classifier, an information
# stealer: it embeds the names of the APIs it looks for, the credential
# targets and the C2 patterns. The indicators are obfuscated in the
# shipped binary, but an unsigned binary still gets the benefit of the
# doubt that a signed one gets. Windows Defender and SmartScreen treat a
# valid publisher signature as an identity claim, and a machine learning
# verdict on an unknown unsigned binary is exactly the case where they
# get it wrong.
#
# Signing removes the question entirely. It is the standard answer and it
# is the one every security vendor uses for their own tools.
#
# Two options:
#
#   1. A code signing certificate (OV or EV). Sign with a PFX:
#        scripts\sign.ps1 -File ... -PfxFile cert.pfx -PfxPassword $env:PFX_PASSWORD
#
#   2. Azure Trusted Signing (a cloud signing service, much cheaper than
#      a certificate, no key to steal). Sign with the Azure Sign CLI:
#        scripts\sign.ps1 -File ... -TrustedSigning -AccountUrl <url> \
#            -TenantId <tenant> -CertificateProfileName <profile>
#
# Verify the result:
#        Get-AuthenticodeSignature .\scanner.exe | Format-List

param(
  [Parameter(Mandatory = $true)][string]$File,
  [string]$PfxFile = "",
  [string]$PfxPassword = "",
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [switch]$TrustedSigning,
  [string]$AccountUrl = "",
  [string]$TenantId = "",
  [string]$CertificateProfileName = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $File)) {
  throw "file not found: $File"
}

# Locate signtool. It ships with the Windows SDK.
$signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
  Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) {
  $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($cmd) { $signtool = $cmd }
}
if (-not $signtool) {
  throw "signtool.exe not found. Install the Windows SDK, or use -TrustedSigning with the Azure Sign CLI instead."
}
$signtool = $signtool.FullName
if (-not $signtool) { $signtool = "signtool.exe" }

Write-Host "==> signing $File"
Write-Host "    signtool: $signtool"

if ($TrustedSigning) {
  if (-not $AccountUrl -or -not $TenantId -or -not $CertificateProfileName) {
    throw "-TrustedSigning needs -AccountUrl, -TenantId and -CertificateProfileName"
  }
  $az = Get-Command az -ErrorAction SilentlyContinue
  if (-not $az) {
    throw "the Azure CLI is required for -TrustedSigning (az trust sign --help)"
  }
  & az trust sign --account $AccountUrl --tenant $TenantId --certificate-profile $CertificateProfileName `
    --timestamp-uri $TimestampUrl --file $File
  if ($LASTEXITCODE -ne 0) { throw "azure trusted signing failed" }
}
else {
  if (-not $PfxFile) {
    throw "provide -PfxFile <cert.pfx> (with -PfxPassword) or use -TrustedSigning"
  }
  & $signtool sign /fd SHA256 /tr $TimestampUrl /td SHA256 /f $PfxFile /p $PfxPassword $File
  if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
}

$sig = Get-AuthenticodeSignature $File
Write-Host "==> result: $($sig.Status)"
if ($sig.SignerCertificate) {
  Write-Host "    subject: $($sig.SignerCertificate.Subject)"
  Write-Host "    expires: $($sig.SignerCertificate.NotAfter)"
}
if ($sig.Status -ne "Valid") {
  throw "the signature is not valid: $($sig.Status)"
}
Write-Host "==> signed and verified"
