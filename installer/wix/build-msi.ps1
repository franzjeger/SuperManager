# Build the SuperManager MSI (and optionally the Burn bundle EXE).
#
# Prerequisites:
#   1. .NET SDK 8+ (https://dotnet.microsoft.com/download)
#   2. WiX Toolset v5 — installed once per machine:
#        dotnet tool install --global wix --version 5.0.2
#        wix extension add WixToolset.UI.wixext/5.0.2 --global
#        wix extension add WixToolset.Util.wixext/5.0.2 --global
#        wix extension add WixToolset.BootstrapperApplications.wixext/5.0.2 --global   # -Bundle only
#   3. Release builds of supermgrd-win.exe, supermgr-win.exe,
#      supermgr-mcp.exe. The script invokes `cargo build --release` for
#      you unless you pass `-SkipBuild`.
#   4. (Optional) vendor\openfortivpn.exe — when present, the FortiClient
#      SSL VPN client is embedded directly into the MSI. Absent → the MSI
#      still builds; the FortiClient backend surfaces a typed missing-
#      dependency error at connect time.
#   5. (Optional, -Bundle only) vendor\wireguard-installer.msi and
#      vendor\openvpn-installer.msi from the upstream WireGuard for
#      Windows and OpenVPN Community releases; plus installer\wix\license.rtf
#      shown by the Burn welcome page.
#
# Outputs:
#   installer\wix\SuperManager.msi          (bare MSI, always built)
#   installer\wix\SuperManager-Setup.exe    (Burn bootstrapper, with -Bundle)

[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$Bundle
)

$ErrorActionPreference = "Stop"

$repoRoot   = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$targetDir  = Join-Path $repoRoot "target\release"
$vendorDir  = Join-Path $repoRoot "vendor"
$wxsMain    = Join-Path $PSScriptRoot "supermanager.wxs"
$wxsBundle  = Join-Path $PSScriptRoot "bundle.wxs"
$outputMsi  = Join-Path $PSScriptRoot "SuperManager.msi"
$outputExe  = Join-Path $PSScriptRoot "SuperManager-Setup.exe"

# Locate wix.exe — installed by `dotnet tool install --global wix`.
$wix = "$env:USERPROFILE\.dotnet\tools\wix.exe"
if (-not (Test-Path $wix)) {
    $wixCmd = Get-Command wix.exe -ErrorAction SilentlyContinue
    if ($wixCmd) {
        $wix = $wixCmd.Source
    } else {
        throw "WiX v5 not found. Install with: dotnet tool install --global wix --version 5.0.2"
    }
}

# 1. Build the binaries unless told otherwise.
if (-not $SkipBuild) {
    Push-Location $repoRoot
    try {
        Write-Host "Building release binaries..."
        cargo build --release -p supermgrd-win -p supermgr-win -p supermgr-mcp
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}

foreach ($exe in @("supermgrd-win.exe", "supermgr-win.exe", "supermgr-mcp.exe")) {
    $path = Join-Path $targetDir $exe
    if (-not (Test-Path $path)) {
        throw "Missing binary $path. Run without -SkipBuild or build the workspace first."
    }
}

# 2. Decide whether to embed openfortivpn.
#
# Two paths:
#   a) `vendor/openfortivpn.exe` - a single, statically-linked binary the
#      user dropped in by hand. Embedded directly into bin\.
#   b) `vendor/openfortivpn-bundle/` - the Cygwin-built closure
#      (openfortivpn.exe + pppd.exe + cyg*.dll). Embedded into
#      bin\openfortivpn-bundle\. CI populates this via
#      `scripts/windows/Stage-Openfortivpn.ps1` after installing the
#      Cygwin `openfortivpn` package.
$openfortivpnPath   = Join-Path $vendorDir "openfortivpn.exe"
$openfortivpnBundle = Join-Path $vendorDir "openfortivpn-bundle"

$includeOpenfortivpn       = "no"
$includeOpenfortivpnBundle = "no"

if (Test-Path $openfortivpnPath) {
    Write-Host "Found vendor\openfortivpn.exe -- embedding into the MSI bin\."
    $includeOpenfortivpn = "yes"
}
if (Test-Path $openfortivpnBundle) {
    $count = (Get-ChildItem $openfortivpnBundle).Count
    Write-Host "Found vendor\openfortivpn-bundle\ ($count files) -- embedding into bin\openfortivpn-bundle\."
    $includeOpenfortivpnBundle = "yes"
}
if (($includeOpenfortivpn -eq "no") -and ($includeOpenfortivpnBundle -eq "no")) {
    Write-Host "openfortivpn not staged -- MSI will ship without FortiGate SSL VPN support."
    Write-Host "(Run scripts/windows/Stage-Openfortivpn.ps1 after a Cygwin install, or drop a static .exe at vendor/openfortivpn.exe.)"
}

Push-Location $repoRoot
try {
    # 3. Build the bare MSI.
    Write-Host "Compiling SuperManager.msi..."
    Remove-Item $outputMsi -ErrorAction SilentlyContinue
    & $wix build `
        -arch x64 `
        -d "TargetDir=$targetDir" `
        -d "IncludeOpenfortivpn=$includeOpenfortivpn" `
        -d "IncludeOpenfortivpnBundle=$includeOpenfortivpnBundle" `
        -ext WixToolset.UI.wixext `
        -ext WixToolset.Util.wixext `
        -out $outputMsi `
        $wxsMain
    if ($LASTEXITCODE -ne 0) { throw "wix build (main) failed" }

    # 4. Optional Burn bundle.
    if ($Bundle) {
        foreach ($f in @("wireguard-installer.msi", "openvpn-installer.msi")) {
            $p = Join-Path $vendorDir $f
            if (-not (Test-Path $p)) {
                throw "Bundle build requires $p. See vendor\README.md for the download URL."
            }
        }
        $licenseRtf = Join-Path $PSScriptRoot "license.rtf"
        if (-not (Test-Path $licenseRtf)) {
            throw "Bundle build requires installer\wix\license.rtf (the bootstrapper's RTF license file)."
        }

        Write-Host "Compiling SuperManager-Setup.exe (Burn bundle)..."
        Remove-Item $outputExe -ErrorAction SilentlyContinue
        # The bal extension was renamed in WiX v5 — the package
        # `WixToolset.BootstrapperApplications.wixext` is the same
        # thing the v4 docs still refer to as "bal".
        & $wix build `
            -arch x64 `
            -ext WixToolset.BootstrapperApplications.wixext `
            -out $outputExe `
            $wxsBundle
        if ($LASTEXITCODE -ne 0) { throw "wix build (bundle) failed" }
    }
} finally {
    Pop-Location
}

Write-Host "`nBuilt $outputMsi"
Get-Item $outputMsi | Format-Table Name, Length, LastWriteTime -AutoSize
if ($Bundle) {
    Write-Host "Built $outputExe"
    Get-Item $outputExe | Format-Table Name, Length, LastWriteTime -AutoSize
}
