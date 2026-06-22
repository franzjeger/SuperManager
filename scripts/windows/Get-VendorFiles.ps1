# Download + hash-verify the upstream files listed in vendor/manifest.toml,
# then extract individual DLLs / EXEs into vendor/ for the MSI build.
#
# SuperManager bundles only the MINIMAL files each VPN backend needs:
#   wireguard.dll  — from wireguard-nt zip (no WireGuard GUI installed)
#   wintun.dll     — from Wintun zip (no separate driver installer)
#   openvpn.exe    — extracted from OpenVPN MSI via msiexec /a (no OpenVPN
#                    GUI installed; just the CLI binary)
#
# Idempotent: files already present with the right hash are left alone.
# CI calls this before build-msi.ps1.
#
# Exit codes:
#   0  - all vendor files present and verified
#   1  - download, hash, or extraction failure

[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'vendor/manifest.toml'),
    [string]$VendorDir    = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'vendor'),
    [switch]$Force        # Re-download even if hash matches
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = 'SilentlyContinue'

if (-not (Test-Path $ManifestPath)) {
    throw "manifest not found at $ManifestPath"
}

# Minimal TOML parser — handles [section] + key = "value" lines.
function ConvertFrom-SimpleToml {
    param([string]$Text)
    $result = @{}
    $section = $null
    foreach ($raw in ($Text -split "(`r`n|`n)")) {
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        if ($line -match '^\[(?<name>[^\]]+)\]$') {
            $section = $Matches['name'].Trim()
            $result[$section] = @{}
            continue
        }
        if ($section -and $line -match '^(?<k>[A-Za-z_][\w-]*)\s*=\s*"(?<v>[^"]*)"\s*(#.*)?$') {
            $result[$section][$Matches['k']] = $Matches['v']
        }
    }
    return $result
}

# Download a URL to a temp file, verify SHA-256, return temp path.
function Get-Verified {
    param([string]$Name, [string]$Url, [string]$ExpectedHash)
    $tmp = [System.IO.Path]::GetTempFileName()
    Write-Host ("  ← {0}" -f $Url)
    try {
        Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing
    } catch {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        throw "[$Name] download failed: $($_.Exception.Message)"
    }
    $actual = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToUpperInvariant()
    $expected = $ExpectedHash.ToUpperInvariant()
    if ($actual -ne $expected) {
        Remove-Item $tmp -Force
        throw "[$Name] HASH MISMATCH`n  expected: $expected`n  actual:   $actual`n  Re-pin vendor/manifest.toml."
    }
    Write-Host ("  ✓ SHA-256 verified ({0} bytes)" -f (Get-Item $tmp).Length)
    return $tmp
}

# Extract a single file from a zip archive to a destination path.
function Expand-ZipEntry {
    param([string]$ZipPath, [string]$EntryPath, [string]$Dest)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entry = $zip.Entries | Where-Object { $_.FullName -eq $EntryPath }
        if (-not $entry) {
            throw "Entry '$EntryPath' not found in zip"
        }
        $stream = $entry.Open()
        $out    = [System.IO.File]::Create($Dest)
        try { $stream.CopyTo($out) } finally { $out.Close(); $stream.Close() }
    } finally { $zip.Dispose() }
}

if (-not (Test-Path $VendorDir)) {
    New-Item -ItemType Directory -Path $VendorDir | Out-Null
}

$manifest = ConvertFrom-SimpleToml -Text (Get-Content $ManifestPath -Raw)
$failed   = $false

foreach ($name in $manifest.Keys | Sort-Object) {
    $entry = $manifest[$name]
    if (-not $entry.ContainsKey('output')) { continue }  # skip comment-only sections
    $dest = Join-Path $VendorDir $entry['output']

    # Check if already present and correct.
    if (-not $Force -and (Test-Path $dest)) {
        if ($entry.ContainsKey('sha256')) {
            $actual   = (Get-FileHash $dest -Algorithm SHA256).Hash.ToUpperInvariant()
            $expected = $entry['sha256'].ToUpperInvariant()
            if ($actual -eq $expected) {
                Write-Host ("[{0}] {1} — cached, hash OK" -f $name, $entry['output'])
                continue
            }
            Write-Host ("[{0}] hash drifted, re-fetching" -f $name)
        } else {
            Write-Host ("[{0}] {1} — cached" -f $name, $entry['output'])
            continue
        }
    }

    Write-Host ("[{0}] fetching {1}..." -f $name, $entry['output'])
    try {
        # --- ZIP source: download zip, extract single entry ---
        if ($entry.ContainsKey('zip_path')) {
            $tmp = Get-Verified -Name $name -Url $entry['url'] -ExpectedHash $entry['sha256']
            Expand-ZipEntry -ZipPath $tmp -EntryPath $entry['zip_path'] -Dest $dest
            Remove-Item $tmp -Force
            Write-Host ("  → extracted {0}" -f $dest)
        }
        # --- MSI source: download MSI, admin-install to temp, copy exe ---
        elseif ($entry.ContainsKey('msi_extract_path')) {
            $msiTmp  = Get-Verified -Name $name -Url $entry['url'] -ExpectedHash $entry['sha256']
            $exDir   = Join-Path $env:TEMP "supermgr-vendor-$name"
            New-Item -ItemType Directory -Path $exDir -Force | Out-Null
            Write-Host "  → extracting MSI (msiexec /a)…"
            $proc = Start-Process msiexec.exe -ArgumentList "/a `"$msiTmp`" /qn TARGETDIR=`"$exDir`"" -Wait -PassThru
            if ($proc.ExitCode -ne 0) { throw "msiexec failed (exit $($proc.ExitCode))" }
            $src = Join-Path $exDir $entry['msi_extract_path']
            if (-not (Test-Path $src)) { throw "msiexec ran but '$src' not found in extracted tree" }
            Copy-Item $src $dest -Force
            Remove-Item $exDir -Recurse -Force
            Remove-Item $msiTmp -Force
            Write-Host ("  → extracted {0}" -f $dest)
        }
        # --- Direct download (no extraction) ---
        else {
            $tmp = Get-Verified -Name $name -Url $entry['url'] -ExpectedHash $entry['sha256']
            Move-Item $tmp $dest -Force
        }
    } catch {
        Write-Warning $_.Exception.Message
        $failed = $true
        continue
    }
    Write-Host ("[{0}] done → {1}" -f $name, (Get-Item $dest).Length) -ForegroundColor Green
}

if ($failed) {
    Write-Host ""
    Write-Host "One or more vendor files failed. Update vendor/manifest.toml if upstream legitimately changed." -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "All vendor files ready." -ForegroundColor Green
