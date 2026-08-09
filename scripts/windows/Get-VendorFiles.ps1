# Download + hash-verify the upstream installers listed in
# `vendor/manifest.toml`, staging them under `vendor/` for the Burn
# bundle build.
#
# Idempotent: a file already present with the right hash is left
# alone; a file whose hash drifted is re-downloaded. CI calls this
# before `build-msi.ps1 -Bundle`.
#
# Exit codes:
#   0  - everything pinned matches; vendor/ is populated
#   1  - manifest parse / network / hash-mismatch failure

[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'vendor/manifest.toml'),
    [string]$VendorDir    = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'vendor')
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = 'SilentlyContinue'

if (-not (Test-Path $ManifestPath)) {
    throw "manifest not found at $ManifestPath"
}

# Minimal TOML parser - we only need [section] headers + key="value"
# lines. PowerShell's built-in ConvertFrom-Toml didn't ship until 7.4
# so doing it by hand keeps the script runnable on the older runners.
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

$manifest = ConvertFrom-SimpleToml -Text (Get-Content $ManifestPath -Raw)
if (-not (Test-Path $VendorDir)) {
    New-Item -ItemType Directory -Path $VendorDir | Out-Null
}

$failed = $false
foreach ($name in $manifest.Keys | Sort-Object) {
    $entry = $manifest[$name]
    $required = @('url', 'sha256', 'output')
    $missing = $required | Where-Object { -not $entry.ContainsKey($_) }
    if ($missing) {
        Write-Warning "[$name] missing keys: $($missing -join ', ') - skipping"
        continue
    }
    $expectedHash = $entry['sha256'].ToUpperInvariant()
    $dest = Join-Path $VendorDir $entry['output']

    if (Test-Path $dest) {
        $actual = (Get-FileHash $dest -Algorithm SHA256).Hash
        if ($actual -eq $expectedHash) {
            Write-Host ("[{0}] cached at {1} (hash matches)" -f $name, $entry['output'])
            continue
        }
        Write-Host ("[{0}] cached file hash drifted; re-downloading" -f $name)
        Remove-Item $dest -Force
    }

    Write-Host ("[{0}] downloading {1}" -f $name, $entry['url'])
    try {
        Invoke-WebRequest -Uri $entry['url'] -OutFile $dest -UseBasicParsing
    } catch {
        Write-Warning ("[{0}] download failed: {1}" -f $name, $_.Exception.Message)
        $failed = $true
        continue
    }

    $actual = (Get-FileHash $dest -Algorithm SHA256).Hash
    if ($actual -ne $expectedHash) {
        Write-Warning ("[{0}] HASH MISMATCH at {1}" -f $name, $dest)
        Write-Warning ("       expected: {0}" -f $expectedHash)
        Write-Warning ("       actual:   {0}" -f $actual)
        Remove-Item $dest -Force
        $failed = $true
        continue
    }
    Write-Host ("[{0}] verified - {1} bytes" -f $name, (Get-Item $dest).Length)
}

if ($failed) {
    Write-Host ""
    Write-Host "One or more vendor files failed verification. Re-pin the manifest with the actual upstream hash if the upstream legitimately changed." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "All vendor files verified." -ForegroundColor Green
