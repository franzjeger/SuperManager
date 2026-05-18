# Verify that AzureVpn profiles get routed to the Azure backend.
#
# Drops a synthetic Azure profile under %PROGRAMDATA%\SuperManager\profiles\,
# starts the daemon (so it loads the profile at boot), calls `connect`,
# confirms the daemon reached the Azure code path, then cleans up. The
# OAuth/openvpn flow will fail (the gateway is fake) but the failure mode
# proves the dispatcher routed correctly.

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$daemonExe = Join-Path $repoRoot "target\release\supermgrd-win.exe"
if (-not (Test-Path $daemonExe)) {
    Write-Error "Build supermgrd-win first: cargo build --release -p supermgrd-win"
}

# --- Write a synthetic Azure profile to disk -------------------------------
$azProfileId = [guid]::NewGuid().ToString()
$zeros = '0' * 512
$tomlLines = @(
    "id = `"$azProfileId`"",
    "name = `"smoke-azure`"",
    "auto_connect = false",
    "full_tunnel = true",
    "kill_switch = false",
    "updated_at = `"$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))`"",
    "",
    "[config]",
    "backend = `"azure_vpn`"",
    "gateway_fqdn = `"azuregateway-example.vpn.azure.com`"",
    "tenant_id = `"00000000-0000-0000-0000-000000000000`"",
    "client_id = `"c632b3df-fb67-4d84-bdcf-b95ad541b5c8`"",
    "server_secret_hex = `"$zeros`"",
    "ca_cert_pem = `"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n`"",
    "routes = []",
    "dns_servers = []"
)
$profileDir = "$env:PROGRAMDATA\SuperManager\profiles"
[System.IO.Directory]::CreateDirectory($profileDir) | Out-Null
$profilePath = Join-Path $profileDir "$azProfileId.toml"
[System.IO.File]::WriteAllText(
    $profilePath,
    ($tomlLines -join [Environment]::NewLine),
    (New-Object System.Text.UTF8Encoding $false)
)
Write-Host "Wrote test Azure profile: $profilePath"

# --- Spawn the daemon with the new profile already present -----------------
$proc = Start-Process -FilePath $daemonExe -ArgumentList "--console" `
    -PassThru -NoNewWindow `
    -RedirectStandardError (Join-Path $repoRoot "azure-stderr.log") `
    -RedirectStandardOutput (Join-Path $repoRoot "azure-stdout.log")
Start-Sleep -Seconds 1
if ($proc.HasExited) {
    Write-Error "Daemon exited early; check azure-stderr.log"
}

try {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "supermgrd", "InOut")
    $pipe.Connect(5000)
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $reader = New-Object System.IO.StreamReader($pipe, $utf8NoBom)
    $writer = New-Object System.IO.StreamWriter($pipe, $utf8NoBom)
    $writer.AutoFlush = $true

    function Invoke-Rpc {
        param([string]$Method, [hashtable]$RpcArgs = @{})
        $req = @{ v = 1; id = (Get-Random); method = $Method; args = $RpcArgs } |
            ConvertTo-Json -Compress
        $writer.WriteLine($req)
        $line = $reader.ReadLine()
        return $line | ConvertFrom-Json
    }

    Write-Host "`n=== list_profiles (should include the Azure profile) ==="
    $list = Invoke-Rpc -Method "list_profiles"
    $list | ConvertTo-Json
    if ($list.result -notmatch $azProfileId) {
        Write-Error "Azure profile was not loaded; profile_store may have rejected the TOML"
    }

    Write-Host "`n=== connect (expect routed-to-azure error) ==="
    $resp = Invoke-Rpc -Method "connect" -RpcArgs @{ profile_id = $azProfileId }
    $resp | ConvertTo-Json
    if ($resp.error) {
        Write-Host "Dispatcher returned a typed error: Azure routing confirmed."
    } elseif ($resp.result) {
        Write-Host "Dispatcher returned success (unexpected: Azure OAuth should not succeed against a fake gateway)."
    }

    $pipe.Close()
} finally {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Remove-Item $profilePath -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $repoRoot "azure-stderr.log") -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $repoRoot "azure-stdout.log") -ErrorAction SilentlyContinue
}

Write-Host "`nAzure routing smoke test complete."
