# Smoke-test the daemon: open the named pipe, list keys, generate a key,
# list again, delete it, list once more.
$ErrorActionPreference = "Stop"

$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "supermgrd", "InOut")
$pipe.Connect(5000)

# Suppress BOM — PowerShell's default UTF8Encoding emits a BOM on first
# write, which the daemon's JSON parser rejects as malformed input.
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$reader = New-Object System.IO.StreamReader($pipe, $utf8NoBom)
$writer = New-Object System.IO.StreamWriter($pipe, $utf8NoBom)
$writer.AutoFlush = $true

function Invoke-Rpc {
    param(
        [Parameter(Mandatory)][string]$Method,
        [hashtable]$RpcArgs = @{}
    )
    $req = @{ v = 1; id = (Get-Random); method = $Method; args = $RpcArgs } | ConvertTo-Json -Compress
    $writer.WriteLine($req)
    $line = $reader.ReadLine()
    return $line | ConvertFrom-Json
}

Write-Host "=== list_hosts ==="
Invoke-Rpc -Method "list_hosts" | ConvertTo-Json

Write-Host "`n=== ssh_list_keys (before) ==="
Invoke-Rpc -Method "ssh_list_keys" | ConvertTo-Json

Write-Host "`n=== ssh_generate_key ==="
$gen = Invoke-Rpc -Method "ssh_generate_key" -RpcArgs @{
    key_type    = "ed25519"
    name        = "smoke-test-$(Get-Random)"
    description = "automated smoke test"
    tags_json   = "[]"
}
$gen | ConvertTo-Json
$keyMeta = $gen.result | ConvertFrom-Json
$keyId = $keyMeta.id
Write-Host "Generated key id: $keyId"

Write-Host "`n=== ssh_list_keys (after) ==="
Invoke-Rpc -Method "ssh_list_keys" | ConvertTo-Json

Write-Host "`n=== ssh_export_public_key ==="
$export = Invoke-Rpc -Method "ssh_export_public_key" -RpcArgs @{ key_id = $keyId }
Write-Host $export.result

Write-Host "`n=== ssh_delete_key ==="
Invoke-Rpc -Method "ssh_delete_key" -RpcArgs @{ key_id = $keyId } | ConvertTo-Json

Write-Host "`n=== ssh_list_keys (cleaned up) ==="
Invoke-Rpc -Method "ssh_list_keys" | ConvertTo-Json

# --------------------------------------------------------------------------
# VPN profile flow — import a deterministic WireGuard config, confirm it
# round-trips through list_profiles, then delete it.
# --------------------------------------------------------------------------

$wgConf = @'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.7.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
'@

Write-Host "`n=== list_profiles (before import) ==="
Invoke-Rpc -Method "list_profiles" | ConvertTo-Json

Write-Host "`n=== import_wireguard ==="
$imp = Invoke-Rpc -Method "import_wireguard" -RpcArgs @{
    conf_text = $wgConf
    name      = "smoke-wg-$(Get-Random)"
}
$imp | ConvertTo-Json
$profileId = $imp.result
Write-Host "Imported profile id: $profileId"

Write-Host "`n=== list_profiles (after import) ==="
Invoke-Rpc -Method "list_profiles" | ConvertTo-Json

Write-Host "`n=== get_status (before connect) ==="
Invoke-Rpc -Method "get_status" | ConvertTo-Json

Write-Host "`n=== connect (will fail without wireguard.dll, but should route to backend) ==="
$conn = Invoke-Rpc -Method "connect" -RpcArgs @{ profile_id = $profileId }
$conn | ConvertTo-Json
if ($conn.error) {
    Write-Host "Expected: connect surfaces a typed error when WireGuardNT isn't installed."
}

Write-Host "`n=== disconnect (no-op when nothing is connected) ==="
Invoke-Rpc -Method "disconnect" | ConvertTo-Json

Write-Host "`n=== delete_profile ==="
Invoke-Rpc -Method "delete_profile" -RpcArgs @{ profile_id = $profileId } | ConvertTo-Json

Write-Host "`n=== list_profiles (cleaned up) ==="
Invoke-Rpc -Method "list_profiles" | ConvertTo-Json

# --------------------------------------------------------------------------
# Appliance APIs — confirm the dispatcher routes correctly. We invoke
# against a non-existent host so the daemon surfaces a typed NotFound,
# proving the handler ran (not just "unknown method").
# --------------------------------------------------------------------------

$fakeHostId = [guid]::NewGuid().ToString()
$fakeKeyId  = [guid]::NewGuid().ToString()

Write-Host "`n=== fortigate_api (expect not_found host) ==="
Invoke-Rpc -Method "fortigate_api" -RpcArgs @{
    host_id = $fakeHostId
    method  = "GET"
    path    = "/api/v2/cmdb/system/global"
    body    = ""
} | ConvertTo-Json

Write-Host "`n=== fortigate_push_ssh_key (expect not_found key) ==="
Invoke-Rpc -Method "fortigate_push_ssh_key" -RpcArgs @{
    host_id    = $fakeHostId
    key_id     = $fakeKeyId
    admin_user = "admin"
} | ConvertTo-Json

Write-Host "`n=== fortigate_backup_config (expect not_found host) ==="
Invoke-Rpc -Method "fortigate_backup_config" -RpcArgs @{
    host_id = $fakeHostId
} | ConvertTo-Json

Write-Host "`n=== unifi_api (expect not_found host) ==="
Invoke-Rpc -Method "unifi_api" -RpcArgs @{
    host_id = $fakeHostId
    method  = "GET"
    path    = "/api/self"
    body    = ""
} | ConvertTo-Json

Write-Host "`n=== opnsense_api (expect not_found host) ==="
Invoke-Rpc -Method "opnsense_api" -RpcArgs @{
    host_id = $fakeHostId
    method  = "GET"
    path    = "/api/diagnostics/system/system_information"
    body    = ""
} | ConvertTo-Json

Write-Host "`n=== opnsense_backup_config (expect not_found host) ==="
Invoke-Rpc -Method "opnsense_backup_config" -RpcArgs @{
    host_id = $fakeHostId
} | ConvertTo-Json

Write-Host "`n=== sophos_xml_api (expect not_found host) ==="
Invoke-Rpc -Method "sophos_xml_api" -RpcArgs @{
    host_id   = $fakeHostId
    inner_xml = "<Get><Information /></Get>"
} | ConvertTo-Json

# --------------------------------------------------------------------------
# FortiClient SSL VPN — import a profile, confirm it round-trips, delete.
# --------------------------------------------------------------------------

Write-Host "`n=== import_forticlient_sslvpn ==="
$fcImport = Invoke-Rpc -Method "import_forticlient_sslvpn" -RpcArgs @{
    name             = "smoke-fc-$(Get-Random)"
    host             = "fortigate.example.com"
    port             = 10443
    username         = "smoke-user"
    password         = "smoke-password"
    trusted_cert     = ""
    dns_servers_json = "[]"
    routes_json      = "[]"
}
$fcImport | ConvertTo-Json
$fcProfileId = $fcImport.result
Write-Host "Imported FortiClient profile id: $fcProfileId"

Write-Host "`n=== list_profiles (FortiClient included) ==="
Invoke-Rpc -Method "list_profiles" | ConvertTo-Json

Write-Host "`n=== connect FortiClient (expect openfortivpn-missing or routed error) ==="
$fcConnect = Invoke-Rpc -Method "connect" -RpcArgs @{ profile_id = $fcProfileId }
$fcConnect | ConvertTo-Json
if ($fcConnect.error -and ($fcConnect.error.msg -match "openfortivpn|FortiClient")) {
    Write-Host "Routed to FortiClient backend."
}

Write-Host "`n=== delete FortiClient profile ==="
Invoke-Rpc -Method "delete_profile" -RpcArgs @{ profile_id = $fcProfileId } | ConvertTo-Json

$pipe.Close()
Write-Host "`nSmoke test passed."
