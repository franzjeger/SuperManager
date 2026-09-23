# End-to-end VPN test against the installed SuperManager service.
#
# Destructive: creates adapters, a WireGuard tunnel service and firewall
# rules, so it only runs on a disposable GitHub Actions runner. It is
# called by test-installer.ps1 once the bundle is installed.
#
# Real servers run on this machine — a WireGuard tunnel through WireGuard
# for Windows, an OpenVPN server through the bundled openvpn.exe with a
# throwaway PKI — and the service is driven over its named pipe the way the
# app drives it: import, connect, switch, disconnect, cancel, stop. Each
# step is checked against what Windows and the server see (adapters,
# addresses, routes, DNS, handshakes, bytes received, processes), not only
# against what the service says about itself.
#
# Both ends share one IP stack, so a reply can never come back through a
# tunnel: a packet for the far end's address is delivered locally. Traffic
# is proven one way instead — the server counts the bytes it decrypted.
[CmdletBinding()]
param([string]$LogDir = (Join-Path $env:RUNNER_TEMP 'supermanager-installer-test\vpn'))
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Run only on a disposable GitHub Actions runner.' }

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$work = Join-Path $env:RUNNER_TEMP 'supermanager-vpn-e2e'
New-Item -ItemType Directory -Path $work -Force | Out-Null

$wgDir = Join-Path $env:ProgramFiles 'WireGuard'
$wg = Join-Path $wgDir 'wg.exe'
$wireguard = Join-Path $wgDir 'wireguard.exe'
$ovpnBin = Join-Path $env:ProgramFiles 'OpenVPN\bin'
$openvpn = Join-Path $ovpnBin 'openvpn.exe'
$tapctl = Join-Path $ovpnBin 'tapctl.exe'

$wgServerTunnel = 'smtestsrv'
$wgServerPort = 51820
$ovpnServerAdapter = 'SMTestOvpnSrv'
$ovpnSpareAdapter = 'SMTestOvpnCli'
$ovpnServerPort = 1194
$firewallRule = 'SuperManager VPN end-to-end test'

# ---------------------------------------------------------------------------
# The service's pipe
# ---------------------------------------------------------------------------

class RpcException : System.Exception {
    [string]$Method
    [string]$Kind
    RpcException([string]$method, [string]$kind, [string]$message) : base("$method failed ($kind): $message") {
        $this.Method = $method
        $this.Kind = $kind
    }
}

$script:pipe = $null
$script:reader = $null
$script:writer = $null
$script:nextId = 1000

function Close-Service {
    if ($script:pipe) { $script:pipe.Dispose() }
    $script:pipe = $null
}

function Open-Service {
    Close-Service
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'supermgrd', [IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(15000)
    $encoding = [Text.UTF8Encoding]::new($false)
    $script:reader = [IO.StreamReader]::new($pipe, $encoding)
    $script:writer = [IO.StreamWriter]::new($pipe, $encoding)
    $script:writer.AutoFlush = $true
    $script:pipe = $pipe
}

# Call a method and return its result; a service error becomes an RpcException.
function Invoke-Rpc([string]$Method, [hashtable]$Arguments = @{}, [int]$TimeoutSeconds = 30) {
    if (-not $script:pipe -or -not $script:pipe.IsConnected) { Open-Service }
    $id = ++$script:nextId
    $request = @{ v = 1; id = $id; method = $Method; args = $Arguments } | ConvertTo-Json -Compress -Depth 10
    $script:writer.WriteLine($request)
    $read = $script:reader.ReadLineAsync()
    if (-not $read.Wait($TimeoutSeconds * 1000)) {
        Close-Service
        throw "${Method}: no answer within $TimeoutSeconds s"
    }
    if ($null -eq $read.Result) {
        Close-Service
        throw "${Method}: the service closed the pipe"
    }
    $reply = $read.Result | ConvertFrom-Json
    if ($reply.id -ne $id) { throw "${Method}: answered request $($reply.id), expected $id" }
    if ($reply.error) { throw [RpcException]::new($Method, $reply.error.kind, $reply.error.msg) }
    return $reply.result
}

function Get-VpnStatus { Invoke-Rpc 'get_status' | ConvertFrom-Json }

function Format-Status($Status) { $Status | ConvertTo-Json -Compress }

# Poll until the tunnel is in one of $States; return that status.
function Wait-VpnState([string[]]$States, [int]$TimeoutSeconds = 60) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $status = Get-VpnStatus
        if ($status.state -in $States) { return $status }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Still '$($status.state)' after $TimeoutSeconds s, waiting for $($States -join '/'): $(Format-Status $status)"
}

# Connect a profile and wait for the tunnel; fail with the service's reason.
function Connect-Profile([string]$ProfileId, [int]$TimeoutSeconds = 60) {
    $started = Invoke-Rpc 'connect' @{ profile_id = $ProfileId }
    if ($started.status -ne 'connecting') { throw "connect answered $($started | ConvertTo-Json -Compress)" }
    $status = Wait-VpnState @('connected', 'error') $TimeoutSeconds
    if ($status.state -ne 'connected') { throw "Connect failed: $($status.message)" }
    if ($status.profile_id -ne $ProfileId) { throw "Connected the wrong profile: $(Format-Status $status)" }
    return $status
}

function Disconnect-Vpn {
    Invoke-Rpc 'disconnect' | Out-Null
    Wait-VpnState @('disconnected') 30 | Out-Null
}

# ---------------------------------------------------------------------------
# What Windows sees
# ---------------------------------------------------------------------------

function Wait-Until([scriptblock]$Condition, [string]$What, [int]$TimeoutSeconds = 20) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out after $TimeoutSeconds s waiting for: $What"
}

function Test-Adapter([string]$Name) {
    $null -ne (Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue)
}

function Assert-AdapterGone([string]$Name) {
    Wait-Until { -not (Test-Adapter $Name) } "adapter $Name to be removed"
}

# The service's WireGuard adapter for a profile: "wg" and the id's first
# eight hex digits (Profile::wg_interface_name).
function Get-WgAdapterName([string]$ProfileId) {
    'wg' + $ProfileId.Replace('-', '').Substring(0, 8)
}

# latest-handshakes / transfer for the server's one peer, from wg.exe.
function Get-WgPeerField([string]$Field) {
    $lines = @(& $wg show $wgServerTunnel $Field 2>$null)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0) { return $null }
    , ($lines[0] -split "`t")
}

# The OpenVPN clients the service started: their configs live in its
# private ovpn folder. The test's own server is not one of them.
function Get-OpenVpnClients {
    Get-CimInstance Win32_Process -Filter "Name = 'openvpn.exe'" |
        Where-Object { $_.CommandLine -like '*\SuperManager\ovpn\*' }
}

# wireguard.exe is a GUI program: with no console to write to, it reports
# an error in a message box, which on a runner nobody can close. Captured
# output gives it somewhere to write, and makes PowerShell wait for it.
function Invoke-WireGuard {
    $output = & $wireguard @args 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "wireguard $($args -join ' ') failed ($LASTEXITCODE): $output" }
    $output
}

# Whether a file another process is still writing contains $Text. Opened
# for shared read and write, since OpenVPN holds its log and status open.
function Test-FileContains([string]$Path, [string]$Text) {
    try {
        $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
        try { [IO.StreamReader]::new($stream).ReadToEnd().Contains($Text) } finally { $stream.Dispose() }
    } catch { $false }
}

function Assert-RpcRefused([scriptblock]$Call, [string]$Expect, [string]$What) {
    try {
        & $Call | Out-Null
    } catch [RpcException] {
        if ($_.Exception.Message -notlike "*$Expect*") { throw "$What was refused, but not as expected: $($_.Exception.Message)" }
        return
    }
    throw "$What was allowed; it should have been refused."
}

# ---------------------------------------------------------------------------
# A throwaway PKI for the OpenVPN server and client
# ---------------------------------------------------------------------------

function New-TestPki {
    $x509 = 'System.Security.Cryptography.X509Certificates'
    $now = [DateTimeOffset]::UtcNow
    $sha256 = [Security.Cryptography.HashAlgorithmName]::SHA256
    $curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256

    $caKey = [Security.Cryptography.ECDsa]::Create($curve)
    $caRequest = New-Object "$x509.CertificateRequest" 'CN=SuperManager E2E CA', $caKey, $sha256
    $caRequest.CertificateExtensions.Add((New-Object "$x509.X509BasicConstraintsExtension" $true, $false, 0, $true))
    $caRequest.CertificateExtensions.Add((New-Object "$x509.X509KeyUsageExtension" ([Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign'), $true))
    $caRequest.CertificateExtensions.Add((New-Object "$x509.X509SubjectKeyIdentifierExtension" $caRequest.PublicKey, $false))
    $ca = $caRequest.CreateSelfSigned($now.AddDays(-1), $now.AddDays(7))

    $leaf = {
        param([string]$Name, [string]$Usage)
        $key = [Security.Cryptography.ECDsa]::Create($curve)
        $request = New-Object "$x509.CertificateRequest" "CN=$Name", $key, $sha256
        $request.CertificateExtensions.Add((New-Object "$x509.X509BasicConstraintsExtension" $false, $false, 0, $true))
        $request.CertificateExtensions.Add((New-Object "$x509.X509KeyUsageExtension" ([Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature'), $true))
        $usages = [Security.Cryptography.OidCollection]::new()
        [void]$usages.Add([Security.Cryptography.Oid]::new($Usage))
        $request.CertificateExtensions.Add((New-Object "$x509.X509EnhancedKeyUsageExtension" $usages, $false))
        $request.CertificateExtensions.Add((New-Object "$x509.X509SubjectKeyIdentifierExtension" $request.PublicKey, $false))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension]::CreateFromCertificate($ca, $true, $false))
        $serial = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
        $serial[0] = $serial[0] -band 0x7f
        $cert = $request.Create($ca, $now.AddDays(-1), $now.AddDays(7), $serial)
        [pscustomobject]@{ Cert = $cert.ExportCertificatePem(); Key = $key.ExportPkcs8PrivateKeyPem() }
    }

    [pscustomobject]@{
        Ca     = $ca.ExportCertificatePem()
        Server = & $leaf 'sm-e2e-server' '1.3.6.1.5.5.7.3.1'
        Client = & $leaf 'sm-e2e-client' '1.3.6.1.5.5.7.3.2'
    }
}

function Get-OpenVpnClientConfig($Pki, [int]$Port) {
    @"
client
dev tun
proto udp4
remote 127.0.0.1 $Port
nobind
remote-cert-tls server
verb 3
<ca>
$($Pki.Ca)
</ca>
<cert>
$($Pki.Client.Cert)
</cert>
<key>
$($Pki.Client.Key)
</key>
"@
}

# ---------------------------------------------------------------------------
# Diagnostics, whatever happens
# ---------------------------------------------------------------------------

function Save-Diagnostics {
    $out = { param($Name, $Block) try { & $Block 2>&1 | Out-String -Width 400 | Set-Content (Join-Path $LogDir $Name) } catch { "$_" | Set-Content (Join-Path $LogDir $Name) } }
    & $out 'status.json' { Invoke-Rpc 'get_status' }
    & $out 'profiles.json' { Invoke-Rpc 'list_profiles' }
    & $out 'adapters.txt' { Get-NetAdapter -IncludeHidden | Format-Table -AutoSize Name, InterfaceDescription, Status, ifIndex }
    & $out 'addresses.txt' { Get-NetIPAddress -AddressFamily IPv4 | Format-Table -AutoSize InterfaceAlias, IPAddress, PrefixLength }
    & $out 'routes.txt' { Get-NetRoute -AddressFamily IPv4 | Format-Table -AutoSize InterfaceAlias, DestinationPrefix, NextHop, RouteMetric }
    & $out 'dns.txt' { Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize InterfaceAlias, ServerAddresses }
    & $out 'wg-show.txt' { & $wg show all }
    & $out 'openvpn-processes.txt' { Get-CimInstance Win32_Process -Filter "Name = 'openvpn.exe'" | Format-List ProcessId, CommandLine }
    & $out 'service-events.txt' {
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'SuperManager' } -MaxEvents 400 -ErrorAction SilentlyContinue |
            Sort-Object TimeCreated | Format-Table -Wrap -AutoSize TimeCreated, LevelDisplayName, Message
    }
    & $out 'wireguard-log.txt' { Invoke-WireGuard /dumplog }
}

# The same, in the job log: the uploaded artifact is not always at hand
# when a run is being looked at.
function Show-Diagnostics {
    foreach ($file in Get-ChildItem $LogDir -File | Where-Object Name -ne 'test-vpn.transcript.txt') {
        Write-Host "----- $($file.Name) (last 150 lines) -----"
        Get-Content $file.FullName -Tail 150 | ForEach-Object { Write-Host $_ }
    }
}

# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------

$profiles = [Collections.Generic.List[string]]::new()
$ovpnServer = $null
$wgServerInstalled = $false
$ovpnAdapters = [Collections.Generic.List[string]]::new()
$failed = $true
Start-Transcript -Path (Join-Path $LogDir 'test-vpn.transcript.txt') -Force | Out-Null
try {
    foreach ($file in @($wg, $wireguard, $openvpn, $tapctl)) {
        if (-not (Test-Path $file)) { throw "Missing $file — the bundle should have installed it." }
    }

    Write-Host '==> The service can run WireGuard and OpenVPN'
    $caps = Invoke-Rpc 'vpn_capabilities' | ConvertFrom-Json
    foreach ($kind in @('wireguard', 'openvpn')) {
        if (-not $caps.$kind.available) { throw "The service says $kind is unavailable: $($caps.$kind.reason)" }
    }
    # Loopback is not normally filtered; the rule is a precaution.
    try {
        New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound -Protocol UDP `
            -LocalPort $wgServerPort, $ovpnServerPort -Action Allow | Out-Null
    } catch { Write-Host "No firewall rule added ($_); carrying on." }

    # -- WireGuard ------------------------------------------------------------

    Write-Host '==> WireGuard server tunnel (WireGuard for Windows)'
    $serverKeys = & $wg genkey
    $server = [pscustomobject]@{ Private = $serverKeys.Trim(); Public = ($serverKeys | & $wg pubkey).Trim() }
    $clientKeys = & $wg genkey
    $client = [pscustomobject]@{ Private = $clientKeys.Trim(); Public = ($clientKeys | & $wg pubkey).Trim() }
    # Only the client's tunnel address is routed back: nothing here may
    # take this runner's own traffic (0.0.0.0/0 would also switch on
    # WireGuard for Windows' kill switch).
    $serverConf = Join-Path $work "$wgServerTunnel.conf"
    Set-Content -Path $serverConf -Encoding ascii -Value @"
[Interface]
PrivateKey = $($server.Private)
ListenPort = $wgServerPort
Address = 10.98.0.1/32

[Peer]
PublicKey = $($client.Public)
AllowedIPs = 10.99.1.2/32
"@
    Invoke-WireGuard /installtunnelservice $serverConf | Out-Null
    $wgServerInstalled = $true
    Wait-Until { (Get-Service "WireGuardTunnel`$$wgServerTunnel" -ErrorAction SilentlyContinue).Status -eq 'Running' } 'the WireGuard server tunnel service'
    Wait-Until { (Get-NetAdapter -Name $wgServerTunnel -ErrorAction SilentlyContinue).Status -eq 'Up' } 'the WireGuard server adapter'

    Write-Host '==> Import a WireGuard profile'
    # AllowedIPs with host bits set, as hand-written configs often have:
    # WireGuard masks them; the route table refuses them unless the
    # service does too.
    $wgConfA = @"
[Interface]
PrivateKey = $($client.Private)
Address = 10.99.1.2/24
DNS = 10.99.1.53

[Peer]
PublicKey = $($server.Public)
Endpoint = 127.0.0.1:$wgServerPort
AllowedIPs = 10.98.0.9/24
PersistentKeepalive = 1
"@
    $wgA = Invoke-Rpc 'import_wireguard' @{ conf_text = $wgConfA; name = 'E2E WireGuard A' }
    $profiles.Add($wgA)
    $listed = (Invoke-Rpc 'list_profiles' | ConvertFrom-Json) | Where-Object id -eq $wgA
    if (-not $listed) { throw 'The imported profile is not listed.' }
    if (-not $listed.push_dns) { throw 'A WireGuard config with a DNS line imported with DNS off.' }

    Write-Host '==> Connect it'
    $status = Connect-Profile $wgA
    $ifaceA = Get-WgAdapterName $wgA
    if ($status.interface -ne $ifaceA) { throw "Status names interface '$($status.interface)', expected '$ifaceA'." }
    Wait-Until { (Get-NetAdapter -Name $ifaceA -ErrorAction SilentlyContinue).Status -eq 'Up' } "adapter $ifaceA up"
    $address = Get-NetIPAddress -InterfaceAlias $ifaceA -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($address.IPAddress -ne '10.99.1.2' -or $address.PrefixLength -ne 24) {
        throw "Adapter $ifaceA has $($address.IPAddress)/$($address.PrefixLength), expected 10.99.1.2/24."
    }
    if (-not (Get-NetRoute -InterfaceAlias $ifaceA -DestinationPrefix '10.98.0.0/24' -ErrorAction SilentlyContinue)) {
        throw "No route for AllowedIPs 10.98.0.0/24 through $ifaceA."
    }
    $dns = (Get-DnsClientServerAddress -InterfaceAlias $ifaceA -AddressFamily IPv4).ServerAddresses
    if ($dns -notcontains '10.99.1.53') { throw "DNS on $ifaceA is '$($dns -join ', ')', expected 10.99.1.53." }

    Write-Host '==> The server completes a handshake with it'
    Wait-Until {
        $h = Get-WgPeerField 'latest-handshakes'
        $h -and $h[0] -eq $client.Public -and [int64]$h[1] -gt 0
    } 'a handshake on the server' 30

    Write-Host '==> Traffic for AllowedIPs goes through the tunnel'
    $transfer = Get-WgPeerField 'transfer'
    $before = [int64]$transfer[1]
    # The replies cannot come back (see the top of this file); the pings
    # only have to arrive.
    & ping.exe -n 4 -w 500 -l 1200 10.98.0.77 | Out-Null
    Start-Sleep -Seconds 1
    $transfer = Get-WgPeerField 'transfer'
    $after = [int64]$transfer[1]
    if ($after - $before -lt 4 * 1200) {
        throw "The server decrypted $($after - $before) bytes for 4 pings of 1200 bytes."
    }

    Write-Host '==> A connected profile cannot be deleted'
    Assert-RpcRefused { Invoke-Rpc 'delete_profile' @{ profile_id = $wgA } } 'disconnect it first' 'Deleting the connected profile'

    Write-Host '==> Switching profiles closes the first tunnel'
    $wgConfB = $wgConfA -replace 'DNS = 10.99.1.53\r?\n', '' -replace '10.98.0.9/24', '10.98.0.0/24'
    $wgB = Invoke-Rpc 'import_wireguard' @{ conf_text = $wgConfB; name = 'E2E WireGuard B' }
    $profiles.Add($wgB)
    $status = Connect-Profile $wgB
    $ifaceB = Get-WgAdapterName $wgB
    if ($status.interface -ne $ifaceB) { throw "Status names interface '$($status.interface)', expected '$ifaceB'." }
    Assert-AdapterGone $ifaceA
    if (-not (Test-Adapter $ifaceB)) { throw "Adapter $ifaceB is missing." }

    Write-Host '==> Disconnect removes the adapter'
    Disconnect-Vpn
    Assert-AdapterGone $ifaceB

    Write-Host '==> Stopping the service closes the tunnel'
    Connect-Profile $wgA | Out-Null
    Close-Service
    $service = Get-Service SuperManager
    $service.Stop()
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    Assert-AdapterGone $ifaceA
    $service.Start()
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Wait-Until { try { Open-Service; $true } catch { $false } } 'the service pipe after a restart'
    $status = Get-VpnStatus
    if ($status.state -ne 'disconnected') { throw "After a restart the service says $(Format-Status $status)." }

    # -- OpenVPN --------------------------------------------------------------

    Write-Host '==> OpenVPN adapters'
    # One for the server, and a spare for the service's client: it uses the
    # DCO driver where it can open it, and falls back to TAP-Windows6 —
    # which needs a free adapter — where it cannot.
    foreach ($name in @($ovpnServerAdapter, $ovpnSpareAdapter)) {
        & $tapctl create --name $name --hwid 'root\tap0901' | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "tapctl could not create TAP-Windows6 adapter $name ($LASTEXITCODE)." }
        $ovpnAdapters.Add($name)
    }

    Write-Host '==> OpenVPN: a connect that cannot reach its server can be cancelled'
    $pki = New-TestPki
    $unreachable = Invoke-Rpc 'import_openvpn' @{ conf_text = (Get-OpenVpnClientConfig $pki 1195); name = 'E2E OpenVPN unreachable' }
    $profiles.Add($unreachable)
    Invoke-Rpc 'connect' @{ profile_id = $unreachable } | Out-Null
    $status = Wait-VpnState @('connecting') 10
    Wait-Until { @(Get-OpenVpnClients).Count -gt 0 } 'the OpenVPN client to start' 10
    Start-Sleep -Seconds 3
    Disconnect-Vpn
    Wait-Until { @(Get-OpenVpnClients).Count -eq 0 } 'the cancelled OpenVPN client to exit' 15

    Write-Host '==> OpenVPN: an unanswered connect gives up with a reason'
    Invoke-Rpc 'connect' @{ profile_id = $unreachable } | Out-Null
    $status = Wait-VpnState @('connected', 'error') 90
    if ($status.state -ne 'error' -or $status.message -notlike '*did not connect within*') {
        throw "Expected a timeout error, got $(Format-Status $status)"
    }
    Wait-Until { @(Get-OpenVpnClients).Count -eq 0 } 'the timed-out OpenVPN client to exit' 15
    Disconnect-Vpn

    Write-Host '==> OpenVPN server'
    $serverLog = Join-Path $LogDir 'openvpn-server.log'
    $serverStatus = Join-Path $work 'openvpn-server-status.txt'
    $serverOvpn = Join-Path $work 'server.ovpn'
    Set-Content -Path $serverOvpn -Encoding ascii -Value @"
dev tun
dev-node $ovpnServerAdapter
windows-driver tap-windows6
disable-dco
topology subnet
server 10.97.0.0 255.255.255.0
ip-win32 netsh
proto udp4
port $ovpnServerPort
dh none
remote-cert-tls client
keepalive 5 30
verb 3
status "$($serverStatus -replace '\\', '\\')" 1
<ca>
$($pki.Ca)
</ca>
<cert>
$($pki.Server.Cert)
</cert>
<key>
$($pki.Server.Key)
</key>
"@
    $ovpnServer = Start-Process $openvpn -WorkingDirectory $ovpnBin -PassThru -WindowStyle Hidden `
        -ArgumentList '--config', "`"$serverOvpn`"", '--log', "`"$serverLog`""
    Wait-Until {
        if ($ovpnServer.HasExited) { throw "The OpenVPN server exited ($($ovpnServer.ExitCode)); see openvpn-server.log." }
        Test-FileContains $serverLog 'Initialization Sequence Completed'
    } 'the OpenVPN server to start' 60

    Write-Host '==> Import and connect an OpenVPN profile'
    $ovpn = Invoke-Rpc 'import_openvpn' @{ conf_text = (Get-OpenVpnClientConfig $pki $ovpnServerPort); name = 'E2E OpenVPN' }
    $profiles.Add($ovpn)
    Connect-Profile $ovpn 90 | Out-Null
    Wait-Until {
        Test-FileContains $serverStatus 'sm-e2e-client'
    } 'the OpenVPN server to list the client' 20
    Wait-Until {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -like '10.97.0.*' -and $_.InterfaceAlias -ne $ovpnServerAdapter }
    } 'the OpenVPN client to be given an address' 20

    Write-Host '==> Disconnect stops the OpenVPN client'
    Disconnect-Vpn
    Wait-Until { @(Get-OpenVpnClients).Count -eq 0 } 'the OpenVPN client to exit' 15

    Write-Host '==> Profiles are deleted once disconnected'
    foreach ($id in @($profiles)) {
        Invoke-Rpc 'delete_profile' @{ profile_id = $id } | Out-Null
        $profiles.Remove($id) | Out-Null
    }

    $failed = $false
    Write-Host 'VPN end-to-end passed: WireGuard (import, connect, adapter, address, route, DNS, handshake, traffic, delete refused, switch, disconnect, service stop) and OpenVPN (cancel, timeout, connect, disconnect).'
} finally {
    Save-Diagnostics
    if ($failed) {
        Write-Host '==> Failed; diagnostics follow'
        Show-Diagnostics
    }
    try { Invoke-Rpc 'disconnect' | Out-Null } catch { Write-Host "cleanup: disconnect: $_" }
    foreach ($id in @($profiles)) {
        try { Invoke-Rpc 'delete_profile' @{ profile_id = $id } | Out-Null } catch { Write-Host "cleanup: delete $id`: $_" }
    }
    Close-Service
    if ($ovpnServer -and -not $ovpnServer.HasExited) { Stop-Process -Id $ovpnServer.Id -Force; $ovpnServer.WaitForExit(10000) | Out-Null }
    foreach ($name in $ovpnAdapters) { & $tapctl delete $name | Out-Host }
    if ($wgServerInstalled) {
        try { Invoke-WireGuard /uninstalltunnelservice $wgServerTunnel | Out-Null } catch { Write-Host "cleanup: $_" }
    }
    Remove-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue
    Stop-Transcript | Out-Null
}
