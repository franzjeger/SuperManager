# Destructive lifecycle test, only on disposable GitHub-hosted Windows runners.
[CmdletBinding()]
param([string]$Installer = "$PSScriptRoot\..\..\installer\wix\SuperManager-Setup.exe")
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Run only on a disposable GitHub Actions runner.' }
$Installer = (Resolve-Path $Installer).Path
$logs = Join-Path $env:RUNNER_TEMP 'supermanager-installer-test'
New-Item -ItemType Directory -Path $logs -Force | Out-Null

function Invoke-Setup([string]$Action) {
    $log = Join-Path $logs "$Action.log"
    $process = Start-Process $Installer -ArgumentList "/$Action /quiet /norestart /log `"$log`"" -PassThru
    if (-not $process.WaitForExit(180000)) { $process.Kill(); throw "$Action timed out; see $log" }
    if ($process.ExitCode -notin @(0, 3010)) { throw "$Action failed ($($process.ExitCode)); see $log" }
}

Invoke-Setup 'install'
$bin = Join-Path $env:ProgramFiles 'SuperManager\bin'
foreach ($file in @('supermgr-win.exe', 'supermgrd-win.exe', 'supermgr-mcp.exe', 'wireguard.dll')) {
    if (-not (Test-Path (Join-Path $bin $file))) { throw "Missing installed file: $file" }
}
$service = Get-Service SuperManager
$service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
$openvpn = Join-Path $env:ProgramFiles 'OpenVPN\bin\openvpn.exe'
& $openvpn --version
if ($LASTEXITCODE -ne 0) { throw 'Installed OpenVPN cannot start.' }

# Prove that the bundled DLL can create its signed driver/adapter. No VPN
# endpoint, address, routes or credentials are configured during this test.
$dll = Join-Path $bin 'wireguard.dll'
& "$PSHOME\pwsh.exe" -NoProfile -File "$PSScriptRoot\test-wireguard-driver.ps1" -DllPath $dll
if ($LASTEXITCODE -ne 0) { throw 'WireGuard driver probe failed.' }

$pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'supermgrd', [IO.Pipes.PipeDirection]::InOut)
try {
    $pipe.Connect(10000)
    $encoding = [Text.UTF8Encoding]::new($false)
    $reader = [IO.StreamReader]::new($pipe, $encoding)
    $writer = [IO.StreamWriter]::new($pipe, $encoding)
    $writer.AutoFlush = $true
    $writer.WriteLine('{"v":1,"id":1,"method":"list_profiles","args":{}}')
    $read = $reader.ReadLineAsync()
    if (-not $read.Wait(10000)) { throw 'Installed daemon RPC timed out.' }
    $reply = $read.Result | ConvertFrom-Json
    if ($null -eq $reply -or $reply.id -ne 1 -or $reply.error) { throw 'Installed daemon RPC failed.' }
} finally { $pipe.Dispose() }

# Real tunnels through the installed service, against servers stood up on
# this runner: see test-vpn.ps1. A child process, like the driver probe, so
# nothing it loads outlives it into the repair below.
& "$PSHOME\pwsh.exe" -NoProfile -File "$PSScriptRoot\test-vpn.ps1" -LogDir (Join-Path $logs 'vpn')
if ($LASTEXITCODE -ne 0) { throw 'VPN end-to-end test failed; see vpn\ in the installer test logs.' }

$gui = Start-Process (Join-Path $bin 'supermgr-win.exe') -PassThru
try {
    if ($gui.WaitForExit(7000)) { throw "Installed GUI exited during startup ($($gui.ExitCode))." }
} finally { if (-not $gui.HasExited) { $gui.Kill(); $gui.WaitForExit() } }

$sentinel = Join-Path $env:ProgramData 'SuperManager\installer-test-state.txt'
Set-Content $sentinel 'preserve user state'
Invoke-Setup 'repair'
if ((Get-Content $sentinel) -ne 'preserve user state') { throw 'Repair removed user state.' }
(Get-Service SuperManager).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Invoke-Setup 'uninstall'
if (Get-Service SuperManager -ErrorAction SilentlyContinue) { throw 'Uninstall left the service registered.' }
if ((Get-Content $sentinel) -ne 'preserve user state') { throw 'Uninstall removed user state.' }
Remove-Item $sentinel
Write-Host 'Installer lifecycle passed: dependencies, driver, daemon RPC, VPN end to end, GUI startup, repair, uninstall, preserved state.'
