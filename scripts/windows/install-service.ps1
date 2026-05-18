# Install the SuperManager Windows Service.
#
# Run from an elevated PowerShell prompt:
#
#   .\scripts\windows\install-service.ps1
#
# Re-running is idempotent: an existing service is stopped, removed, and
# re-created with the latest binary path so a `cargo build --release` +
# rerun cycle works without manual cleanup.

[CmdletBinding()]
param(
    [string]$ServiceName = "SuperManager",
    [string]$DisplayName = "SuperManager Daemon",
    [string]$Description = "Manages SSH keys, hosts, and VPN connections for SuperManager.",
    [string]$BinaryPath  = (Join-Path $PSScriptRoot "..\..\target\release\supermgrd-win.exe")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found at $BinaryPath. Build with 'cargo build --release -p supermgrd-win' first."
}
$BinaryPath = (Resolve-Path $BinaryPath).Path

# Require admin — New-Service writes to HKLM\SYSTEM\CurrentControlSet\Services
$elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
    Write-Error "Run this script from an elevated PowerShell prompt."
}

# Stop + remove any existing service before reinstall.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing $ServiceName service..."
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
    }
    Write-Host "Removing existing $ServiceName service..."
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "Creating service $ServiceName -> $BinaryPath"
New-Service `
    -Name           $ServiceName `
    -DisplayName    $DisplayName `
    -Description    $Description `
    -BinaryPathName "`"$BinaryPath`"" `
    -StartupType    Automatic `
    -DependsOn      @("Tcpip", "Dhcp") | Out-Null

# Restart-on-failure policy: first two failures restart after 5s, third
# leaves the service stopped so the SCM doesn't loop forever if the
# daemon is broken. Mirrors what we ship in the systemd unit on Linux.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/""/0 | Out-Null

Write-Host "Starting service..."
Start-Service -Name $ServiceName
Write-Host "Service status:"
Get-Service -Name $ServiceName | Format-Table -AutoSize
