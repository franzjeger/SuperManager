# Remove the SuperManager Windows Service.
#
# Run from an elevated PowerShell prompt:
#
#   .\scripts\windows\uninstall-service.ps1

[CmdletBinding()]
param([string]$ServiceName = "SuperManager")

$ErrorActionPreference = "Stop"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "Service $ServiceName is not installed."
    return
}

if ($existing.Status -ne "Stopped") {
    Write-Host "Stopping $ServiceName..."
    Stop-Service -Name $ServiceName -Force
}

Write-Host "Removing $ServiceName..."
sc.exe delete $ServiceName | Out-Null
Write-Host "Done."
