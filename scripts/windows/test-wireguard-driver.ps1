# Run in a child process so the DLL is unloaded before MSI maintenance.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DllPath)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Run only on a disposable GitHub Actions runner.' }
$dll = (Resolve-Path $DllPath).Path
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WireGuardInstallProbe {
    [DllImport(@"$dll", CallingConvention=CallingConvention.Winapi, CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr WireGuardCreateAdapter(string name, string type, IntPtr guid);
    [DllImport(@"$dll", CallingConvention=CallingConvention.Winapi)]
    public static extern void WireGuardCloseAdapter(IntPtr adapter);
}
"@
$adapter = [WireGuardInstallProbe]::WireGuardCreateAdapter('SuperManagerInstallTest', 'SuperManager', [IntPtr]::Zero)
if ($adapter -eq [IntPtr]::Zero) { throw "WireGuard driver failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
[WireGuardInstallProbe]::WireGuardCloseAdapter($adapter)

