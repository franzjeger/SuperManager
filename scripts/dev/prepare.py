#!/usr/bin/env python3
"""Create a disposable, isolated macOS Dev source tree. Never edit the input tree."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil

REPLACEMENTS = [
    ('com.sybr.supermanager', 'com.sybr.supermanager.dev'),
    ('com.sybr.tailscaled', 'com.sybr.supermanager.dev.tailscaled'),
    ('SuperManagerVPN', 'SuperManagerDevVPN'),
    ('SuperManagerSystem', 'SuperManagerDevSystem'),
    ('Library/Application Support/SuperManager', 'Library/Application Support/SuperManager Dev'),
    ('"SuperManager"', '"SuperManager Dev"'),
    ('appendingPathComponent("SuperManager")', 'appendingPathComponent("SuperManager Dev")'),
    ('supermgrd-mac', 'supermanager-dev-engine'),
    ('supermanager-', 'supermanager-dev-'),
    ('supermgr-', 'supermgr-dev-'),
    ('supermgr://', 'supermgr-dev://'),
    ('"supermgr"', '"supermgr-dev"'),
    ('/private/etc/wireguard', '/private/etc/supermanager-dev-wireguard'),
    ('/var/log/supermanager"', '/var/log/supermanager-dev"'),
    ('/var/run/charon.vici', '/Library/PrivilegedHelperTools/SuperManagerDevIPSecState/charon.vici'),
    ('/var/lib/tailscale', '/var/lib/supermanager-dev-tailscale'),
    ('/var/run/tailscaled.socket', '/var/run/supermanager-dev-tailscaled.socket'),
]


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Source layout changed: ' + old[:80])
    return text.replace(old, new, 1)


def transform(text):
    # Simultaneous substitution: replacement strings must not be transformed again.
    mapping = dict(REPLACEMENTS)
    return re.sub('|'.join(re.escape(k) + (r'(?![A-Za-z])' if k.endswith('Application Support/SuperManager') else '') for k in mapping), lambda m: mapping[m[0]], text)


def prepare(source, output):
    source, output = source.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(source):
        raise ValueError('Use a new output directory outside the source checkout')
    shutil.copytree(source, output, ignore=shutil.ignore_patterns(
        '.git', 'target', '.build', 'build', 'DerivedData', 'dist', '*.zip', '*.xcodeproj',
        'audit-evidence-*', '.DS_Store', '*.pkg', '*.dmg'))
    for path in output.rglob('*'):
        if path.is_relative_to(output / 'scripts/dev'):
            continue
        if path.is_file() and (path.suffix in {'.swift', '.rs', '.plist', '.yml', '.py', '.sh'}
                               or path.name in {'preinstall', 'postinstall'}):
            path.write_text(transform(path.read_text()))
    def edit(relative, fn):
        path = output / relative
        path.write_text(fn(path.read_text()))
    edit('supermgrd-mac/src/main.rs', lambda s: replace_once(s,
        'supermgr_engine::scheduler::spawn();', '// Dev: scheduled scans are disabled.'))
    # Folder names remain unchanged; only binary identity changes.
    edit('supermgrd-mac/Cargo.toml', lambda s: replace_once(s, 'name = "supermgrd-mac"', 'name = "supermanager-dev-engine"'))
    edit('SuperManagerMac/SuperManagerMac/App/SuperManagerApp.swift', lambda s: s.replace(
        'appState.startSleepWakeMonitor()', '// Dev: no sleep/wake network changes').replace(
        'CrashReporting.start()', 'CrashReporting.start()\n        NSApplication.shared.dockTile.badgeLabel = "DEV"').replace(
        'WindowGroup {', 'WindowGroup("SuperManager Dev") {'))
    edit('SuperManagerMac/SuperManagerMac/App/AppState.swift', lambda s: s.replace(
        '        await NotificationManager.requestAuthorization()', '        // Dev: notifications are opt-in after startup').replace(
        '        installSleepWakeObservers()', '        // Dev: sleep/wake networking disabled').replace(
        '        await reconcileBundledTailscaledUpdate()', '        // Dev: no automatic Tailscale installation').replace(
        '                await kickComplianceAutoScanIfDue()', '                // Dev: no automatic compliance scan'))
    edit('SuperManagerMac/SuperManagerMac/Services/SparkleUpdater.swift', lambda s: replace_once(s,
        'let publicKey = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String ?? ""',
        'let publicKey = "" // Dev never consumes the production update feed').replace(
        'Auto-updates are not configured yet. Run scripts/sparkle-keygen.sh and paste the public key into SuperManagerMac/project.yml\'s SUPublicEDKey.',
        'Updates are disabled in SuperManager Dev. Rebuild the Dev app to update it.'))
    edit('SuperManagerMac/SuperManagerMac/Services/TailscaleClient.swift', lambda s: s.replace(
        'process.arguments = args', 'process.arguments = ["--socket=/var/run/supermanager-dev-tailscaled.socket"] + args'))
    def helper(s):
        begin = s.index('    // Sweep transient strongSwan configs')
        end = s.index('    let listener = UnixListener::bind', begin)
        s = s[:begin] + '    // Dev: no background route, DNS, or reconnect watchdogs.\n' + s[end:]
        begin = s.index('    // Always-on auto-reconnect watchdog.')
        end = s.index('    let connections =', begin)
        s = s[:begin] + s[end:]
        guard = '''    // Dev is intentionally manual-only. Do not expose global recovery actions.
    let allowed = ["ping", "helper_version", "vpn_runtime_status", "vpn_status",
        "wg_status", "ovpn_status", "vpn_connect", "vpn_disconnect", "wg_connect",
        "wg_disconnect", "ovpn_connect", "ovpn_disconnect", "auto_reconnect_list"];
    if !allowed.contains(&req.method.as_str()) {
        return Response::err(id, -32601, "This automatic/global networking action is disabled in SuperManager Dev");
    }
    if req.method.ends_with("_connect") || req.method.ends_with("_disconnect") {
        // Fail closed, including a stale stable socket. The operator must explicitly
        // stop stable networking and remove its stale socket before a Dev VPN test.
        if std::path::Path::new("/var/run/com.sybr.supermanager.helper.sock").exists()
            || std::path::Path::new("/var/run/charon.vici").exists() {
            return Response::err(id, -32000, "Stop the regular SuperManager helper and disconnect its VPNs before testing a Dev tunnel");
        }
    }
'''
        return replace_once(s, '    debug!(method = %req.method, "dispatch");', guard + '    debug!(method = %req.method, "dispatch");')
    edit('supermanager-helper/src/main.rs', helper)
    edit('supermanager-helper/src/strongswan.rs', lambda s: replace_once(s,
        '    async fn ensure_charon(&mut self) -> anyhow::Result<()> {',
        '    async fn ensure_charon(&mut self) -> anyhow::Result<()> {\n        crate::secure_files::ensure_root_directory(Path::new("/Library/PrivilegedHelperTools/SuperManagerDevIPSecState"))?;'))

    edit('supermanager-helper/src/wireguard.rs', lambda s: s.replace('smwg', 'sdwg'))
    edit('installer/system/build_runtime.py', lambda s: replace_once(s,
        "configure('strongswan', ['--disable-defaults',",
        "configure('strongswan', ['--with-piddir=/Library/PrivilegedHelperTools/SuperManagerDevIPSecState', '--disable-defaults',").replace(
        "    (runtime / 'lib/ipsec/plugins').mkdir(parents=True)",
        "    (runtime / 'var/run').mkdir(parents=True)\n    (runtime / 'lib/ipsec/plugins').mkdir(parents=True)"))
    edit('installer/system/scripts/preinstall', lambda s: s.replace(
        'for process in SuperManagerMac openvpn openvpn3 charon wireguard-go; do',
        'for process in SuperManagerDev; do').replace(
        "base='/Library/Application Support/SuperManagerDevSystem'",
        '''if pgrep -f '^/Library/PrivilegedHelperTools/SuperManagerDevVPN/(sbin/openvpn|bin/openvpn3|libexec/ipsec/charon|bin/wireguard-go)( |$)' >/dev/null; then
    echo 'Disconnect Dev VPNs and stop the Dev VPN processes before updating.' >&2; exit 1
fi
base='/Library/Application Support/SuperManagerDevSystem' '''.rstrip()))
    edit('SuperManagerMac/SuperManagerMac/Views/WelcomeView.swift', lambda s: s.replace(
        'Welcome to SuperManager', 'Welcome to SuperManager Dev').replace(
        'All connections come with safety nets.', 'DEV — independent data, real network actions').replace(
        'Auto-reconnect after sleep, kill-switch when enabled, and a connectivity watchdog that auto-recovers within 10 seconds if anything goes wrong.',
        'Profiles are copied, not synchronized. Automatic VPN recovery and scheduled jobs are disabled. Install the Dev system package and stop stable VPN services before manually testing a tunnel.').replace(
        'Install our bundled tailscaled as a system service — auto-starts at boot, auto-reconnects after sleep.',
        'Tailscale daemon installation is disabled in this isolated Dev build. The existing system node is not shared.'))
    # Disable stale production feed / URL handler in generated project.
    path = output / 'SuperManagerMac/project.yml'
    spec = path.read_text()
    begin = spec.index('    preBuildScripts:')
    end = spec.index('  SuperManagerMacTests:', begin)
    spec = spec[:begin] + spec[end:]
    spec = spec.replace('CFBundleName: SuperManager', 'CFBundleName: SuperManager Dev')
    spec = spec.replace('- supermgr\n', '- supermgr-dev\n')
    spec = re.sub(r'^(\s*)SUFeedURL:.*$', r'\1SUFeedURL: ""', spec, flags=re.M)
    spec = re.sub(r'^(\s*)SUPublicEDKey:.*$', r'\1SUPublicEDKey: ""', spec, flags=re.M)
    path.write_text(spec)
    (output / 'DEV-BUILD.json').write_text(json.dumps({
        'source': str(source), 'bundle_id': 'com.sybr.supermanager.dev',
        'automatic_networking': False, 'production_updates': False}, indent=2))
    print('Prepared isolated Dev source: ' + str(output))

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    prepare(a.source, a.output)
