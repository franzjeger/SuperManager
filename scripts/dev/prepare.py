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


def tailscale_helper(s):
    # Installation must never remove routes belonging to another active VPN.
    s = s.replace('    let _ = remove_exit_routes(ExitRoutesArgs::default());',
                  '    // Dev: leave existing system/VPN routes untouched during installation.', 1)
    s = s.replace('<key>TS_BIND_TO_INTERFACE_BY_ROUTE</key><string>1</string>',
                  '<key>TS_BIND_TO_INTERFACE_BY_ROUTE</key><string>1</string>\n        <key>TS_LOGS_DIR</key><string>{state}</string>')
    return s.replace('--port=41641', '--port=41642')


def tailscale_client(s):
    s = s.replace('process.arguments = args',
                  'process.arguments = ["--socket=/var/run/supermanager-dev-tailscaled.socket"] + args')
    s = s.replace('["up", "--force-reauth"]', '["up", "--force-reauth", "--accept-dns=false", "--accept-routes=false", "--hostname=supermanager-dev"]')
    check = '\n        let ownership = try await HelperClient.shared.devTailscaleServiceStatus()\n        if ownership["stable_running"] as? Bool == true {\n            throw ClientError.daemonNotRunning("Regular Tailscale is running. Open Tailscale Settings and choose Use Dev Tailscale before connecting.")\n        }'
    for signature in ['    static func up() async throws {',
                      '    static func login(onAuthURL: @escaping @Sendable (URL) -> Void) async throws {',
                      '    static func addAccount(onAuthURL: @escaping @Sendable (URL) -> Void) async throws {']:
        s = s.replace(signature, signature + check)
    # Prevent an exit-node setting from succeeding before its blocked routing RPC.
    marker = '    private static func runSet(_ args: [String]) async throws {'
    s = replace_once(s, marker, marker + '\n        if args.contains(where: { $0.hasPrefix("--exit-node=") && $0 != "--exit-node=" || $0 == "--accept-dns=true" }) {\n            throw ClientError.daemonNotRunning("Exit nodes and system DNS changes are unavailable in Dev. Peer connections and subnet routes are supported.")\n        }')
    return s


def tailscale_header(s):
    s = s.replace('            exitNodeSubmenu', '            Text("Exit nodes unavailable in Dev")')
    s = s.replace('.help("Force-write the system resolver', '.disabled(true)\n            .help("Force-write the system resolver')
    s = s.replace('.help("Clear exit-node + accept-routes', '.disabled(true)\n            .help("Clear exit-node + accept-routes')
    return s


def service_switch_main(s):
    s = s.replace('mod tailscale;', 'mod network_switch;\nmod tailscale;')
    marker = '    match req.method.as_str() {'
    addition = '''    let _switch_lock = if ["dev_tailscale_switch", "tailscaled_install", "tailscaled_uninstall"].contains(&req.method.as_str()) {
        Some(network_switch::LOCK.lock().await)
    } else { None };
    match req.method.as_str() {
        "dev_tailscale_status" => match network_switch::status().await {
            Ok(state) => Response::ok(id, serde_json::to_value(state).unwrap()),
            Err(error) => Response::err(id, -32000, format!("Service status failed: {error:#}")),
        },
        "dev_tailscale_switch" => match serde_json::from_value::<network_switch::SwitchArgs>(req.params) {
            Ok(args) => match network_switch::switch(args).await {
                Ok(state) => Response::ok(id, serde_json::to_value(state).unwrap()),
                Err(error) => Response::err(id, -32000, format!("Service switch failed: {error:#}")),
            },
            Err(error) => Response::err(id, -32602, error.to_string()),
        },'''
    return replace_once(s, marker, addition)


def service_switch_client(s):
    marker = '    private static var nextId: UInt64 = 0'
    methods = '''    func devTailscaleServiceStatus() async throws -> [String: Any] {
        try await callOnce(method: "dev_tailscale_status", params: [:], timeoutSeconds: 20)
    }
    func devTailscaleSwitch(_ target: String) async throws -> [String: Any] {
        // A mutation is never automatically retried after a lost response.
        try await callOnce(method: "dev_tailscale_switch", params: ["target": target], timeoutSeconds: 90)
    }
'''
    return replace_once(s, marker, methods + marker)


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
    edit('SuperManagerMac/SuperManagerMac/Services/TailscaleClient.swift', tailscale_client)
    edit('supermanager-helper/src/tailscale.rs', tailscale_helper)
    edit('SuperManagerMac/SuperManagerMac/App/AppState+Tailscale.swift', lambda s: s.replace('        await ensureMagicDNSResolver()', '        // Dev: DNS remains under the existing VPN/system owner'))
    edit('SuperManagerMac/SuperManagerMac/Views/Tailscale/TailscaleHeaderView.swift', tailscale_header)
    edit('SuperManagerMac/SuperManagerMac/Views/Tailscale/TailscaleSettingsView.swift', lambda s: s.replace('                    dnsSection', '                    Text("Dev uses existing system DNS. Exit-node and global DNS recovery are unavailable.").font(.caption)'))
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
        "wg_disconnect", "ovpn_connect", "ovpn_disconnect", "auto_reconnect_list", "tailscaled_install",
        "tailscaled_uninstall", "tailscaled_status", "dev_tailscale_status", "dev_tailscale_switch"];
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
    edit('supermanager-helper/src/main.rs', service_switch_main)
    (output / 'supermanager-helper/src/network_switch.rs').write_text(
        (Path(__file__).parent / 'network_switch.rs').read_text())
    edit('SuperManagerMac/SuperManagerMac/Services/HelperClient.swift', service_switch_client)
    edit('SuperManagerMac/SuperManagerMac/Views/Tailscale/TailscaleSettingsView.swift', lambda s:
        s.replace('                    accountSection', '                    TailscaleServiceSwitch()\n                    accountSection')
        + '\n' + (Path(__file__).parent / 'TailscaleServiceSwitch.swift').read_text())

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
        'Install a separate Dev Tailscale node. Sign in separately; pause other Tailscale nodes before connecting. Dev keeps the current system DNS.'))
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
