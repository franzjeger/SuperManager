# Security Policy

## Supported Versions

Security fixes ship on the latest `1.8.x` release line across macOS, Linux, and Windows. Older releases do not receive backported patches; upgrade to the newest published tag before verifying an issue.

| Version | Supported |
| ------- | --------- |
| Latest `1.8.x` release | Yes |
| Earlier `1.8.x` / `< 1.8` | No |

## Reporting a Vulnerability

**Do not open a public GitHub issue or pull request for suspected security vulnerabilities.**

SuperManager includes root/SYSTEM helpers (`supermanager-helper`, `supermgrd`, `supermgrd-win`) and handles SSH keys, VPN credentials, and firewall API tokens. Public disclosure before a fix is available puts existing installations at risk.

Report vulnerabilities privately through GitHub Security Advisories:

- **Private report URL:** https://github.com/franzjeger/SuperManager/security/advisories/new

Please include:
1. Affected platform(s), component (`supermanager-helper`, `supermgrd`, `supermgrd-win`, `supermgr-engine`, `supermgr-mcp`, or UI), and version/commit SHA.
2. Preconditions (e.g., local unprivileged user, network position, untrusted profile/import file, or MCP client configuration).
3. Minimal reproduction steps or proof of concept, and the security boundary crossed.

## Response Timeline

- **Initial acknowledgment:** within **72 hours** of submission.
- **Triage & severity assessment:** within **7 calendar days**.
- **Remediation & coordinated disclosure:** privilege-escalation, remote-execution, and credential-disclosure fixes are prioritized ahead of feature work; advisory details are published after a patched release is available.
