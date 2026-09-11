//! Preflight checks for editable drafts; this is not a vendor syntax compiler.

use anyhow::{bail, ensure};

/// Catch incomplete drafts before opening a device session.
pub fn validate(device_type: &str, config: &str) -> anyhow::Result<usize> {
    ensure!(!config.trim().is_empty(), "The draft is empty");
    ensure!(
        config.len() <= 1024 * 1024,
        "The draft exceeds the 1 MB preflight limit"
    );
    ensure!(
        !config.contains("```"),
        "Remove Markdown fences from the device commands"
    );
    ensure!(
        !config
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
        "The draft contains control characters"
    );
    let mut stack = Vec::new();
    let mut commands = 0;
    for (index, line) in config.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        commands += 1;
        let upper = line.to_ascii_uppercase();
        ensure!(
            ![
                "CHANGEME",
                "CHANGE_ME",
                "CHANGE-ME",
                "YOUR_",
                "<PASSWORD>",
                "<IP_ADDRESS>"
            ]
            .iter()
            .any(|p| upper.contains(p)),
            "Unfilled placeholder on line {}",
            index + 1
        );
        if device_type == "FortiGate" {
            let verb = line.split_whitespace().next().unwrap_or("");
            match verb {
                "config" if line.split_whitespace().count() >= 2 => stack.push("config"),
                "edit"
                    if stack.last() == Some(&"config") && line.split_whitespace().count() >= 2 =>
                {
                    stack.push("edit")
                }
                "next" if line == "next" && stack.last() == Some(&"edit") => {
                    stack.pop();
                }
                "end" if line == "end" && !stack.is_empty() => {
                    if stack.last() == Some(&"edit") {
                        stack.pop();
                    }
                    ensure!(
                        stack.pop() == Some("config"),
                        "Unmatched end on line {}",
                        index + 1
                    );
                }
                "set" | "unset" | "append" | "select" | "unselect" | "delete" | "move"
                | "rename"
                    if !stack.is_empty() && line.split_whitespace().count() >= 2 => {}
                _ => bail!(
                    "Line {} is outside the supported FortiGate configuration structure: {verb}",
                    index + 1
                ),
            }
        }
    }
    ensure!(commands > 0, "The draft contains no device commands");
    ensure!(
        stack.is_empty(),
        "The FortiGate draft has unclosed config/edit blocks"
    );
    ensure!(
        matches!(device_type, "FortiGate" | "UniFi"),
        "Unsupported target device type"
    );
    if device_type == "UniFi" {
        if is_controller_json(config) {
            let _: serde_json::Value = serde_json::from_str(config)?;
            return Ok(commands);
        }
        // Parse only. The local shell does not execute the draft or substitutions.
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(config.as_bytes())?;
        ensure!(
            std::process::Command::new("/bin/sh")
                .arg("-n")
                .arg(file.path())
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()?
                .success(),
            "The UniFi draft is not valid POSIX shell syntax"
        );
    }
    Ok(commands)
}

pub fn is_controller_json(config: &str) -> bool {
    config.trim_start().starts_with(['{', '['])
}

pub fn validate_for_push(device_type: &str, config: &str) -> anyhow::Result<usize> {
    let count = validate(device_type, config)?;
    ensure!(device_type != "UniFi" || !is_controller_json(config),
        "UniFi controller JSON is export-only. SSH push requires reviewed, device-specific shell commands.");
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_and_misplaced_fortigate_commands_are_rejected() {
        assert!(validate(
            "FortiGate",
            "config system interface\nedit port1\nset alias office\nnext\nend"
        )
        .is_ok());
        assert!(validate("FortiGate", "config system interface\nedit port1\nconfig secondaryip\nedit 1\nset ip 10.0.0.2/24\nnext\nend\nnext\nend").is_ok());
        for config in [
            "# empty",
            "set hostname x",
            "config system global\nset hostname x",
            "next",
            "config system global\nset hostname YOUR_HOST\nend",
            "```\nconfig system global\n```",
            "Here is the configuration:",
        ] {
            assert!(validate("FortiGate", config).is_err(), "{config}");
        }
    }

    #[test]
    fn shell_syntax_is_checked_without_execution() {
        assert!(validate("UniFi", "exit 99\necho $(exit 42)").is_ok());
        assert!(validate("UniFi", "if true; then echo missing_fi").is_err());
    }

    #[test]
    fn controller_json_can_be_reviewed_but_never_sent_to_a_shell() {
        let json = r#"{"networks": [{"name": "Office"}]}"#;
        assert!(validate("UniFi", json).is_ok());
        assert!(validate_for_push("UniFi", json).is_err());
        assert!(validate("UniFi", "{broken}").is_err());
        assert!(validate_for_push(
            "FortiGate",
            "config system global\nset hostname CHANGE-ME\nend"
        )
        .is_err());
    }
}
