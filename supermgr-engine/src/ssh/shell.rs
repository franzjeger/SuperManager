//! FortiOS interactive command driver. A returned prompt is transport-level
//! acknowledgment, not proof of application state or transactional rollback.
use std::time::Duration;
use tokio::time::{timeout_at, Instant};

const MAX_TRANSCRIPT: usize = 4 * 1024 * 1024;
const MAX_RESPONSE: usize = 256 * 1024;

pub(super) enum Event {
    Data(Vec<u8>),
    Closed,
    Rejected,
    Other,
}

#[async_trait::async_trait]
pub(super) trait ShellIo: Send {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), ()>;
    async fn recv(&mut self) -> Event;
}

#[derive(Debug)]
pub(crate) struct ShellFailure {
    pub acknowledged_lines: usize,
    pub line: Option<usize>,
    pub reason: &'static str,
}
impl std::fmt::Display for ShellFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({} lines acknowledged",
            self.reason, self.acknowledged_lines
        )?;
        if let Some(line) = self.line {
            write!(
                f,
                "; stopped at line {line}; that line may have been applied"
            )?;
        }
        write!(f, ")")
    }
}
impl std::error::Error for ShellFailure {}
impl ShellFailure {
    pub(super) fn setup(reason: &'static str) -> Self {
        Self {
            acknowledged_lines: 0,
            line: None,
            reason,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ShellOutput {
    pub transcript: String,
    pub acknowledged_lines: usize,
}

fn hostname(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 255
        && text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}
/// Match the entire final line, never a '#' embedded in command output.
fn prompt(text: &str) -> Option<&str> {
    let tail = text.rsplit('\n').next()?.trim();
    let body = tail.strip_suffix('#')?.trim_end();
    let name = if let Some((name, context)) = body.split_once(" (") {
        let context = context.strip_suffix(')')?;
        if context.is_empty() || context.contains(['\r', '\n', '#', '$']) {
            return None;
        }
        name
    } else {
        body
    };
    hostname(name).then_some(name)
}
fn password_prompt(text: &str) -> bool {
    let tail = text.rsplit('\n').next().unwrap_or("").trim();
    tail.eq_ignore_ascii_case("password:")
        || tail.eq_ignore_ascii_case("please input your password:")
}
fn device_error(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    text.lines().any(|line| {
        [
            "command fail",
            "command parse error",
            "unknown action",
            "ambiguous command",
            "permission denied",
            "incomplete command",
            "value parse error",
            "node_check_object fail",
        ]
        .iter()
        .any(|marker| line.trim_start().starts_with(marker))
    })
}
fn new_hostname(line: &str) -> Option<&str> {
    let name = line
        .trim()
        .strip_prefix("set hostname ")?
        .trim()
        .trim_matches('"');
    hostname(name).then_some(name)
}
fn valid_line(line: &str) -> bool {
    !line.chars().any(|c| c.is_control() && c != '\t')
}

struct Driver<'a, T> {
    io: &'a mut T,
    deadline: Instant,
    transcript: Vec<u8>,
    acknowledged: usize,
    line: Option<usize>,
}
impl<T: ShellIo> Driver<'_, T> {
    fn fail(&self, reason: &'static str) -> ShellFailure {
        ShellFailure {
            acknowledged_lines: self.acknowledged,
            line: self.line,
            reason,
        }
    }
    async fn send(&mut self, line: &str) -> Result<(), ShellFailure> {
        if Instant::now() >= self.deadline {
            return Err(self.fail("SSH command deadline exceeded"));
        }
        let bytes = format!("{line}\n");
        match timeout_at(self.deadline, self.io.send(bytes.as_bytes())).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(())) => Err(self.fail("SSH command write failed")),
            Err(_) => Err(self.fail("SSH command write timed out")),
        }
    }
    async fn response(
        &mut self,
        expected: Option<&str>,
        renamed: Option<&str>,
        mut password: Option<&str>,
    ) -> Result<String, ShellFailure> {
        let mut response = Vec::new();
        loop {
            if Instant::now() >= self.deadline {
                return Err(self.fail("SSH prompt timed out"));
            }
            let event = timeout_at(self.deadline, self.io.recv())
                .await
                .map_err(|_| self.fail("SSH prompt timed out"))?;
            match event {
                Event::Closed => return Err(self.fail("SSH channel closed before acknowledgment")),
                Event::Rejected => {
                    return Err(self.fail("SSH request rejected or command exited unsuccessfully"))
                }
                Event::Other => continue,
                Event::Data(data) => {
                    if self.transcript.len().saturating_add(data.len()) > MAX_TRANSCRIPT
                        || response.len().saturating_add(data.len()) > MAX_RESPONSE
                    {
                        return Err(self.fail("SSH output limit exceeded"));
                    }
                    self.transcript.extend_from_slice(&data);
                    response.extend_from_slice(&data);
                }
            }
            let text = String::from_utf8_lossy(&response);
            if device_error(&text) {
                return Err(
                    self.fail("FortiOS rejected a command; inspect the device before retrying")
                );
            }
            if password_prompt(&text) {
                let secret = password
                    .take()
                    .ok_or_else(|| self.fail("Unexpected password prompt"))?;
                self.send(secret).await?;
                response.clear();
                continue;
            }
            if let Some(name) = prompt(&text) {
                if expected.is_none() || expected == Some(name) || renamed == Some(name) {
                    return Ok(name.to_owned());
                }
            }
        }
    }
}

/// All command writes and waits share one deadline. Secrets are only sent in
/// response to a password prompt, never appended to the command list.
pub(super) async fn run<T: ShellIo>(
    io: &mut T,
    lines: &[&str],
    password: Option<&str>,
    duration: Duration,
) -> Result<ShellOutput, ShellFailure> {
    if lines.iter().any(|line| !valid_line(line)) || password.is_some_and(|p| !valid_line(p)) {
        return Err(ShellFailure::setup(
            "Control characters are not allowed in shell input",
        ));
    }
    let mut driver = Driver {
        io,
        deadline: Instant::now() + duration,
        transcript: Vec::new(),
        acknowledged: 0,
        line: None,
    };
    let mut name = driver.response(None, None, None).await?;
    for (index, line) in lines.iter().enumerate() {
        driver.line = Some(index + 1);
        driver.send(line).await?;
        // Only the final generate-key command may ask for the one-off secret.
        // A password prompt during configuration is always an error.
        let response_password = if index + 1 == lines.len() {
            password
        } else {
            None
        };
        name = driver
            .response(Some(&name), new_hostname(line), response_password)
            .await?;
        driver.acknowledged += 1;
    }
    Ok(ShellOutput {
        transcript: String::from_utf8_lossy(&driver.transcript).into_owned(),
        acknowledged_lines: driver.acknowledged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Scripted {
        events: VecDeque<Event>,
        writes: Vec<String>,
        fail_write: Option<usize>,
        hang_write: bool,
    }
    impl Scripted {
        fn new(events: Vec<Event>) -> Self {
            Self {
                events: events.into(),
                writes: vec![],
                fail_write: None,
                hang_write: false,
            }
        }
    }
    #[async_trait::async_trait]
    impl ShellIo for Scripted {
        async fn send(&mut self, bytes: &[u8]) -> Result<(), ()> {
            if self.hang_write {
                std::future::pending::<()>().await;
            }
            if self.fail_write == Some(self.writes.len()) {
                return Err(());
            }
            self.writes.push(String::from_utf8(bytes.to_vec()).unwrap());
            Ok(())
        }
        async fn recv(&mut self) -> Event {
            match self.events.pop_front() {
                Some(event) => event,
                None => std::future::pending().await,
            }
        }
    }
    fn data(text: &str) -> Event {
        Event::Data(text.as_bytes().to_vec())
    }
    const DEADLINE: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn fragmented_prompts_and_hostname_change_acknowledge_exact_lines() {
        let mut io = Scripted::new(vec![
            data("Welcome\r\nFG"),
            data("T # "),
            data("config system global\r\nFGT (global) # "),
            data("set hostname BRANCH\r\nBRANCH (global) # "),
            data("end\r\nBRANCH # "),
        ]);
        let out = run(
            &mut io,
            &["config system global", "set hostname BRANCH", "end"],
            None,
            DEADLINE,
        )
        .await
        .unwrap();
        assert_eq!(out.acknowledged_lines, 3);
        assert_eq!(
            io.writes,
            ["config system global\n", "set hostname BRANCH\n", "end\n"]
        );
    }
    #[tokio::test]
    async fn initial_eof_rejection_or_timeout_never_sends_commands() {
        for events in [
            vec![Event::Closed],
            vec![Event::Rejected],
            vec![Event::Other],
            vec![data("banner # inside text")],
        ] {
            let mut io = Scripted::new(events);
            let err = run(&mut io, &["delete target"], None, DEADLINE)
                .await
                .unwrap_err();
            assert_eq!(err.acknowledged_lines, 0);
            assert_eq!(err.line, None);
            assert!(io.writes.is_empty());
        }
    }
    #[tokio::test]
    async fn eof_and_timeout_after_write_report_uncertain_line_and_stop() {
        for tail in [vec![Event::Closed], vec![Event::Rejected], vec![]] {
            let mut events = vec![data("FGT # "), data("FGT (global) # ")];
            events.extend(tail);
            let mut io = Scripted::new(events);
            let err = run(
                &mut io,
                &["config system global", "set hostname secret-target", "end"],
                None,
                DEADLINE,
            )
            .await
            .unwrap_err();
            assert_eq!(err.acknowledged_lines, 1);
            assert_eq!(err.line, Some(2));
            assert_eq!(io.writes.len(), 2);
            assert!(!err.to_string().contains("secret-target"));
            assert!(err.to_string().contains("may have been applied"));
        }
    }
    #[tokio::test]
    async fn failed_and_blocked_writes_are_bounded_and_abort() {
        for hanging in [false, true] {
            let mut io = Scripted::new(vec![data("FGT # ")]);
            io.hang_write = hanging;
            io.fail_write = Some(0);
            let err = run(&mut io, &["first", "must not send"], None, DEADLINE)
                .await
                .unwrap_err();
            assert_eq!(err.acknowledged_lines, 0);
            assert_eq!(err.line, Some(1));
            assert!(io.writes.is_empty());
        }
    }
    #[tokio::test]
    async fn fragmented_fortios_error_stops_before_next_command_without_leaking_output() {
        let mut io = Scripted::new(vec![
            data("FGT # "),
            data("Command fa"),
            data("il. secret echoed here\r\nFGT # "),
        ]);
        let err = run(&mut io, &["first", "must not send"], None, DEADLINE)
            .await
            .unwrap_err();
        assert_eq!(io.writes, ["first\n"]);
        assert_eq!(err.acknowledged_lines, 0);
        assert!(!err.to_string().contains("secret"));
    }
    #[tokio::test]
    async fn embedded_prompt_or_error_words_in_echo_do_not_acknowledge() {
        let mut io = Scripted::new(vec![
            data("FGT # "),
            data("set comments \"Command fail # password:\"\r\n"),
            Event::Closed,
        ]);
        let err = run(&mut io, &["first", "must not send"], None, DEADLINE)
            .await
            .unwrap_err();
        assert_eq!(io.writes.len(), 1);
        assert_eq!(err.reason, "SSH channel closed before acknowledgment");
    }
    #[tokio::test]
    async fn wrong_hostname_prompt_is_not_acknowledgment() {
        let mut io = Scripted::new(vec![data("FGT # "), data("OTHER # "), Event::Closed]);
        assert!(run(&mut io, &["first", "second"], None, DEADLINE)
            .await
            .is_err());
        assert_eq!(io.writes.len(), 1);
    }
    #[tokio::test]
    async fn config_password_prompt_is_an_error_and_no_next_line_is_sent() {
        let mut io = Scripted::new(vec![data("FGT # "), data("Password: ")]);
        let err = run(&mut io, &["first", "must not send"], None, DEADLINE)
            .await
            .unwrap_err();
        assert_eq!(err.reason, "Unexpected password prompt");
        assert_eq!(io.writes.len(), 1);
    }
    #[tokio::test]
    async fn password_is_sent_only_when_requested_and_token_is_not_a_prompt() {
        let mut io = Scripted::new(vec![
            data("FGT # "),
            data("Password: "),
            data("New API key: token\r\n"),
            data("FGT # "),
        ]);
        let out = run(
            &mut io,
            &["execute api-user generate-key admin"],
            Some("test-password"),
            DEADLINE,
        )
        .await
        .unwrap();
        assert_eq!(
            io.writes,
            ["execute api-user generate-key admin\n", "test-password\n"]
        );
        assert_eq!(out.acknowledged_lines, 1);
        assert!(out.transcript.contains("New API key: token"));
        let mut no_prompt =
            Scripted::new(vec![data("FGT # "), data("New API key: token\r\nFGT # ")]);
        run(
            &mut no_prompt,
            &["generate"],
            Some("must-not-send"),
            DEADLINE,
        )
        .await
        .unwrap();
        assert_eq!(no_prompt.writes, ["generate\n"]);
    }
    #[tokio::test]
    async fn password_cannot_be_retried_or_used_by_an_earlier_command() {
        for (lines, events) in [
            (
                vec!["generate"],
                vec![data("FGT # "), data("Password: "), data("Password: ")],
            ),
            (
                vec!["first", "generate"],
                vec![data("FGT # "), data("Password: ")],
            ),
        ] {
            let mut io = Scripted::new(events);
            assert!(run(&mut io, &lines, Some("secret"), DEADLINE)
                .await
                .is_err());
            assert!(io.writes.len() <= 2);
        }
    }
    #[tokio::test]
    async fn oversized_output_and_control_characters_fail_closed() {
        let mut io = Scripted::new(vec![
            data("FGT # "),
            Event::Data(vec![b'x'; MAX_RESPONSE + 1]),
        ]);
        assert!(run(&mut io, &["first", "second"], None, DEADLINE)
            .await
            .is_err());
        assert_eq!(io.writes.len(), 1);
        for bad in ["hello\nexecute reboot", "hello\r", "hello\0", "\x1b[2J"] {
            let mut io = Scripted::new(vec![data("FGT # ")]);
            assert!(run(&mut io, &[bad], None, DEADLINE).await.is_err());
            assert!(io.writes.is_empty());
        }
    }
    #[tokio::test]
    async fn expired_deadline_cannot_be_bypassed_by_immediately_ready_events() {
        let mut io = Scripted::new(vec![data("FGT # "), data("FGT # ")]);
        assert!(run(&mut io, &["must not send"], None, Duration::ZERO)
            .await
            .is_err());
        assert!(io.writes.is_empty());
    }
}
