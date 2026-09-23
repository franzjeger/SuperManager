//! What a VPN client process printed, read for as long as it runs.
//!
//! # Why every client's output goes through here
//!
//! The OpenVPN, Azure and SSL VPN backends start a client with its stdout
//! and stderr piped. A pipe nobody reads fills up — a few kilobytes on
//! Windows — and the client then blocks on its next log line. The OpenVPN
//! backend never read its pipes at all, so a verbose handshake could stall
//! before the tunnel came up; the Azure backend stopped reading once it
//! was connected, so its tunnel froze at the first renegotiation that
//! logged enough. Neither failure said anything.
//!
//! [`capture`] reads both streams until the process exits, whatever else
//! is going on. It keeps the last lines, so a failed connect can say what
//! the client said rather than "exited with code 1", and forwards every
//! line to whoever is watching the bring-up. The watcher can stop
//! listening at any time; the reading does not stop with it.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use tokio::{
    io::{AsyncBufReadExt as _, AsyncRead, BufReader},
    process::Child,
    sync::mpsc,
};
use tracing::{debug, warn};

/// How many lines of output to keep for an error message.
const TAIL_LINES: usize = 60;

/// The most recent lines a client printed, stdout and stderr interleaved
/// in the order they arrived.
#[derive(Clone, Default)]
pub struct Tail(Arc<Mutex<VecDeque<String>>>);

impl Tail {
    fn push(&self, line: String) {
        if let Ok(mut lines) = self.0.lock() {
            if lines.len() == TAIL_LINES {
                lines.pop_front();
            }
            lines.push_back(line);
        }
    }

    /// Everything kept, oldest first.
    pub fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .map(|lines| lines.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The line that best explains a failure, if the client printed one.
    pub fn reason(&self) -> Option<String> {
        failure_line(&self.lines())
    }

    /// Put everything kept in the service's log, for a connect that failed.
    ///
    /// The operator is shown one line; what led up to it is often the
    /// explanation, and without it a failure that happens only on someone
    /// else's machine cannot be told apart from any other.
    pub fn log_failure(&self, client: &str) {
        let lines = self.lines();
        if !lines.is_empty() {
            warn!(target: "vpn_client", "{client} said, before it failed:\n{}", lines.join("\n"));
        }
    }
}

/// Start reading `child`'s stdout and stderr, and return what they say.
///
/// The receiver gets every line; drop it once the bring-up no longer
/// cares. The pipes keep being read until the process exits either way.
pub fn capture(child: &mut Child) -> (Tail, mpsc::UnboundedReceiver<String>) {
    let tail = Tail::default();
    let (tx, rx) = mpsc::unbounded_channel();
    if let Some(stdout) = child.stdout.take() {
        drain(stdout, tail.clone(), tx.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        drain(stderr, tail.clone(), tx);
    }
    (tail, rx)
}

fn drain<R>(stream: R, tail: Tail, tx: mpsc::UnboundedSender<String>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::with_capacity(256);
        loop {
            buf.clear();
            // Bytes, not `lines()`: a client printing one line that is not
            // UTF-8 — an adapter name in the system code page is enough —
            // would end a `lines()` loop with an error, and the pipe would
            // fill behind it all the same.
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let line = String::from_utf8_lossy(&buf)
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            if line.is_empty() {
                continue;
            }
            debug!(target: "vpn_client", "{line}");
            tail.push(line.clone());
            // Nobody listening is normal once the tunnel is up.
            let _ = tx.send(line);
        }
    });
}

/// Why a client that was carrying a tunnel stopped, for the operator.
pub fn exit_reason(client: &str, status: std::process::ExitStatus, tail: &Tail) -> String {
    match tail.reason() {
        Some(reason) => format!("The {client} client stopped: {reason}"),
        None => format!("The {client} client stopped unexpectedly ({status})"),
    }
}

/// Pick the line that says why a client gave up.
///
/// Clients print a lot on the way to failing — OpenVPN's banner, library
/// versions, every retry. The explanation is the last line that reads like
/// one, so search from the end. OpenVPN ends every fatal error with the
/// same "Exiting due to fatal error", which explains nothing: it is only
/// the answer when no line before it does. Its "Note:" lines are never the
/// answer — every 2.6 client starts with one about cipher negotiation that
/// has "failed" in it. Nothing matching means the client's output has no
/// explanation to offer, and the caller says what it knows instead.
pub fn failure_line(lines: &[String]) -> Option<String> {
    const MARKERS: &[&str] = &[
        "AUTH_FAILED",
        "Options error",
        "Cannot ",
        "cannot ",
        "Could not",
        "could not",
        "ERROR",
        "Error",
        "error:",
        "FATAL",
        "Fatal",
        "failed",
        "Failed",
        "refused",
        "No such file",
    ];
    const LAST_RESORT: &[&str] = &["Exiting due to"];
    let last_with = |markers: &[&str]| {
        lines
            .iter()
            .rev()
            .map(|line| clean(line))
            .filter(|line| !line.starts_with("Note:"))
            .find(|line| markers.iter().any(|m| line.contains(m)))
    };
    last_with(MARKERS).or_else(|| last_with(LAST_RESORT))
}

/// Drop the decoration clients put in front of a message.
///
/// OpenVPN prefixes a timestamp unless told not to, and both it and
/// openfortivpn tag the level ("ERROR:  "). What the operator needs is the
/// sentence after them.
fn clean(line: &str) -> String {
    let mut s = line.trim();
    // "2024-05-01 10:00:00 " — a date, a time, then the message.
    let mut parts = s.splitn(3, ' ');
    if let (Some(date), Some(time), Some(rest)) = (parts.next(), parts.next(), parts.next()) {
        let looks_dated = date.len() == 10 && date.as_bytes().get(4) == Some(&b'-');
        let looks_timed = time.len() >= 8 && time.as_bytes().get(2) == Some(&b':');
        if looks_dated && looks_timed {
            s = rest.trim_start();
        }
    }
    for tag in ["ERROR:", "WARN:", "FATAL:", "err:"] {
        if let Some(rest) = s.strip_prefix(tag) {
            s = rest.trim_start();
        }
    }
    s.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_owned).collect()
    }

    #[test]
    fn the_last_explanation_wins_over_the_banner() {
        let out = lines(
            "OpenVPN 2.6.12 [SSL (OpenSSL)] [LZO] [LZ4]\n\
             library versions: OpenSSL 3.3.1\n\
             TCP/UDP: Preserving recently used remote address\n\
             Cannot resolve host address: vpn.example.invalid:1194 (No such host is known.)\n\
             SIGUSR1[soft,init_instance] received, process restarting",
        );
        assert_eq!(
            failure_line(&out).as_deref(),
            Some("Cannot resolve host address: vpn.example.invalid:1194 (No such host is known.)")
        );
    }

    #[test]
    fn a_timestamp_and_level_tag_are_not_part_of_the_reason() {
        let out = lines("2024-05-01 10:00:00 ERROR:  Could not authenticate to gateway.");
        assert_eq!(
            failure_line(&out).as_deref(),
            Some("Could not authenticate to gateway.")
        );
    }

    #[test]
    fn a_fatal_errors_own_line_wins_over_its_generic_trailer() {
        let out = lines(
            "OpenVPN 2.6.22\n\
             Cannot load inline certificate file\n\
             Exiting due to fatal error",
        );
        assert_eq!(
            failure_line(&out).as_deref(),
            Some("Cannot load inline certificate file")
        );

        // With nothing more specific said, the trailer is still better
        // than no reason at all.
        let out = lines(
            "OpenVPN 2.6.22 [git:v2.6.22] Windows [SSL (OpenSSL)] [DCO]\n\
             There are no TAP-Windows, Wintun or ovpn-dco adapters on this system.\n\
             Exiting due to fatal error",
        );
        assert_eq!(
            failure_line(&out).as_deref(),
            Some("Exiting due to fatal error")
        );
    }

    #[test]
    fn output_with_no_explanation_offers_none() {
        let out = lines("OpenVPN 2.6.12\nTCP/UDP: Preserving recently used remote address");
        assert_eq!(failure_line(&out), None);
    }

    #[test]
    fn openvpns_notes_are_not_complaints() {
        let out = lines(
            "Note: --cipher is not set. OpenVPN versions before 2.5 defaulted to BF-CBC as \
             fallback when cipher negotiation failed in this case.\n\
             OpenVPN 2.6.22 [git:v2.6.22/c9b790f5b9e8ebca] Windows [SSL (OpenSSL)] [DCO]\n\
             MANAGEMENT: CMD 'hold release'",
        );
        assert_eq!(failure_line(&out), None);
    }

    #[test]
    fn the_tail_keeps_only_the_most_recent_lines() {
        let tail = Tail::default();
        for i in 0..(TAIL_LINES + 5) {
            tail.push(format!("line {i}"));
        }
        let kept = tail.lines();
        assert_eq!(kept.len(), TAIL_LINES);
        assert_eq!(kept.first().map(String::as_str), Some("line 5"));
    }
}
