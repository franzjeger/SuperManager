//! Structured error types for the engine's critical paths.
//!
//! `anyhow::Error` is fine for one-off scripts and prototyping
//! but loses information at the trust boundary: when a daemon
//! handler converts an error to an RPC `Response::err`, all the
//! caller sees is a string. The Mac app can't tell "wrong
//! password" apart from "network timeout" apart from
//! "configuration file corrupt" — they all surface as identical
//! red banners.
//!
//! We use this enum on the paths where the GUI actually wants to
//! make different decisions per error kind:
//!   - SSH credential testing (auth-fail vs network-fail vs
//!     remote-disconnect)
//!   - Findings-store IO (lock contention vs disk full vs
//!     malformed JSON)
//!   - DNS health (resolver timeout vs missing tool)
//!
//! Outside those critical paths, `anyhow` is fine.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    // --- SSH operations ---
    /// Authentication rejected — wrong password, wrong key, or
    /// account locked. UI should prompt the operator for new creds.
    #[error("SSH auth failed: {reason}")]
    SshAuth { reason: String },

    /// Could not reach the host (no route, refused connection,
    /// timeout). UI should suggest checking connectivity.
    #[error("SSH network error: {reason}")]
    SshNetwork { reason: String },

    /// Handshake completed but the remote disconnected before
    /// sending an auth result.
    #[error("SSH session closed unexpectedly: {reason}")]
    SshDisconnected { reason: String },

    // --- Findings store ---
    /// Path / filesystem failure (read, write, rename). Disk full,
    /// permission denied, or invalid path component.
    #[error("findings store IO error: {reason}")]
    FindingsIo { reason: String },

    /// Stored JSON was malformed. Either the schema drifted or the
    /// file was hand-edited. UI should suggest restoring from a
    /// recent backup.
    #[error("findings store JSON parse: {reason}")]
    FindingsParse { reason: String },

    /// Caller passed a slug that fails validation (path traversal
    /// attempt, illegal characters, too long).
    #[error("invalid scope slug: {reason}")]
    InvalidScope { reason: String },

    // --- External tools ---
    /// A required CLI tool isn't installed. UI should link to
    /// the Settings → Integrations panel for install instructions.
    #[error("required tool not installed: {tool}")]
    ToolMissing { tool: String },

    /// External tool ran but reported an error. `output` is the
    /// stderr text up to ~1 KB.
    #[error("{tool} failed: {output}")]
    ToolFailed { tool: String, output: String },

    // --- PDF / report ---
    /// Pandoc is present but no PDF engine (tectonic / xelatex /
    /// pdflatex / wkhtmltopdf / weasyprint) is on PATH. The Mac
    /// client treats this specially — a WebKit-based fallback
    /// path runs locally, so the operator never sees a hard error
    /// dialog. The structured kind lets the Swift side recognise
    /// this case instead of regex-matching the error message.
    #[error("no PDF engine on PATH (pandoc alone cannot produce PDF)")]
    PdfEngineMissing,

    // --- Generic fallback for paths we haven't structured yet ---
    /// Wrap an `anyhow::Error` for callers still on the
    /// unstructured path. Bridges old + new code during the
    /// gradual migration.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl EngineError {
    /// Maps the error to a JSON-RPC error code so the Swift side
    /// can switch on category (not just message).
    /// Codes follow the JSON-RPC convention: -32000..-32099
    /// reserved for server-defined errors.
    #[must_use]
    pub fn rpc_code(&self) -> i32 {
        match self {
            Self::SshAuth { .. }         => -32010,
            Self::SshNetwork { .. }      => -32011,
            Self::SshDisconnected { .. } => -32012,
            Self::FindingsIo { .. }      => -32020,
            Self::FindingsParse { .. }   => -32021,
            Self::InvalidScope { .. }    => -32022,
            Self::ToolMissing { .. }     => -32030,
            Self::ToolFailed { .. }      => -32031,
            Self::PdfEngineMissing       => -32040,
            Self::Other(_)               => -32099,
        }
    }

    /// Stable machine-readable category string. The Mac client
    /// matches on this rather than on the human message so that
    /// rephrasing the error text never silently breaks the UI's
    /// per-category branching.
    ///
    /// Format: `lower_snake_case`, never localised.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SshAuth { .. }         => "ssh_auth",
            Self::SshNetwork { .. }      => "ssh_network",
            Self::SshDisconnected { .. } => "ssh_disconnected",
            Self::FindingsIo { .. }      => "findings_io",
            Self::FindingsParse { .. }   => "findings_parse",
            Self::InvalidScope { .. }    => "invalid_scope",
            Self::ToolMissing { .. }     => "tool_missing",
            Self::ToolFailed { .. }      => "tool_failed",
            Self::PdfEngineMissing       => "pdf_engine_missing",
            Self::Other(_)               => "other",
        }
    }

    /// True for errors the operator can fix by installing /
    /// configuring something, vs. transient (retry-now) and
    /// truly-fatal kinds. UI uses this to pick between
    /// "Try again", "Open Settings", and a plain "Dismiss" button.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            Self::ToolMissing { .. } | Self::PdfEngineMissing | Self::SshAuth { .. }
        )
    }
}
