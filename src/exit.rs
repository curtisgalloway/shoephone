// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! Exit statuses and the `--skill` flag for a CLI that programs drive.
//!
//! See the `cli-conventions` skill for the reasoning. Under 100 is portable;
//! 100-124 is this tool's own. Never emit 125-255: 126/127 are shell
//! conventions, 128+N means "killed by signal N", 255 is ssh's own code.

// Remove once every status and helper here is actually used; a fresh project
// otherwise builds with dead-code warnings for the codes it has not reached yet.
#![allow(dead_code)]

use std::process::ExitCode;

/// The tool's own agent-facing document, compiled in so it cannot drift from
/// the binary that implements it.
pub const SKILL: &str = include_str!("../SKILL.md");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    /// Ran fine; the answer is empty or negative.
    Empty = 1,

    // 2-9: deterministic. An identical retry is futile.
    Usage = 2,
    /// A binary, config file or input was not found.
    Precondition = 3,
    /// DNS failure, connection refused, no route.
    Unreachable = 4,

    // 10s: authentication and permission.
    /// Fixable locally; retry after remediation.
    AuthRemediable = 10,
    /// A person must act; stop.
    AuthNeedsHuman = 11,
    /// Denied by rule or policy.
    AuthDenied = 12,

    // 20s: transient. Retry.
    /// Nothing was done; retry is free.
    RetryClean = 20,
    /// Partially done; reconcile before retrying.
    RetryPartial = 21,
    /// No response within budget; outcome UNKNOWN, check state first.
    RetryUnknown = 22,
    /// Quota reset or maintenance window; come back later.
    RetryLater = 23,

    // 30s: permanent. The request itself must change.
    Permanent = 30,
}

impl From<Status> for ExitCode {
    fn from(s: Status) -> Self {
        ExitCode::from(s as u8)
    }
}

impl Status {
    /// True when a caller may reasonably try the same call again.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Status::AuthRemediable
                | Status::RetryClean
                | Status::RetryPartial
                | Status::RetryUnknown
                | Status::RetryLater
        )
    }
}

/// Translate a child process's status into this tool's vocabulary. Never
/// propagate a subprocess code unchanged — the caller cannot tell whose
/// failure it is reading.
pub fn from_child(code: Option<i32>) -> Status {
    match code {
        Some(0) => Status::Ok,
        // Command not found / not executable, from the shell.
        Some(126) | Some(127) => Status::Precondition,
        // ssh's own failure, not the remote command's. Inspect stderr to tell
        // a transport failure from an authentication one.
        Some(255) => Status::Unreachable,
        Some(_) => Status::RetryUnknown,
        // No code at all means a signal killed it.
        None => Status::RetryUnknown,
    }
}

// Wiring, for src/main.rs:
//
//     mod exit;
//     use exit::{Status, SKILL, VERSION};
//     use std::process::ExitCode;
//
//     fn main() -> ExitCode {
//         if std::env::args().any(|a| a == "--skill") {
//             print!("{}", SKILL.replace("{{VERSION}}", VERSION));
//             return Status::Ok.into();
//         }
//         run().into()
//     }
//
// Return a Status from every path rather than calling process::exit, so the
// contract is visible in the signatures and the compiler checks it.
