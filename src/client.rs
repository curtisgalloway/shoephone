// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The CLI's view of the daemon: blocking HTTP, typed replies, and the
//! translation of every failure into the exit-code vocabulary.

use std::fmt;
use std::time::Duration;

use serde::de::DeserializeOwned;
use ureq::Agent;

use crate::api::*;
use crate::exit::Status;

#[derive(Debug)]
pub enum Error {
    /// DNS, connect, TLS, or a resolve/connect timeout: the daemon was
    /// never reached, so nothing was done.
    Unreachable(String),
    /// The connection failed, or timed out, at a point after the request
    /// may already have left this process. The daemon may have acted on
    /// it; there is no way to tell from here.
    Ambiguous(String),
    /// The daemon answered with a refusal.
    Daemon { http: u16, reply: ErrorReply },
    /// The daemon answered something this client does not understand.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unreachable(e) => write!(f, "daemon unreachable: {e}"),
            Error::Ambiguous(e) => write!(
                f,
                "the daemon may have acted on this request; the outcome is unknown: {e}; check `shoephone status` before retrying"
            ),
            Error::Daemon { reply, .. } => write!(f, "{} ({})", reply.error, reply.code),
            Error::Protocol(e) => write!(f, "unexpected reply from daemon: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// The exit status this failure deserves. The refusal codes are the
    /// daemon's `ErrorReply::code` strings.
    pub fn status(&self) -> Status {
        match self {
            Error::Unreachable(_) => Status::Unreachable,
            Error::Ambiguous(_) => Status::RetryUnknown,
            Error::Protocol(_) => Status::RetryUnknown,
            Error::Daemon { http, reply } => match reply.code.as_str() {
                "unknown_host" | "bad_key" | "reason_required" => Status::Permanent,
                "busy" => Status::RetryClean,
                "cooldown" | "rate_capped" => Status::RetryLater,
                "no_window" | "no_such_request" => Status::AuthNeedsHuman,
                "key_mismatch" | "nonce_mismatch" | "scope_mismatch" => Status::AuthDenied,
                _ if *http >= 500 => Status::RetryUnknown,
                _ => Status::Permanent,
            },
        }
    }
}

impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        match e {
            ureq::Error::HostNotFound
            | ureq::Error::ConnectionFailed
            | ureq::Error::Tls(_)
            | ureq::Error::Rustls(_) => Error::Unreachable(e.to_string()),
            // Resolve and Connect fire before this process has sent a
            // single byte of the request, so the daemon was never reached.
            // Every later phase -- sending the body, waiting on the
            // response, reading it back -- can time out after the daemon
            // already acted on the request.
            ureq::Error::Timeout(ureq::Timeout::Resolve | ureq::Timeout::Connect) => {
                Error::Unreachable(e.to_string())
            }
            // A refused connection (nobody listening, or a firewall
            // rejecting outright) fails synchronously in the OS before any
            // request bytes exist to send; every other I/O error can
            // happen mid-request, after bytes are already on the wire.
            ureq::Error::Io(ref io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
                Error::Unreachable(e.to_string())
            }
            ureq::Error::Timeout(_) | ureq::Error::Io(_) => Error::Ambiguous(e.to_string()),
            other => Error::Protocol(other.to_string()),
        }
    }
}

pub struct Client {
    agent: Agent,
    base: String,
}

impl Client {
    pub fn new(base: &str) -> Self {
        Self::with_timeout(base, Duration::from_secs(15))
    }

    /// Like [`Client::new`], but with an explicit global timeout instead of
    /// the default 15 seconds. For tests that need a short one.
    pub fn with_timeout(base: &str, timeout: Duration) -> Self {
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .user_agent(concat!("shoephone/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: config.into(),
            base: base.trim_end_matches('/').to_owned(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let resp = self.agent.get(self.url(path)).call()?;
        decode(resp)
    }

    fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl serde::Serialize,
    ) -> Result<T, Error> {
        let resp = self.agent.post(self.url(path)).send_json(body)?;
        decode(resp)
    }

    pub fn status(&self) -> Result<StatusReply, Error> {
        self.get("/api/status")
    }

    pub fn request(&self, body: &RequestBody) -> Result<RequestReply, Error> {
        self.post("/api/request", body)
    }

    pub fn poll(&self, id: u64) -> Result<RequestState, Error> {
        self.get(&format!("/api/request/{id}"))
    }

    pub fn issue(&self, host: &str, public_key: &str) -> Result<IssueReply, Error> {
        self.post(
            "/api/issue",
            &IssueBody {
                host: host.to_owned(),
                public_key: public_key.to_owned(),
            },
        )
    }

    pub fn kill(&self, host: &str) -> Result<(), Error> {
        let _: serde_json::Value = self.post(
            "/api/kill",
            &KillBody {
                host: host.to_owned(),
            },
        )?;
        Ok(())
    }
}

fn decode<T: DeserializeOwned>(mut resp: ureq::http::Response<ureq::Body>) -> Result<T, Error> {
    let http = resp.status().as_u16();
    let text = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::Protocol(e.to_string()))?;
    if (200..300).contains(&http) {
        return serde_json::from_str(&text).map_err(|e| Error::Protocol(format!("{e}: {text}")));
    }
    let reply = serde_json::from_str::<ErrorReply>(&text).unwrap_or(ErrorReply {
        code: format!("http_{http}"),
        error: if text.trim().is_empty() {
            format!("HTTP {http}")
        } else {
            text.trim().to_owned()
        },
        until: None,
    });
    Err(Error::Daemon { http, reply })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn daemon(code: &str, http: u16) -> Error {
        Error::Daemon {
            http,
            reply: ErrorReply {
                code: code.into(),
                error: String::new(),
                until: None,
            },
        }
    }

    #[test]
    fn refusals_map_to_the_documented_exit_codes() {
        assert_eq!(daemon("busy", 409).status(), Status::RetryClean);
        assert_eq!(daemon("cooldown", 429).status(), Status::RetryLater);
        assert_eq!(daemon("rate_capped", 429).status(), Status::RetryLater);
        assert_eq!(daemon("unknown_host", 404).status(), Status::Permanent);
        assert_eq!(daemon("no_window", 404).status(), Status::AuthNeedsHuman);
        assert_eq!(daemon("key_mismatch", 403).status(), Status::AuthDenied);
        assert_eq!(daemon("internal", 500).status(), Status::RetryUnknown);
        assert_eq!(daemon("http_502", 502).status(), Status::RetryUnknown);
        assert_eq!(Error::Unreachable("x".into()).status(), Status::Unreachable);
    }
}
