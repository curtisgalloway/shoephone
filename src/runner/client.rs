// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The runner's side of the daemon's runner endpoints: blocking HTTP, every
//! request signed with the runner's key over a fresh nonce and the current
//! time (see [`crate::runner_auth`]).
//!
//! What the runner sends is digests, scopes, display text and failure
//! categories. Nothing it sends carries a resolved secret.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use ssh_key::PrivateKey;
use ssh_key::rand_core::{OsRng, RngCore};
use ureq::Agent;

use crate::api::{
    ById, FinishBody, JobScopeWire, JobStatus, MAX_ARCHIVE_BYTES, RefuseBody, RunnerJob, SubmitBody,
};
use crate::client::{Error, decode};
use crate::runner_auth;

/// Header carrying the request's Unix time in seconds.
const TIMESTAMP_HEADER: &str = "shoephone-runner-timestamp";
/// Header carrying the request's single-use nonce.
const NONCE_HEADER: &str = "shoephone-runner-nonce";

/// A signed client for one runner.
pub struct RunnerClient {
    agent: Agent,
    base: String,
    name: String,
    key: PrivateKey,
}

impl std::fmt::Debug for RunnerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerClient")
            .field("base", &self.base)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// 128 random bits as hex.
fn fresh_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl RunnerClient {
    pub fn new(base: &str, name: &str, key: PrivateKey) -> RunnerClient {
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .user_agent(concat!("shoephone-runner/", env!("CARGO_PKG_VERSION")))
            .build();
        RunnerClient {
            agent: config.into(),
            base: base.trim_end_matches('/').to_owned(),
            name: name.to_owned(),
            key,
        }
    }

    /// The three signature headers for one request.
    fn headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        job: Option<u64>,
    ) -> Result<[(&'static str, String); 4], Error> {
        let timestamp = unix_now();
        let nonce = fresh_nonce();
        let message = runner_auth::canonical(method, path, body, job, timestamp, &nonce);
        let signature = runner_auth::sign(&self.key, &message).map_err(Error::Protocol)?;
        Ok([
            (runner_auth::RUNNER_HEADER, self.name.clone()),
            (runner_auth::SIGNATURE_HEADER, signature),
            (TIMESTAMP_HEADER, timestamp.to_string()),
            (NONCE_HEADER, nonce),
        ])
    }

    /// POST `body` as JSON, signed over its exact bytes. `job` is the id
    /// the body names, which the signature covers.
    fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl serde::Serialize,
        job: Option<u64>,
    ) -> Result<T, Error> {
        let bytes = serde_json::to_vec(body).map_err(|e| Error::Protocol(e.to_string()))?;
        let mut req = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json");
        for (k, v) in self.headers("POST", path, &bytes, job)? {
            req = req.header(k, v);
        }
        decode(req.send(&bytes[..])?)
    }

    /// `POST /api/runner/poll`: the next job for this runner, if any.
    pub fn poll(&self) -> Result<Option<RunnerJob>, Error> {
        self.post("/api/runner/poll", &serde_json::json!({}), None)
    }

    /// `GET /api/runner/archive/{id}`: a trust job's archive, at most
    /// [`MAX_ARCHIVE_BYTES`].
    pub fn archive(&self, id: u64) -> Result<Vec<u8>, Error> {
        let path = format!("/api/runner/archive/{id}");
        let mut req = self.agent.get(format!("{}{path}", self.base));
        for (k, v) in self.headers("GET", &path, b"", Some(id))? {
            req = req.header(k, v);
        }
        let mut resp = req.call()?;
        let http = resp.status().as_u16();
        if !(200..300).contains(&http) {
            return decode::<serde_json::Value>(resp).map(|_| Vec::new());
        }
        resp.body_mut()
            .with_config()
            .limit(MAX_ARCHIVE_BYTES as u64 + 1)
            .read_to_vec()
            .map_err(|e| Error::Protocol(e.to_string()))
            .and_then(|bytes| {
                if bytes.len() > MAX_ARCHIVE_BYTES {
                    Err(Error::Protocol("the archive is too large".into()))
                } else {
                    Ok(bytes)
                }
            })
    }

    /// `POST /api/runner/submit`: hand in a planned scope and its display.
    pub fn submit(&self, body: &SubmitBody) -> Result<(), Error> {
        self.post::<serde_json::Value>("/api/runner/submit", body, Some(body.id))
            .map(drop)
    }

    /// `POST /api/runner/refuse`: end planning without a scope.
    pub fn refuse(&self, body: &RefuseBody) -> Result<(), Error> {
        self.post::<serde_json::Value>("/api/runner/refuse", body, Some(body.id))
            .map(drop)
    }

    /// `POST /api/runner/claim`: take an approval, once.
    pub fn claim(&self, id: u64) -> Result<JobScopeWire, Error> {
        self.post("/api/runner/claim", &ById { id }, Some(id))
    }

    /// `POST /api/runner/finish`: report how a claimed job ended.
    pub fn finish(&self, body: &FinishBody) -> Result<(), Error> {
        self.post::<serde_json::Value>("/api/runner/finish", body, Some(body.id))
            .map(drop)
    }

    /// `GET /api/job/{id}`, the unauthenticated status the CLI reads. The
    /// runner uses it to notice that a job it planned has ended without
    /// coming back for a claim. `Ok(None)` when the daemon no longer knows
    /// the job.
    pub fn job(&self, id: u64) -> Result<Option<JobStatus>, Error> {
        let resp = self
            .agent
            .get(format!("{}/api/job/{id}", self.base))
            .call()?;
        match decode(resp) {
            Ok(s) => Ok(Some(s)),
            Err(Error::Daemon { http: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_fresh_and_single_line() {
        let a = fresh_nonce();
        let b = fresh_nonce();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
