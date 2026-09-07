// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The wire types shared by `shoephoned` and `shoephone`. JSON over HTTP.
//!
//! Nothing here is trusted by the daemon: every field is validated against
//! policy and the principal table before it influences anything.

use serde::{Deserialize, Serialize};

/// `POST /api/request`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub host: String,
    /// OpenSSH public key line for the session key.
    pub public_key: String,
    /// The requesting machine's name, display only.
    #[serde(default)]
    pub requester: String,
    /// Wanted window; clamped to policy.
    #[serde(default)]
    pub window_minutes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestReply {
    pub id: u64,
    pub match_code: String,
    pub host: String,
    pub principal: String,
    /// Unix seconds.
    pub ends_at: u64,
    /// How long the daemon will wait for a verdict, in seconds.
    pub pending_ttl: u64,
}

/// `GET /api/request/{id}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum RequestState {
    Pending,
    Approved {
        ends_at: u64,
    },
    /// Declined, timed out, killed, or expired. The daemon does not say
    /// which; the person can see it on their device.
    Gone,
}

/// `POST /api/issue`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueBody {
    pub host: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueReply {
    /// The OpenSSH certificate line, for the `-cert.pub` file or the agent.
    pub certificate: String,
    pub serial: u64,
    pub valid_before: u64,
    /// When the window itself closes.
    pub ends_at: u64,
}

/// `POST /api/kill`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillBody {
    pub host: String,
}

/// `GET /api/status`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReply {
    pub version: String,
    pub hosts: Vec<String>,
    pub devices: Vec<String>,
    pub windows: Vec<WindowView>,
    pub ca_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowView {
    pub id: u64,
    pub host: String,
    pub ends_at: u64,
    pub fingerprint: String,
}

/// Every error body. `code` is the machine-readable name; `until` is set
/// for cooldowns and the rate cap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReply {
    pub code: String,
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// `GET /api/pending`, the approver's view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingView {
    pub id: u64,
    pub host: String,
    pub principal: String,
    pub ends_at: u64,
    pub match_code: String,
    pub requester: String,
    pub fingerprint: String,
    pub created: u64,
    pub expires: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverState {
    pub pending: Option<PendingView>,
    pub enrolled: usize,
    pub windows: Vec<WindowView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ById {
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollStart {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollFinish<C> {
    pub code: String,
    pub credential: C,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveFinish<C> {
    pub id: u64,
    pub credential: C,
}
