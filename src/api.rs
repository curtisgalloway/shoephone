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
    /// Why admin is needed: the task, in a sentence the person can judge.
    /// Required; the daemon refuses an empty one. Display only, untrusted.
    #[serde(default)]
    pub reason: String,
    /// Where the person can read more: the agent session's URL. Optional;
    /// https only; display only, untrusted.
    #[serde(default)]
    pub context: Option<String>,
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
///
/// Exactly one of `host` (close SSH windows) or `project` (stop a Terraform
/// job) must be set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
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

/// `GET /api/ledger` query parameters.
///
/// A client pages backward through history: call with no parameters for
/// the newest page, then repeat the call with `before` set to the smallest
/// `seq` it received in the previous page, until an empty page comes back.
/// `limit` defaults to 50 and is clamped to the range 1..=500.
#[derive(Debug, Clone, Deserialize)]
pub struct LedgerQuery {
    /// Return only entries with `seq` less than this.
    pub before: Option<u64>,
    /// At most this many entries.
    pub limit: Option<usize>,
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
///
/// `public_key` and `nonce` are exposed deliberately, alongside the fields
/// already here: the approve page recomputes
/// `sha256(scope.bytes_to_sign(nonce))` from exactly what it displays and
/// checks it against the WebAuthn challenge before it will sign anything, so
/// it needs every field that goes into that computation, not just the ones
/// that are otherwise human-readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingView {
    pub id: u64,
    pub host: String,
    pub principal: String,
    pub public_key: String,
    pub ends_at: u64,
    pub match_code: String,
    pub nonce: String,
    pub requester: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
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

/// `POST /api/push/register`: the app hands the daemon its APNs device
/// token, bound to the credential it enrolled with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRegister {
    /// Credential id, base64url on the wire, as in the WebAuthn responses.
    pub credential_id: webauthn_rs::prelude::Base64UrlSafeData,
    /// The device token as hex.
    pub token: String,
    /// The per-device secret minted at enrollment, hex. Credential ids are
    /// public (`approve/start` discloses them to anyone who can reach the
    /// daemon), so this secret, known only to the app that enrolled, is what
    /// authenticates this call.
    pub secret: String,
    /// Which pushes to send, by kind name (`request_waiting`,
    /// `window_opened`, `window_killed`). Absent means all.
    #[serde(default)]
    pub kinds: Option<Vec<String>>,
}

/// Largest archive, after base64 decoding, that `POST /api/trust` accepts.
pub const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;

/// Largest manifest, in bytes, that `POST /api/apply` accepts.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// `POST /api/trust`: ask the approver to trust a code change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBody {
    pub project: String,
    /// Base64 of a gzip tar of the candidate code.
    pub archive: String,
    /// Why, in a sentence the person can judge. Required; display only.
    #[serde(default)]
    pub reason: String,
    /// The requesting machine's name, display only.
    #[serde(default)]
    pub requester: String,
    /// The agent session's URL. Optional; https only; display only.
    #[serde(default)]
    pub context: Option<String>,
}

/// `POST /api/apply`: ask the approver to apply a plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyBody {
    pub project: String,
    /// The agent's JSON manifest text, at most 64 KiB.
    pub manifest: String,
    #[serde(default)]
    pub allow_destroy: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub requester: String,
    #[serde(default)]
    pub context: Option<String>,
}

/// The reply to `trust` and `apply`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobReply {
    pub id: u64,
    pub match_code: String,
    /// Unix seconds: when the daemon gives up on a job that has not been
    /// planned.
    pub expires: u64,
}

/// `GET /api/job/{id}`. Never carries a manifest value or an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatus {
    pub id: u64,
    pub project: String,
    /// `trust` or `apply`.
    pub kind: String,
    /// `queued`, `working`, `waiting`, `approved`, `claimed` or `done`.
    pub state: String,
    /// Set when `state` is `done`: `trusted`, `applied`, `refused`,
    /// `plan_failed`, `apply_failed`, `outcome_unknown`, `declined`,
    /// `timed_out` or `killed`.
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub failure: Option<FailureView>,
    #[serde(default)]
    pub summary: Option<SummaryView>,
}

/// Why a job did not complete, in the runner's words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureView {
    pub category: String,
    pub addresses: Vec<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

/// What a plan would do: counts, addresses and names, never values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryView {
    pub create: u32,
    pub update: u32,
    pub replace: u32,
    pub delete: u32,
    /// Resource addresses, one line each.
    pub addresses: Vec<String>,
    /// Names of the variables whose values changed.
    pub variables: Vec<String>,
    /// `none`, `applied` or `uncertain`.
    pub baseline_status: String,
}

/// The wire form of [`crate::scope::TrustScope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScopeWire {
    pub project: String,
    #[serde(default)]
    pub baseline: Option<String>,
    pub candidate: String,
    pub diff: String,
    pub schema: String,
    pub policy_version: u32,
    pub files_changed: u32,
    pub lines_added: u32,
    pub lines_removed: u32,
    pub schema_changed: bool,
}

/// The four change counts of a plan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CountsWire {
    pub create: u32,
    pub update: u32,
    pub replace: u32,
    pub delete: u32,
}

/// The wire form of [`crate::scope::ApplyScope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyScopeWire {
    pub project: String,
    pub revision: String,
    pub schema: String,
    pub manifest: String,
    #[serde(default)]
    pub baseline_manifest: Option<String>,
    /// `none`, `applied` or `uncertain`.
    pub baseline_status: String,
    pub plan: String,
    pub destructive: bool,
    pub counts: CountsWire,
    pub addresses: String,
}

/// The wire form of [`crate::job::JobScope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobScopeWire {
    Trust(TrustScopeWire),
    Apply(ApplyScopeWire),
}

/// What the approver needs in order to recompute the digests in a scope.
/// The daemon checks them before it accepts the scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisplayWire {
    /// A trust: the diff text whose SHA-256 is the scope's `diff`.
    #[serde(default)]
    pub diff: Option<String>,
    /// A trust whose diff is too large to carry: the approver checks it
    /// outside the app with `verify_command`.
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub verify_command: Option<String>,
    /// An apply: the canonical manifest text.
    #[serde(default)]
    pub manifest: Option<String>,
    /// An apply: the baseline manifest text, if there is a baseline.
    #[serde(default)]
    pub baseline_manifest: Option<String>,
    /// An apply: one `"{action} {address}\n"` line per change.
    #[serde(default)]
    pub address_text: Option<String>,
}

/// What `POST /api/runner/poll` hands a runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerJob {
    pub id: u64,
    pub project: String,
    /// `trust` or `apply`.
    pub kind: String,
    /// `working` or `approved`.
    pub state: String,
    /// An apply: the agent's manifest text.
    #[serde(default)]
    pub manifest: Option<String>,
    pub allow_destroy: bool,
    /// The project's currently trusted candidate, if any.
    #[serde(default)]
    pub trusted: Option<crate::store::TrustRecord>,
}

/// `POST /api/runner/submit`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitBody {
    pub id: u64,
    pub scope: JobScopeWire,
    pub display: DisplayWire,
}

/// `POST /api/runner/refuse`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefuseBody {
    pub id: u64,
    /// `refused` or `plan_failed`.
    pub result: String,
    pub failure: FailureView,
}

/// `POST /api/runner/finish`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishBody {
    pub id: u64,
    /// `trusted`, `applied`, `apply_failed` or `outcome_unknown`.
    pub result: String,
    #[serde(default)]
    pub failure: Option<FailureView>,
    /// Needed only when the daemon no longer knows the job (it restarted
    /// mid-apply), so an `outcome_unknown` can still be recorded.
    #[serde(default)]
    pub project: Option<String>,
}
