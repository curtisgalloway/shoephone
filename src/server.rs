// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The daemon's HTTP surface: the CLI API, the approver API, and the page.
//!
//! Plain HTTP, meant to sit behind a TLS-terminating reverse proxy on the
//! failsafe host. Two audiences share one listener: the agent's machine
//! (request, poll, issue, kill) and the approver's phone (pending, approve,
//! decline, enroll, ledger). Nothing on the agent side is authenticated,
//! by design: requests are rate-capped, certificates are only ever issued
//! to the approved public key, and a kill or a decline from a stranger
//! fails closed (it costs the requester a cooldown and opens nothing).
//! Everything that opens a window goes through a WebAuthn assertion from
//! an enrolled security key.
//!
//! The challenge a WebAuthn ceremony asks the approver's device to sign is
//! not the library's own random value: `approve_start` overwrites it with
//! [`grant::bound_challenge`], SHA-256 of the pending request's
//! `Scope::bytes_to_sign`, so the assertion covers the scope and nonce the
//! approver is looking at. The approve page recomputes the same digest from
//! the fields it displayed and refuses to call `navigator.credentials.get`
//! on a mismatch, so a channel that shows the approver one scope and relays
//! a challenge bound to another is caught before a signature ever exists.
//! The daemon does not rely on that client-side check alone: it also
//! snapshots the pending request's id, nonce and enforced scope when the
//! ceremony starts, and only that snapshot is submitted to
//! [`Grants::approve`] when the assertion verifies. A request that changed
//! underneath the ceremony is rejected there too.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use webauthn_rs::prelude::*;

use crate::api::*;
use crate::ca::{self, UserCa};
use crate::config::Config;
use crate::exit::VERSION;
use crate::grant::{self, Approval, Entropy, Event, Grants, Pending, Policy, Refusal, Scope};
use crate::job::{Failure, Job, JobEvent, JobKind, JobResult, JobScope, JobState, Jobs};
use crate::notify::{Apns, Delivery, Notifier, Push};
use crate::runner_auth::{self, Verifier};
use crate::scope::{self, Action, ApplyScope, BaselineStatus, Counts, TrustScope};
use crate::store::{self, Device, EnrollCode, LedgerEntry, Store, TrustRecord};

pub const PAGE: &str = include_str!("../assets/approve.html");

/// How long a started WebAuthn ceremony may take before it is dropped.
const CEREMONY_TTL: Duration = Duration::from_secs(120);

pub struct Daemon {
    config: Config,
    ca: UserCa,
    webauthn: Webauthn,
    store: Store,
    notifier: Option<Arc<Notifier>>,
    apns: Option<Arc<Apns>>,
    inner: Mutex<Inner>,
}

struct Inner {
    grants: Grants,
    devices: Vec<Device>,
    approve: Option<ApproveCeremony>,
    enroll: Option<EnrollCeremony>,
    /// Set once a ledger append has failed. Sticky for the life of the
    /// process: `audited` refuses every further call while this is set,
    /// because "restart with a writable ledger" is the only way back to a
    /// state where every audited outcome is known to be on disk.
    ledger_failed: Option<String>,
    /// The id/serial counter as last written to `Store::save_next_id`, so
    /// `drain_and_append` only writes again when `grants.next_id()` has
    /// actually moved past it.
    persisted_next_id: u64,
    /// Signed certificates already handed out, keyed by window id, so a
    /// window's silent re-request that `Grants::issue` says to reuse gets
    /// back the identical certificate string. See the `issue` handler.
    issued: HashMap<u64, CachedCertificate>,
    /// Terraform trust and apply jobs.
    jobs: Jobs,
    /// The decoded archive of each trust job, by job id, for the runner to
    /// fetch. Dropped once the job leaves `Queued` and `Working`.
    archives: HashMap<u64, Vec<u8>>,
    /// What the approver reads to recompute a submitted scope's digests, by
    /// job id, as the runner sent it. Dropped once the job leaves `Waiting`.
    /// The pending view is built from a `Waiting` job and reads this beside
    /// it, never from an entry here alone.
    displays: HashMap<u64, DisplayWire>,
    /// The trust scope of each claimed trust job, so `finish` can record
    /// what was trusted. Dropped when the job finishes.
    claimed: HashMap<u64, TrustScope>,
    /// What each project currently trusts; mirrors `trusted.json`.
    trusted: BTreeMap<String, TrustRecord>,
    /// Checks the runners' signatures and remembers their nonces.
    verifier: Verifier,
    /// What the requester said about itself, sanitized, by job id.
    job_meta: HashMap<u64, JobMeta>,
}

/// The display-only fields of a job request, already sanitized.
#[derive(Debug, Clone)]
struct JobMeta {
    requester: String,
    context: Option<String>,
}

/// A signed certificate cached under its window's id. `Grants::issue`
/// tracks that a window's last certificate can be reused, but it has no
/// signature to hand back; this is where the daemon keeps the one it
/// already signed so a reuse does not need a fresh signing operation, and
/// so the caller gets back the exact same certificate string, not merely an
/// equivalent one.
#[derive(Debug, Clone)]
struct CachedCertificate {
    certificate: String,
    serial: u64,
    valid_before: SystemTime,
    window_ends_at: SystemTime,
}

/// What an approval ceremony is over: the SSH request or the Terraform job
/// that was waiting when it started. At most one of the two exists.
enum CeremonyScope {
    Ssh(Scope),
    Job(JobScope),
}

struct ApproveCeremony {
    id: u64,
    nonce: String,
    scope: CeremonyScope,
    auth: SecurityKeyAuthentication,
    started: SystemTime,
}

struct EnrollCeremony {
    device_name: String,
    reg: SecurityKeyRegistration,
    started: SystemTime,
}

/// A failed call: an HTTP status and an [`ErrorReply`].
#[derive(Debug)]
pub struct Fail(StatusCode, ErrorReply);

impl Fail {
    fn new(status: StatusCode, code: &str, error: impl Into<String>) -> Self {
        Fail(
            status,
            ErrorReply {
                code: code.to_owned(),
                error: error.into(),
                until: None,
            },
        )
    }

    fn internal(error: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", error)
    }
}

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

impl From<Refusal> for Fail {
    fn from(r: Refusal) -> Self {
        use StatusCode as S;
        let (status, code, until) = match &r {
            Refusal::UnknownHost => (S::NOT_FOUND, "unknown_host", None),
            Refusal::BadKey => (S::BAD_REQUEST, "bad_key", None),
            Refusal::NoReason => (S::BAD_REQUEST, "reason_required", None),
            Refusal::Busy => (S::CONFLICT, "busy", None),
            Refusal::Cooldown { until } => (S::TOO_MANY_REQUESTS, "cooldown", Some(*until)),
            Refusal::RateCapped { until } => (S::TOO_MANY_REQUESTS, "rate_capped", Some(*until)),
            Refusal::NoSuchRequest => (S::NOT_FOUND, "no_such_request", None),
            Refusal::NonceMismatch => (S::FORBIDDEN, "nonce_mismatch", None),
            Refusal::ScopeMismatch => (S::FORBIDDEN, "scope_mismatch", None),
            Refusal::NoWindow => (S::NOT_FOUND, "no_window", None),
            Refusal::KeyMismatch => (S::FORBIDDEN, "key_mismatch", None),
            Refusal::UnknownProject => (S::BAD_REQUEST, "unknown_project", None),
            Refusal::ScopeFrozen => (S::CONFLICT, "scope_frozen", None),
            Refusal::AlreadyClaimed => (S::CONFLICT, "already_claimed", None),
            Refusal::WrongRunner => (S::FORBIDDEN, "wrong_runner", None),
            Refusal::Stale => (S::CONFLICT, "stale", None),
            Refusal::StaleSignature => (S::UNAUTHORIZED, "stale_signature", None),
            Refusal::StaleBaseline => (S::CONFLICT, "stale_baseline", None),
            Refusal::PlanTooOld => (S::CONFLICT, "plan_too_old", None),
            Refusal::MalformedScope => (S::BAD_REQUEST, "malformed_scope", None),
        };
        Fail(
            status,
            ErrorReply {
                code: code.to_owned(),
                error: r.to_string(),
                until: until.map(store::unix),
            },
        )
    }
}

type Reply<T> = Result<Json<T>, Fail>;

impl Daemon {
    pub fn new(config: Config) -> Result<Self, String> {
        let ca = UserCa::from_openssh_file(&config.ca_key).map_err(|e| e.to_string())?;
        let origin = Url::parse(&config.rp_origin).map_err(|e| format!("rp_origin: {e}"))?;
        let webauthn = WebauthnBuilder::new(&config.rp_id, &origin)
            .map_err(|e| format!("webauthn: {e}"))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| format!("webauthn: {e}"))?;
        let store = Store::new(&config.state_dir);
        let devices = store.load_devices()?;
        for device in &devices {
            let cred = webauthn_rs::prelude::Credential::from(device.key.clone());
            if cred.backup_eligible || cred.backup_state {
                let verb = if config.allow_synced_credentials {
                    "accepted only because allow_synced_credentials is on"
                } else {
                    "will be refused at approval"
                };
                eprintln!(
                    "shoephoned: device {:?} is a synced credential (backup-eligible); {verb}",
                    device.name
                );
            }
            if device.push_secret_sha256.is_none() {
                eprintln!(
                    "shoephoned: device {:?} has no push secret; it cannot register for notifications until it enrolls again",
                    device.name
                );
            }
        }
        let next_id = store.load_next_id()?;
        let grants = Grants::new(config.policy(), config.principals.clone(), next_id);
        let jobs = Jobs::new(
            config
                .projects
                .iter()
                .map(|(name, p)| (name.clone(), p.runner.clone()))
                .collect(),
        );
        let mut jobs = jobs;
        let mut trusted = BTreeMap::new();
        for dropped in store.reconcile_trusted()? {
            eprintln!(
                "shoephoned: dropping trust for {:?} (job {}): no matching entry in the ledger",
                dropped.project, dropped.job
            );
        }
        for record in store.load_trusted()? {
            jobs.set_trusted(&record.project, Some(record.digest.clone()));
            trusted.insert(record.project.clone(), record);
        }
        let verifier = Verifier::new(config.runner_keys()?);
        let notifier = config.notify.clone().map(|n| Arc::new(Notifier::new(n)));
        let apns = match config.apns.clone() {
            Some(c) => {
                let a = Apns::new(c)?;
                eprintln!(
                    "shoephoned: APNs push through {} for topic {}",
                    a.gateway(),
                    a.topic()
                );
                Some(Arc::new(a))
            }
            None => None,
        };
        Ok(Self {
            config,
            ca,
            webauthn,
            store,
            notifier,
            apns,
            inner: Mutex::new(Inner {
                grants,
                devices,
                approve: None,
                enroll: None,
                ledger_failed: None,
                persisted_next_id: next_id,
                issued: HashMap::new(),
                jobs,
                archives: HashMap::new(),
                displays: HashMap::new(),
                claimed: HashMap::new(),
                trusted,
                verifier,
                job_meta: HashMap::new(),
            }),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn device_names(&self) -> Vec<String> {
        self.inner
            .lock()
            .expect("daemon lock")
            .devices
            .iter()
            .map(|d| d.name.clone())
            .collect()
    }

    /// Run `f` under the lock, then flush any ledger events it produced.
    /// The append happens before the lock is released, so two concurrent
    /// callers' ledger writes land in the same order as their state
    /// transitions. A failed append is logged and recorded in
    /// `ledger_failed`, but `f`'s own result is returned regardless: `kill`
    /// and `decline` use `with`, and they must stay effective even when the
    /// disk backing the ledger is full.
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self.inner.lock().expect("daemon lock");
        let out = f(&mut inner);
        let pushes = self.drain_and_append(&mut inner);
        let targets = push_targets(&inner);
        let badge = badge_count(&mut inner, SystemTime::now());
        drop(inner);
        self.dispatch_pushes(pushes, targets, badge);
        out
    }

    /// Like [`Daemon::with`], but for calls that must refuse rather than
    /// grant anything once the ledger cannot be trusted: `request`, `issue`,
    /// `approve_finish`, and the `test-hooks` approval. If a previous call
    /// already found the ledger unwritable, this refuses immediately,
    /// without running `f` at all. Otherwise it runs `f` and appends its
    /// events under the same lock; if that append fails, the in-memory
    /// transition `f` made still stands (there is no undo), but the caller
    /// is told the same `ledger_unavailable` failure instead of `f`'s own
    /// result, so nothing further is granted on the strength of a decision
    /// this daemon cannot prove it recorded.
    fn audited<T>(&self, f: impl FnOnce(&mut Inner) -> Result<T, Fail>) -> Result<T, Fail> {
        self.audited_or_undo(|inner| f(inner).map(|t| (t, ())), |_, ()| ())
    }

    /// [`Daemon::audited`] for a change the caller can take back. `f` returns
    /// its result and whatever `undo` needs; if the ledger append then
    /// fails, `undo` runs under the same lock, before any other caller can
    /// see the change, and the caller is told `ledger_unavailable`. `undo`
    /// does not run when `f` itself failed, so `f` must not change state on
    /// an error path. When `undo` runs, the pushes for the call's events are
    /// discarded: the ledger holds no line for them and the change no longer
    /// stands, so the phone is not told.
    fn audited_or_undo<T, U>(
        &self,
        f: impl FnOnce(&mut Inner) -> Result<(T, U), Fail>,
        undo: impl FnOnce(&mut Inner, U),
    ) -> Result<T, Fail> {
        let mut inner = self.inner.lock().expect("daemon lock");
        if inner.ledger_failed.is_some() {
            return Err(Self::ledger_unavailable());
        }
        let out = f(&mut inner);
        let mut pushes = self.drain_and_append(&mut inner);
        let append_failed = inner.ledger_failed.is_some();
        let out = match out {
            Ok((_, taken)) if append_failed => {
                undo(&mut inner, taken);
                // The change was taken back and its ledger line was not
                // written, so the phone must not be told it happened.
                pushes.clear();
                Err(Self::ledger_unavailable())
            }
            Ok((value, _)) => Ok(value),
            Err(e) => Err(e),
        };
        let targets = push_targets(&inner);
        let badge = badge_count(&mut inner, SystemTime::now());
        drop(inner);
        self.dispatch_pushes(pushes, targets, badge);
        if append_failed {
            return Err(Self::ledger_unavailable());
        }
        out
    }

    fn ledger_unavailable() -> Fail {
        Fail::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ledger_unavailable",
            "the audit ledger cannot be written; approvals and certificates are refused until the daemon restarts with a writable ledger",
        )
    }

    /// Drain this call's ledger events and append them, then persist the
    /// id/serial counter if it moved, all while still holding the lock. On
    /// either failure this logs and sets `ledger_failed`; it does not
    /// itself decide what the caller does about that. The counter is
    /// checked unconditionally, not only when there were events to append:
    /// it only ever advances alongside an event (`request` and a fresh
    /// `issue` each push one when they call `take_id`), so this never does
    /// avoidable work, but it also never assumes that pairing rather than
    /// re-deriving it, which is one fewer thing to keep in sync by hand.
    fn drain_and_append(&self, inner: &mut Inner) -> Vec<Push> {
        let events = inner.grants.take_events();
        let job_events = inner.jobs.take_events();
        if !events.is_empty() || !job_events.is_empty() {
            let entries: Vec<LedgerEntry> = events
                .iter()
                .map(LedgerEntry::from)
                .chain(job_events.iter().map(LedgerEntry::from))
                .collect();
            if let Err(e) = self.store.append_ledger(&entries) {
                eprintln!("shoephoned: ledger: {e}");
                inner.ledger_failed = Some(e);
            }
        }
        let next_id = inner.grants.next_id();
        if next_id != inner.persisted_next_id {
            match self.store.save_next_id(next_id) {
                Ok(()) => inner.persisted_next_id = next_id,
                Err(e) => {
                    eprintln!("shoephoned: next_id: {e}");
                    inner.ledger_failed = Some(e);
                }
            }
        }
        events
            .iter()
            .map(push_for)
            .chain(job_events.iter().map(push_for_job))
            .collect()
    }

    /// Send the content-free pushes for this call's events. Always called
    /// after the lock is released: notifier and APNs delivery can block, or
    /// need the tokio runtime, and neither should happen while another
    /// caller is waiting on the daemon lock.
    fn dispatch_pushes(
        &self,
        pushes: Vec<Push>,
        targets: Vec<(String, Option<Vec<String>>)>,
        badge: u64,
    ) {
        if pushes.is_empty() {
            return;
        }
        if let Some(n) = &self.notifier
            && !pushes.is_empty()
        {
            let n = n.clone();
            let pushes = pushes.clone();
            let push = move || {
                for p in pushes {
                    if let Err(e) = n.send(p) {
                        eprintln!("shoephoned: {e}");
                    }
                }
            };
            match tokio::runtime::Handle::try_current() {
                Ok(h) => {
                    h.spawn_blocking(push);
                }
                Err(_) => push(),
            }
        }
        // APNs is async and needs the runtime; outside one (unit tests)
        // there is nothing to push to anyway.
        if let Some(a) = &self.apns
            && !pushes.is_empty()
            && !targets.is_empty()
            && let Ok(h) = tokio::runtime::Handle::try_current()
        {
            let a = a.clone();
            h.spawn(async move {
                for p in &pushes {
                    for (t, kinds) in &targets {
                        if let Some(kinds) = kinds
                            && !kinds.iter().any(|k| k == p.kind())
                        {
                            continue;
                        }
                        match a.send(*p, t, badge).await {
                            Delivery::Sent => {}
                            Delivery::Unregistered => eprintln!(
                                "shoephoned: apns rejected a device token as unregistered; the app re-registers on launch"
                            ),
                            Delivery::Failed(e) => eprintln!("shoephoned: {e}"),
                        }
                    }
                }
            });
        }
    }

    pub fn router(self: Arc<Self>) -> Router {
        let router = Router::new()
            .route("/", get(page))
            .route("/api/status", get(status))
            .route("/api/request", post(request))
            .route("/api/request/{id}", get(poll))
            .route("/api/issue", post(issue))
            .route(
                "/api/trust",
                post(trust).layer(DefaultBodyLimit::max(TRUST_BODY_LIMIT)),
            )
            .route(
                "/api/apply",
                post(apply).layer(DefaultBodyLimit::max(APPLY_BODY_LIMIT)),
            )
            .route("/api/job/{id}", get(job))
            .route("/api/runner/poll", post(runner_poll))
            .route("/api/runner/archive/{id}", get(runner_archive))
            .route(
                "/api/runner/submit",
                post(runner_submit).layer(DefaultBodyLimit::max(SUBMIT_BODY_LIMIT)),
            )
            .route("/api/runner/refuse", post(runner_refuse))
            .route("/api/runner/claim", post(runner_claim))
            .route("/api/runner/finish", post(runner_finish))
            .route("/api/kill", post(kill))
            .route("/api/pending", get(pending))
            .route("/api/approve/start", post(approve_start))
            .route("/api/approve/finish", post(approve_finish))
            .route("/api/decline", post(decline))
            .route("/api/enroll/start", post(enroll_start))
            .route("/api/enroll/finish", post(enroll_finish))
            .route("/api/push/register", post(push_register))
            .route("/api/ledger", get(ledger));
        #[cfg(feature = "test-hooks")]
        let router = router
            .route("/api/test/approve", post(test_approve))
            .route("/api/test/approve_job", post(test_approve_job));
        router.with_state(self)
    }
}

/// Request body limit for `trust`: the archive's base64 form plus JSON.
const TRUST_BODY_LIMIT: usize = MAX_ARCHIVE_BYTES / 3 * 4 + 4 * 1024 + 4;

/// Request body limit for `apply`: a manifest of 64 KiB can double in size
/// once JSON-escaped, so leave room for that and the other fields.
const APPLY_BODY_LIMIT: usize = MAX_MANIFEST_BYTES * 2 + 16 * 1024;

type App = State<Arc<Daemon>>;

fn now() -> SystemTime {
    SystemTime::now()
}

/// Each device's push token with the kinds it asked for; `None` means all.
/// What the app icon should read: live authorizations, plus a request if one
/// is waiting. Computed under the lock beside the targets, because by the
/// time the push is sent the lock is gone and the state may have moved.
///
/// The daemon holds at most one pending request or waiting job, so this is
/// windows + 0 or 1.
fn badge_count(inner: &mut Inner, now: SystemTime) -> u64 {
    inner.grants.outstanding(now) + u64::from(inner.jobs.waiting(now).is_some())
}

/// Every ledger event becomes a push; the device, not the daemon, keeps the
/// audit trail (DESIGN.md, custody rule 6). The match is exhaustive on
/// purpose, with no `_` arm: a new `Event` variant does not compile until
/// someone decides what the phone is told about it.
fn push_for(event: &Event) -> Push {
    match event {
        Event::Requested { .. } => Push::RequestWaiting,
        Event::Approved { .. } => Push::WindowOpened,
        Event::Issued { .. } => Push::CertificateIssued,
        Event::Declined { .. } => Push::RequestDeclined,
        Event::TimedOut { .. } => Push::RequestTimedOut,
        Event::Killed { .. } => Push::WindowKilled,
    }
}

/// Every job event becomes a push too, so the audit rule holds for
/// Terraform jobs as it does for SSH windows. Exhaustive for the same
/// reason as [`push_for`]. Only a `Waiting` job interrupts; a filed request
/// is a quiet record, because nobody is asked until a plan is ready.
/// `kind` is `"trust"` or `"apply"`.
fn push_for_job(event: &JobEvent) -> Push {
    match event {
        JobEvent::Requested { .. } => Push::JobRequested,
        JobEvent::Started { .. } => Push::PlanStarted,
        JobEvent::Waiting { kind, .. } => {
            if *kind == "trust" {
                Push::TrustWaiting
            } else {
                Push::ApplyWaiting
            }
        }
        JobEvent::Approved { .. } => Push::JobApproved,
        JobEvent::Refused { .. } => Push::PlanRefused,
        JobEvent::Applied { .. } => Push::Applied,
        JobEvent::Trusted { .. } => Push::Trusted,
        JobEvent::ApplyFailed { .. } => Push::ApplyFailed,
        JobEvent::OutcomeUnknown { .. } => Push::OutcomeUnknown,
        JobEvent::Declined { .. } => Push::RequestDeclined,
        JobEvent::TimedOut { .. } => Push::RequestTimedOut,
        JobEvent::Killed { .. } => Push::JobKilled,
    }
}

fn push_targets(inner: &Inner) -> Vec<(String, Option<Vec<String>>)> {
    inner
        .devices
        .iter()
        .filter_map(|d| d.push_token.clone().map(|t| (t, d.push_kinds.clone())))
        .collect()
}

fn window_views(inner: &mut Inner, now: SystemTime) -> Vec<WindowView> {
    inner
        .grants
        .windows(now)
        .iter()
        .map(|w| WindowView {
            id: w.id,
            host: w.scope.host.clone(),
            ends_at: store::unix(w.scope.ends_at),
            fingerprint: ca::fingerprint(&w.scope.public_key)
                .map(|f| f.to_string())
                .unwrap_or_default(),
        })
        .collect()
}

fn pending_view(p: &Pending, ttl: Duration) -> PendingView {
    PendingView {
        id: p.id,
        host: p.scope.host.clone(),
        principal: p.scope.principal.clone(),
        public_key: p.scope.public_key.clone(),
        ends_at: store::unix(p.scope.ends_at),
        match_code: p.match_code.clone(),
        nonce: p.nonce.clone(),
        requester: p.requester.clone(),
        reason: p.reason.clone(),
        context: p.context.clone(),
        fingerprint: ca::fingerprint(&p.scope.public_key)
            .map(|f| f.to_string())
            .unwrap_or_default(),
        created: store::unix(p.created),
        expires: store::unix(p.created + ttl),
    }
}

/// Overwrite a freshly started WebAuthn authentication ceremony's random
/// challenge with `challenge`, so the assertion the approver signs covers
/// exactly [`grant::bound_challenge`] for the pending request, not whatever
/// the library generated on its own.
///
/// `webauthn-rs` has no setter for either the public options' challenge or
/// the one buried in `SecurityKeyAuthentication`'s private
/// `AuthenticationState`. The `danger-allow-state-serialisation` feature
/// exists so a caller can round-trip that state instead, which is what this
/// does: serialize it to JSON, replace the nested `ast.challenge` field with
/// the same base64url encoding the crate itself would have produced for
/// `challenge`, then deserialize back into the type
/// `finish_securitykey_authentication` expects.
fn bind_challenge(
    mut rcr: RequestChallengeResponse,
    auth: SecurityKeyAuthentication,
    challenge: &[u8; 32],
) -> Result<(RequestChallengeResponse, SecurityKeyAuthentication), String> {
    rcr.public_key.challenge = Base64UrlSafeData::from(challenge);

    // `Base64UrlSafeData` and the `HumanBinaryData` that
    // `AuthenticationState::challenge` actually is both encode as
    // URL-safe, unpadded base64 in a human-readable format like JSON, so
    // this produces the identical string `ast.challenge` needs.
    let encoded = serde_json::to_value(Base64UrlSafeData::from(challenge))
        .map_err(|e| format!("encoding challenge: {e}"))?;
    let mut value = serde_json::to_value(&auth)
        .map_err(|e| format!("serializing authentication state: {e}"))?;
    value
        .get_mut("ast")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| "authentication state JSON has no \"ast\" object".to_owned())?
        .insert("challenge".to_owned(), encoded);
    let auth = serde_json::from_value(value)
        .map_err(|e| format!("rebuilding authentication state: {e}"))?;

    Ok((rcr, auth))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

async fn status(State(d): App) -> Reply<StatusReply> {
    let now = now();
    let (devices, windows) = d.with(|inner| {
        (
            inner.devices.iter().map(|x| x.name.clone()).collect(),
            window_views(inner, now),
        )
    });
    Ok(Json(StatusReply {
        version: VERSION.to_owned(),
        hosts: d.config.principals.keys().cloned().collect(),
        devices,
        windows,
        ca_fingerprint: d.ca.fingerprint().to_string(),
    }))
}

async fn request(State(d): App, Json(body): Json<RequestBody>) -> Reply<RequestReply> {
    let key = ca::canonical_public_key(&body.public_key)
        .map_err(|e| Fail::new(StatusCode::BAD_REQUEST, "bad_key", e.to_string()))?;
    let wanted = body
        .window_minutes
        .map(|m| Duration::from_secs(m.saturating_mul(60)));
    let now = now();
    let ttl = d.config.policy().pending_ttl;
    let p = d.audited(|inner| {
        let mut entropy = ca::OsEntropy;
        inner
            .grants
            .request(
                now,
                &mut entropy,
                &body.host,
                &key,
                &body.requester,
                &body.reason,
                body.context.as_deref(),
                wanted,
            )
            .map_err(Fail::from)
    })?;
    Ok(Json(RequestReply {
        id: p.id,
        match_code: p.match_code,
        host: p.scope.host,
        principal: p.scope.principal,
        ends_at: store::unix(p.scope.ends_at),
        pending_ttl: ttl.as_secs(),
    }))
}

async fn poll(State(d): App, Path(id): Path<u64>) -> Reply<RequestState> {
    let now = now();
    let state = d.with(|inner| {
        if inner.grants.pending(now).is_some_and(|p| p.id == id) {
            return RequestState::Pending;
        }
        match inner.grants.windows(now).iter().find(|w| w.id == id) {
            Some(w) => RequestState::Approved {
                ends_at: store::unix(w.scope.ends_at),
            },
            None => RequestState::Gone,
        }
    });
    Ok(Json(state))
}

async fn issue(State(d): App, Json(body): Json<IssueBody>) -> Reply<IssueReply> {
    let key = ca::canonical_public_key(&body.public_key)
        .map_err(|e| Fail::new(StatusCode::BAD_REQUEST, "bad_key", e.to_string()))?;
    let now = now();
    let (window_id, outcome) = d.audited(|inner| {
        let outcome = inner
            .grants
            .issue(now, &body.host, &key, false)
            .map_err(Fail::from)?;
        prune_issued_cache(inner, now);
        let window_id = window_id_for(inner, now, &body.host, &key, &outcome)?;
        Ok((window_id, outcome))
    })?;
    let cert = match outcome {
        grant::Issuance::Fresh(cert) => cert,
        grant::Issuance::Reuse { .. } => {
            if let Some(cached) = d.with(|inner| inner.issued.get(&window_id).cloned()) {
                return Ok(Json(IssueReply {
                    certificate: cached.certificate,
                    serial: cached.serial,
                    valid_before: store::unix(cached.valid_before),
                    ends_at: store::unix(cached.window_ends_at),
                }));
            }
            // Should not happen: `Grants::issue` said to reuse, but this
            // daemon has no signed certificate cached for that window
            // (the cache does not survive a restart, but neither does
            // `last_issued`, so a fresh process cannot reach this from a
            // cold cache; a defensive fallback anyway, not the expected
            // path). Force a fresh certificate rather than fail the call.
            d.audited(
                |inner| match inner.grants.issue(now, &body.host, &key, true) {
                    Ok(grant::Issuance::Fresh(cert)) => Ok(cert),
                    Ok(grant::Issuance::Reuse { .. }) => {
                        Err(Fail::internal("force_fresh unexpectedly returned a reuse"))
                    }
                    Err(e) => Err(Fail::from(e)),
                },
            )?
        }
    };
    let signed =
        d.ca.sign(&cert, &body.host)
            .and_then(|c| c.to_openssh().map_err(ca::Error::from))
            .map_err(|e| Fail::internal(e.to_string()))?;
    d.with(|inner| {
        inner.issued.insert(
            window_id,
            CachedCertificate {
                certificate: signed.clone(),
                serial: cert.serial,
                valid_before: cert.valid_before,
                window_ends_at: cert.window_ends_at,
            },
        );
    });
    Ok(Json(IssueReply {
        certificate: signed,
        serial: cert.serial,
        valid_before: store::unix(cert.valid_before),
        ends_at: store::unix(cert.window_ends_at),
    }))
}

/// The id of the window a [`grant::Issuance`] belongs to, needed to key the
/// certificate cache. `Reuse` already carries it; for `Fresh` it is
/// whichever window matches the certificate's host, key and
/// `window_ends_at` -- the same selection `Grants::issue` used internally
/// to mint it -- found here while still holding the lock the certificate
/// was minted under.
fn window_id_for(
    inner: &mut Inner,
    now: SystemTime,
    host: &str,
    public_key: &str,
    outcome: &grant::Issuance,
) -> Result<u64, Fail> {
    match outcome {
        grant::Issuance::Reuse { window_id, .. } => Ok(*window_id),
        grant::Issuance::Fresh(cert) => inner
            .grants
            .windows(now)
            .iter()
            .find(|w| {
                w.scope.host == host
                    && w.scope.public_key == public_key
                    && w.scope.ends_at == cert.window_ends_at
            })
            .map(|w| w.id)
            .ok_or_else(|| Fail::internal("issued certificate has no matching window")),
    }
}

/// Drop cached certificates for windows that have since closed, so the
/// cache does not grow across a long-running daemon's lifetime. Run once
/// per `issue` call instead of on a timer: it costs nothing when the window
/// count is small, and needs no extra background task.
fn prune_issued_cache(inner: &mut Inner, now: SystemTime) {
    let live: HashSet<u64> = inner.grants.windows(now).iter().map(|w| w.id).collect();
    inner.issued.retain(|id, _| live.contains(id));
}

async fn kill(State(d): App, Json(body): Json<KillBody>) -> Reply<serde_json::Value> {
    let now = now();
    match (body.host, body.project) {
        (Some(host), None) => {
            d.with(|inner| {
                inner.grants.kill(now, &host)?;
                // A ceremony for the request that kill just declined is stale.
                if inner.grants.pending(now).is_none() {
                    inner.approve = None;
                }
                Ok::<_, Refusal>(())
            })?;
            Ok(Json(serde_json::json!({ "killed": host })))
        }
        (None, Some(project)) => {
            let policy = d.config.policy();
            d.with(|inner| {
                inner
                    .jobs
                    .kill(now, inner.grants.gate_mut(), &policy, &project)
            })?;
            Ok(Json(serde_json::json!({ "killed": project })))
        }
        _ => Err(Fail::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "kill takes exactly one of host or project",
        )),
    }
}

/// Keep a requester-supplied link only if it is a short https URL without
/// whitespace, as `Grants::request` does.
fn clean_context(context: Option<&str>) -> Option<String> {
    context
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| grant::printable(c, 512))
        .filter(|c| c.starts_with("https://") && !c.chars().any(char::is_whitespace))
}

fn too_large(code: &str, what: &str) -> Fail {
    Fail::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        code,
        format!("{what} is too large"),
    )
}

/// File a job and keep what goes beside it. `archive` is the decoded trust
/// archive, if any. The id is taken only once the job is accepted, so a
/// refusal does not burn one.
fn file_job(
    d: &Daemon,
    project: &str,
    kind: JobKind,
    archive: Option<Vec<u8>>,
    reason: &str,
    requester: &str,
    context: Option<&str>,
) -> Result<(Job, u64), Fail> {
    let now = now();
    let policy = d.config.policy();
    let meta = JobMeta {
        requester: grant::printable(requester, 64),
        context: clean_context(context),
    };
    d.audited(|inner| {
        inner.jobs.tick(now, inner.grants.gate_mut(), &policy);
        prune_jobs(inner, now);
        let id = inner.grants.next_id();
        let mut entropy = ca::OsEntropy;
        let job = inner.jobs.request(
            now,
            inner.grants.gate_mut(),
            &policy,
            &mut entropy,
            id,
            project,
            kind,
            reason,
        )?;
        let taken = inner.grants.allocate_id();
        debug_assert_eq!(taken, id, "the id peeked is the id taken");
        if let Some(bytes) = archive {
            inner.archives.insert(id, bytes);
        }
        inner.job_meta.insert(id, meta);
        let expires = store::unix(job.created + policy.plan_timeout);
        Ok((job, expires))
    })
}

/// Drop what the daemon keeps beside a job once the job has moved past the
/// stage that needs it: the archive once the job is neither `Queued` nor
/// `Working`, the display once it is not `Waiting`, the claimed trust scope
/// once it is not `Claimed`, and the requester notes once it is over.
fn prune_jobs(inner: &mut Inner, now: SystemTime) {
    let ids: HashSet<u64> = inner
        .archives
        .keys()
        .chain(inner.job_meta.keys())
        .chain(inner.displays.keys())
        .chain(inner.claimed.keys())
        .copied()
        .collect();
    for id in ids {
        // (queued or working, waiting, claimed, over)
        let (early, waiting, claimed, over) = match inner.jobs.job(now, id).map(|j| &j.state) {
            None => (false, false, false, true),
            Some(JobState::Queued | JobState::Working { .. }) => (true, false, false, false),
            Some(JobState::Waiting { .. }) => (false, true, false, false),
            Some(JobState::Claimed) => (false, false, true, false),
            Some(JobState::Approved { .. }) => (false, false, false, false),
            Some(JobState::Done(_)) => (false, false, false, true),
        };
        if !early {
            inner.archives.remove(&id);
        }
        if !waiting {
            inner.displays.remove(&id);
        }
        if !claimed {
            inner.claimed.remove(&id);
        }
        if over {
            inner.job_meta.remove(&id);
        }
    }
}

/// Refuse a request the daemon would refuse anyway before spending any work
/// on its payload. Read-only; `file_job` still decides, under the lock.
fn precheck_job(d: &Daemon, project: &str) -> Result<(), Fail> {
    let (now, policy) = (now(), d.config.policy());
    d.audited(|inner| {
        // Settle anything that has timed out first, as `file_job` does, so a
        // lapsed job does not make this say `busy`.
        inner.jobs.tick(now, inner.grants.gate_mut(), &policy);
        prune_jobs(inner, now);
        inner
            .jobs
            .precheck(now, inner.grants.gate_mut(), &policy, project)
            .map_err(Fail::from)
    })
}

async fn trust(State(d): App, Json(body): Json<TrustBody>) -> Reply<JobReply> {
    precheck_job(&d, &body.project)?;
    // Bound the work before doing any of it: base64 grows data by 4/3.
    if body.archive.len() > MAX_ARCHIVE_BYTES.div_ceil(3) * 4 {
        return Err(too_large("archive_too_large", "the archive"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.archive.as_bytes())
        .map_err(|e| Fail::new(StatusCode::BAD_REQUEST, "bad_archive", e.to_string()))?;
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(too_large("archive_too_large", "the archive"));
    }
    let digest = scope::challenge_of(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let (job, expires) = file_job(
        &d,
        &body.project,
        JobKind::Trust {
            archive_sha256: digest,
        },
        Some(bytes),
        &body.reason,
        &body.requester,
        body.context.as_deref(),
    )?;
    Ok(Json(JobReply {
        id: job.id,
        match_code: job.match_code,
        expires,
    }))
}

async fn apply(State(d): App, Json(body): Json<ApplyBody>) -> Reply<JobReply> {
    precheck_job(&d, &body.project)?;
    if body.manifest.len() > MAX_MANIFEST_BYTES {
        return Err(too_large("manifest_too_large", "the manifest"));
    }
    let (job, expires) = file_job(
        &d,
        &body.project,
        JobKind::Apply {
            manifest: body.manifest,
            allow_destroy: body.allow_destroy,
        },
        None,
        &body.reason,
        &body.requester,
        body.context.as_deref(),
    )?;
    Ok(Json(JobReply {
        id: job.id,
        match_code: job.match_code,
        expires,
    }))
}

fn result_name(r: &JobResult) -> &'static str {
    match r {
        JobResult::Trusted => "trusted",
        JobResult::Applied => "applied",
        JobResult::Refused(_) => "refused",
        JobResult::PlanFailed(_) => "plan_failed",
        JobResult::ApplyFailed(_) => "apply_failed",
        JobResult::OutcomeUnknown => "outcome_unknown",
        JobResult::Declined => "declined",
        JobResult::TimedOut => "timed_out",
        JobResult::Killed => "killed",
    }
}

/// The agent's view of a job. It names the state and the result and nothing
/// else about the contents: no manifest, no archive.
fn job_status(job: &Job) -> JobStatus {
    let (kind, state, result) = (
        match job.kind {
            JobKind::Trust { .. } => "trust",
            JobKind::Apply { .. } => "apply",
        },
        match &job.state {
            JobState::Queued => "queued",
            JobState::Working { .. } => "working",
            JobState::Waiting { .. } => "waiting",
            JobState::Approved { .. } => "approved",
            JobState::Claimed => "claimed",
            JobState::Done(_) => "done",
        },
        match &job.state {
            JobState::Done(r) => Some(result_name(r).to_owned()),
            _ => None,
        },
    );
    JobStatus {
        id: job.id,
        project: job.project.clone(),
        kind: kind.to_owned(),
        state: state.to_owned(),
        result,
        failure: match &job.state {
            JobState::Done(
                JobResult::Refused(f) | JobResult::PlanFailed(f) | JobResult::ApplyFailed(f),
            ) => Some(failure_view(f)),
            _ => None,
        },
        // Task 8: the approver's view of the plan supplies this.
        summary: None,
    }
}

async fn job(State(d): App, Path(id): Path<u64>) -> Reply<JobStatus> {
    let now = now();
    let policy = d.config.policy();
    let status = d.with(|inner| {
        inner.jobs.tick(now, inner.grants.gate_mut(), &policy);
        inner.jobs.job(now, id).map(job_status)
    });
    status
        .map(Json)
        .ok_or_else(|| Fail::new(StatusCode::NOT_FOUND, "no_such_job", "no job with that id"))
}

async fn pending(State(d): App) -> Reply<ApproverState> {
    let (now, policy) = (now(), d.config.policy());
    let ttl = policy.pending_ttl;
    let state = d.with(|inner| {
        inner.jobs.tick(now, inner.grants.gate_mut(), &policy);
        prune_jobs(inner, now);
        ApproverState {
            pending: inner.grants.pending(now).map(|p| pending_view(p, ttl)),
            job: job_pending_view(inner, now, &policy),
            enrolled: inner.devices.len(),
            windows: window_views(inner, now),
        }
    });
    Ok(Json(state))
}

/// The approver's view of the job waiting on them. Built from the job
/// itself, only while it is `Waiting`; the display text is read beside it
/// and an entry in `displays` without a waiting job shows nothing.
fn job_pending_view(inner: &mut Inner, now: SystemTime, policy: &Policy) -> Option<JobPendingView> {
    let job = inner.jobs.waiting(now)?.clone();
    let JobState::Waiting {
        scope,
        nonce,
        since,
    } = &job.state
    else {
        return None;
    };
    let meta = inner.job_meta.get(&job.id);
    Some(JobPendingView {
        id: job.id,
        project: job.project.clone(),
        kind: match job.kind {
            JobKind::Trust { .. } => "trust",
            JobKind::Apply { .. } => "apply",
        }
        .to_owned(),
        match_code: job.match_code.clone(),
        nonce: nonce.clone(),
        reason: job.reason.clone(),
        requester: meta.map(|m| m.requester.clone()).unwrap_or_default(),
        context: meta.and_then(|m| m.context.clone()),
        created: store::unix(job.created),
        expires: store::unix(*since + policy.approval_ttl),
        scope: scope_to_wire(scope),
        display: inner.displays.get(&job.id).cloned().unwrap_or_default(),
    })
}

async fn approve_start(State(d): App, Json(body): Json<ById>) -> Reply<RequestChallengeResponse> {
    let (now, policy) = (now(), d.config.policy());
    d.with(|inner| {
        if inner.devices.is_empty() {
            return Err(Fail::new(
                StatusCode::PRECONDITION_FAILED,
                "no_devices",
                "no approver device is enrolled; run `shoephoned enroll` at the console",
            ));
        }
        inner.jobs.tick(now, inner.grants.gate_mut(), &policy);
        // At most one of an SSH request and a job is waiting, so whichever
        // has this id is the subject of the ceremony.
        let (nonce, scope) = match inner.grants.pending(now).filter(|p| p.id == body.id) {
            Some(p) => (p.nonce.clone(), CeremonyScope::Ssh(p.scope.clone())),
            None => match inner.jobs.waiting(now) {
                Some(Job {
                    id,
                    state: JobState::Waiting { scope, nonce, .. },
                    ..
                }) if *id == body.id => (nonce.clone(), CeremonyScope::Job(scope.clone())),
                _ => return Err(Refusal::NoSuchRequest.into()),
            },
        };
        let bound = match &scope {
            CeremonyScope::Ssh(s) => Some(grant::bound_challenge(s, &nonce)),
            CeremonyScope::Job(s) => s.bytes_to_sign(&nonce).map(|b| scope::challenge_of(&b)),
        }
        .ok_or_else(|| {
            Fail::new(
                StatusCode::CONFLICT,
                "malformed_scope",
                "the waiting scope is malformed and cannot be signed",
            )
        })?;
        let keys: Vec<SecurityKey> = inner.devices.iter().map(|x| x.key.clone()).collect();
        let (challenge, auth) = d
            .webauthn
            .start_securitykey_authentication(&keys)
            .map_err(|e| Fail::internal(format!("webauthn: {e}")))?;
        let (challenge, auth) = bind_challenge(challenge, auth, &bound).map_err(Fail::internal)?;
        inner.approve = Some(ApproveCeremony {
            id: body.id,
            nonce,
            scope,
            auth,
            started: now,
        });
        Ok(Json(challenge))
    })
}

async fn approve_finish(
    State(d): App,
    Json(body): Json<ApproveFinish<PublicKeyCredential>>,
) -> Reply<serde_json::Value> {
    let (now, policy) = (now(), d.config.policy());
    d.audited(|inner| {
        let ceremony = inner
            .approve
            .take()
            .filter(|c| c.id == body.id && c.started + CEREMONY_TTL > now)
            .ok_or_else(|| {
                Fail::new(
                    StatusCode::CONFLICT,
                    "no_ceremony",
                    "no approval in progress for that request; start again",
                )
            })?;
        let result = d
            .webauthn
            .finish_securitykey_authentication(&body.credential, &ceremony.auth)
            .map_err(|e| Fail::new(StatusCode::FORBIDDEN, "assertion_rejected", e.to_string()))?;
        // The flags are re-read on every assertion: a credential can turn
        // backup-eligible after enrollment (never the reverse), and a device
        // enrolled while the stopgap was on must stop working once it is off.
        refuse_synced(
            result.backup_eligible(),
            result.backup_state(),
            d.config.allow_synced_credentials,
        )?;
        let device = inner
            .devices
            .iter_mut()
            .find(|x| x.key.cred_id() == result.cred_id())
            .ok_or_else(|| {
                Fail::new(
                    StatusCode::FORBIDDEN,
                    "unknown_device",
                    "credential is not enrolled",
                )
            })?;
        let device_name = device.name.clone();
        if device.key.update_credential(&result) == Some(true) {
            d.store
                .save_devices(&inner.devices)
                .map_err(Fail::internal)?;
        }
        match ceremony.scope {
            CeremonyScope::Ssh(scope) => {
                let approval = Approval {
                    id: ceremony.id,
                    nonce: ceremony.nonce,
                    scope,
                };
                let window = inner.grants.approve(now, &approval)?;
                Ok(Json(serde_json::json!({
                    "approved": window.id,
                    "host": window.scope.host,
                    "ends_at": store::unix(window.scope.ends_at),
                    "device": device_name,
                })))
            }
            CeremonyScope::Job(scope) => {
                // A trust is judged against the baseline now on disk, as the
                // runner endpoints do, so an `untrust` since the last look
                // counts.
                refresh_trusted(&d, inner)?;
                inner.jobs.approve(
                    now,
                    inner.grants.gate_mut(),
                    &policy,
                    ceremony.id,
                    &ceremony.nonce,
                    &scope,
                )?;
                Ok(Json(serde_json::json!({
                    "approved": ceremony.id,
                    "device": device_name,
                })))
            }
        }
    })
}

async fn decline(State(d): App, Json(body): Json<ById>) -> Reply<serde_json::Value> {
    let (now, policy) = (now(), d.config.policy());
    d.with(|inner| {
        inner.approve = None;
        inner.jobs.tick(now, inner.grants.gate_mut(), &policy);
        if inner.jobs.waiting(now).is_some_and(|j| j.id == body.id) {
            inner
                .jobs
                .decline(now, inner.grants.gate_mut(), &policy, body.id)
        } else {
            inner.grants.decline(now, body.id)
        }
    })?;
    Ok(Json(serde_json::json!({ "declined": body.id })))
}

fn check_code(d: &Daemon, submitted: &str, now: SystemTime) -> Result<EnrollCode, Fail> {
    let mut code = d
        .store
        .load_enroll_code()
        .map_err(Fail::internal)?
        .ok_or_else(|| {
            Fail::new(
                StatusCode::PRECONDITION_FAILED,
                "no_enroll_code",
                "no enrollment is open; run `shoephoned enroll` at the console",
            )
        })?;
    if code.expires_at <= store::unix(now) {
        d.store.clear_enroll_code().map_err(Fail::internal)?;
        return Err(Fail::new(
            StatusCode::GONE,
            "enroll_expired",
            "the enrollment code expired",
        ));
    }
    let normalized: String = submitted
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if store::sha256_hex(&normalized) != code.sha256 {
        code.failures += 1;
        if code.failures >= EnrollCode::MAX_FAILURES {
            d.store.clear_enroll_code().map_err(Fail::internal)?;
        } else {
            d.store.save_enroll_code(&code).map_err(Fail::internal)?;
        }
        return Err(Fail::new(
            StatusCode::FORBIDDEN,
            "bad_enroll_code",
            "wrong code",
        ));
    }
    Ok(code)
}

async fn enroll_start(
    State(d): App,
    Json(body): Json<EnrollStart>,
) -> Reply<CreationChallengeResponse> {
    let now = now();
    d.with(|inner| {
        // Under the lock: the failure counter is read-modify-write on disk,
        // and concurrent guesses must each cost a strike.
        let code = check_code(&d, &body.code, now)?;
        let exclude: Vec<CredentialID> = inner
            .devices
            .iter()
            .map(|x| x.key.cred_id().clone())
            .collect();
        let (challenge, reg) = d
            .webauthn
            .start_securitykey_registration(
                Uuid::new_v4(),
                &code.device_name,
                &code.device_name,
                Some(exclude),
                None,
                None,
            )
            .map_err(|e| Fail::internal(format!("webauthn: {e}")))?;
        inner.enroll = Some(EnrollCeremony {
            device_name: code.device_name,
            reg,
            started: now,
        });
        Ok(Json(challenge))
    })
}

/// Finish enrollment. Transactional: the new device is written to disk
/// before it is added to `inner.devices`, and the enrollment code is only
/// consumed after that write succeeds, so a failure partway through cannot
/// leave a live device the disk does not know about, nor a consumed code
/// that is still valid with nothing enrolled to show for it.
async fn enroll_finish(
    State(d): App,
    Json(body): Json<EnrollFinish<RegisterPublicKeyCredential>>,
) -> Reply<serde_json::Value> {
    let now = now();
    d.with(|inner| {
        check_code(&d, &body.code, now)?;
        let ceremony = inner
            .enroll
            .take()
            .filter(|c| c.started + CEREMONY_TTL > now)
            .ok_or_else(|| {
                Fail::new(
                    StatusCode::CONFLICT,
                    "no_ceremony",
                    "no enrollment in progress; start again",
                )
            })?;
        let key = d
            .webauthn
            .finish_securitykey_registration(&body.credential, &ceremony.reg)
            .map_err(|e| {
                Fail::new(
                    StatusCode::FORBIDDEN,
                    "registration_rejected",
                    e.to_string(),
                )
            })?;
        let cred = webauthn_rs::prelude::Credential::from(key.clone());
        refuse_synced(
            cred.backup_eligible,
            cred.backup_state,
            d.config.allow_synced_credentials,
        )?;
        // One name, one device. Enrolling over a name that is already taken
        // used to add a second device answering to it, which is how a
        // routine app reinstall left two approvers called the same thing and
        // no way to tell from the name which one still worked. Refuse here
        // rather than replace: the device holding that name may be the only
        // one that can approve, and removing it is a decision for whoever is
        // at the console, made with `shoephoned forget --id <handle>`.
        if inner.devices.iter().any(|x| x.name == ceremony.device_name) {
            return Err(Fail::new(
                StatusCode::CONFLICT,
                "name_taken",
                format!(
                    "a device named {:?} is already enrolled; remove it with `shoephoned forget` or enroll under another name",
                    ceremony.device_name
                ),
            ));
        }
        // A secret only the enrolling app ever sees, so `push/register`
        // later has something to authenticate against besides the
        // credential id, which `approve/start` hands to anyone who can
        // reach the daemon.
        let mut secret_bytes = [0u8; 32];
        ca::OsEntropy.fill(&mut secret_bytes);
        let secret: String = secret_bytes.iter().map(|b| format!("{b:02x}")).collect();
        // Build the new device list and write it before touching
        // `inner.devices`, and only consume the enrollment code once that
        // write has landed. A failed write here must leave neither a live
        // device the disk does not know about (if `inner.devices` were
        // updated first and the save then failed, the device would work
        // for the rest of this process's life but vanish on restart) nor a
        // consumed code that is still valid (if the code were cleared
        // before the save and the save then failed, the enrollment would
        // be unrecoverable without minting a new code). If the code fails
        // to clear after a successful save, the device is already durable,
        // so this rolls the device list back rather than leave a device
        // enrolled with no way to tell the operator it did not fully land.
        let mut devices = inner.devices.clone();
        devices.push(Device {
            name: ceremony.device_name.clone(),
            enrolled_at: store::unix(now),
            key,
            push_token: None,
            push_kinds: None,
            push_secret_sha256: Some(store::sha256_hex(&secret)),
        });
        d.store.save_devices(&devices).map_err(Fail::internal)?;
        if let Err(e) = d.store.clear_enroll_code() {
            if let Err(rollback) = d.store.save_devices(&inner.devices) {
                eprintln!(
                    "shoephoned: enroll: failed to clear the code ({e}), and failed to roll back the device list ({rollback}); the state directory now disagrees with `inner.devices` until the next successful save"
                );
            }
            return Err(Fail::internal(e));
        }
        inner.devices = devices;
        eprintln!("shoephoned: enrolled device {:?}", ceremony.device_name);
        Ok(Json(serde_json::json!({
            "enrolled": ceremony.device_name,
            "push_secret": secret,
        })))
    })
}

/// Refuse a credential the authenticator marks as backup-eligible or backed
/// up unless the config's stopgap is on. Both flags are checked: a provider
/// that syncs sets BE, and BS says a copy already exists elsewhere. A
/// device-bound authenticator (a hardware key, a Secure Enclave key that is
/// never exported) sets neither.
fn refuse_synced(backup_eligible: bool, backup_state: bool, allow: bool) -> Result<(), Fail> {
    if allow || !(backup_eligible || backup_state) {
        return Ok(());
    }
    Err(Fail::new(
        StatusCode::FORBIDDEN,
        "synced_credential",
        "this credential syncs to other devices; the approver must be a device-bound key",
    ))
}

/// The app hands over its APNs device token, bound to the credential it
/// enrolled with. This is authenticated, unlike the rest of the approver
/// API: the credential id alone is not a secret (`approve/start` discloses
/// every enrolled device's credential id to anyone who can reach the
/// daemon), so registering a push token also requires the per-device secret
/// minted at enrollment, which only the enrolling app ever saw. Without that
/// check a stranger who can reach the daemon could point another device's
/// notifications, including the request-waiting push that starts the
/// approval ceremony, at a token of their own choosing.
async fn push_register(State(d): App, Json(body): Json<PushRegister>) -> Reply<serde_json::Value> {
    let token = body.token.to_ascii_lowercase();
    if token.is_empty() || token.len() > 200 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Fail::new(
            StatusCode::BAD_REQUEST,
            "bad_token",
            "token must be the device token as hex",
        ));
    }
    let kinds = match body.kinds {
        None => None,
        Some(list) => {
            let known: Vec<&str> = Push::ALL.iter().map(|p| p.kind()).collect();
            if let Some(bad) = list.iter().find(|k| !known.contains(&k.as_str())) {
                return Err(Fail::new(
                    StatusCode::BAD_REQUEST,
                    "bad_kind",
                    format!("unknown push kind {bad:?}; known: {}", known.join(", ")),
                ));
            }
            Some(list)
        }
    };
    d.with(|inner| {
        let device = inner
            .devices
            .iter_mut()
            .find(|x| x.key.cred_id()[..] == body.credential_id[..])
            .ok_or_else(|| {
                Fail::new(
                    StatusCode::FORBIDDEN,
                    "unknown_device",
                    "credential is not enrolled",
                )
            })?;
        check_push_secret(device.push_secret_sha256.as_deref(), &body.secret)?;
        device.push_token = Some(token);
        device.push_kinds = kinds;
        let name = device.name.clone();
        d.store
            .save_devices(&inner.devices)
            .map_err(Fail::internal)?;
        eprintln!("shoephoned: push token registered for device {name:?}");
        Ok(Json(serde_json::json!({ "registered": name })))
    })
}

/// Check a `push/register` secret against the hash stored at enrollment.
/// Takes the hash rather than a whole [`Device`] because a `Device` embeds a
/// real `SecurityKey` credential, which nothing outside a live WebAuthn
/// ceremony can construct, and this check has nothing to do with the
/// credential anyway.
fn check_push_secret(stored: Option<&str>, submitted: &str) -> Result<(), Fail> {
    let stored = stored.ok_or_else(|| {
        Fail::new(
            StatusCode::FORBIDDEN,
            "reenroll_required",
            "this device enrolled before push registration was authenticated; enroll it again",
        )
    })?;
    if ct_eq(store::sha256_hex(submitted).as_bytes(), stored.as_bytes()) {
        Ok(())
    } else {
        Err(Fail::new(
            StatusCode::FORBIDDEN,
            "bad_secret",
            "wrong device secret",
        ))
    }
}

/// Constant-time byte comparison: XOR every corresponding byte and branch
/// only once, on the accumulated result, so a wrong secret cannot be brute
/// forced a byte at a time by timing how much of it matched.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn ledger(State(d): App, Query(q): Query<LedgerQuery>) -> Reply<Vec<LedgerEntry>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    d.store
        .read_ledger(q.before, limit)
        .map(Json)
        .map_err(Fail::internal)
}

/// Test hook: approve the pending request with no ceremony at all. Only
/// compiled with the `test-hooks` feature, which integration tests enable
/// and deployed builds must not.
#[cfg(feature = "test-hooks")]
async fn test_approve(State(d): App, Json(body): Json<ById>) -> Reply<serde_json::Value> {
    let (now, policy) = (now(), d.config.policy());
    d.audited(|inner| {
        let Some(p) = inner
            .grants
            .pending(now)
            .filter(|p| p.id == body.id)
            .cloned()
        else {
            return approve_waiting_job(&d, inner, now, &policy, body.id);
        };
        let window = inner.grants.approve(
            now,
            &Approval {
                id: p.id,
                nonce: p.nonce,
                scope: p.scope,
            },
        )?;
        Ok(Json(serde_json::json!({ "approved": window.id })))
    })
}

// ---------------------------------------------------------------------
// Runner endpoints
// ---------------------------------------------------------------------

/// Header carrying the request's Unix time in seconds.
const TIMESTAMP_HEADER: &str = "shoephone-runner-timestamp";
/// Header carrying the request's single-use nonce.
const NONCE_HEADER: &str = "shoephone-runner-nonce";

/// Request body limit for `submit`: a diff and a manifest in JSON.
const SUBMIT_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// A runner refusal is a 401 whichever way the signature failed; the other
/// meanings of these refusals keep their statuses elsewhere.
fn runner_refusal(r: Refusal) -> Fail {
    match r {
        Refusal::WrongRunner => Fail::new(
            StatusCode::UNAUTHORIZED,
            "wrong_runner",
            "the request is not signed by a known runner",
        ),
        Refusal::StaleSignature => Fail::new(
            StatusCode::UNAUTHORIZED,
            "stale_signature",
            "the request is stale or was replayed",
        ),
        other => other.into(),
    }
}

/// Verify a runner request and return the runner's name. `job` is the id
/// the signature covers: the body's, the path's, or none.
fn authenticate(
    d: &Daemon,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    job: Option<u64>,
) -> Result<String, Fail> {
    let unsigned = || {
        Fail::new(
            StatusCode::UNAUTHORIZED,
            "unsigned",
            "the request lacks a runner signature, timestamp or nonce",
        )
    };
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let runner = get(runner_auth::RUNNER_HEADER).ok_or_else(unsigned)?;
    let signature = get(runner_auth::SIGNATURE_HEADER).ok_or_else(unsigned)?;
    let nonce = get(NONCE_HEADER).ok_or_else(unsigned)?;
    let timestamp: u64 = get(TIMESTAMP_HEADER)
        .and_then(|t| t.parse().ok())
        .ok_or_else(unsigned)?;
    d.with(|inner| {
        inner.verifier.verify(
            now(),
            Instant::now(),
            runner,
            signature,
            (method, path, body, job, timestamp, nonce),
        )
    })
    .map_err(runner_refusal)?;
    Ok(runner.to_owned())
}

/// The `id` a runner request body names, read before the signature is
/// checked only so the signed message can be rebuilt. Nothing else in the
/// body is looked at until the signature holds.
fn body_id(body: &[u8]) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct Peek {
        id: Option<u64>,
    }
    serde_json::from_slice::<Peek>(body).ok().and_then(|p| p.id)
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Fail> {
    serde_json::from_slice(body)
        .map_err(|e| Fail::new(StatusCode::BAD_REQUEST, "bad_request", e.to_string()))
}

fn bad_request(error: impl Into<String>) -> Fail {
    Fail::new(StatusCode::BAD_REQUEST, "bad_request", error)
}

fn inconsistent(error: impl Into<String>) -> Fail {
    Fail::new(StatusCode::BAD_REQUEST, "inconsistent_scope", error)
}

fn failure_from_view(v: FailureView) -> Result<Failure, Fail> {
    let category_ok = (1..=64).contains(&v.category.len())
        && v.category
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !category_ok {
        return Err(bad_request("failure category must match [a-z0-9_]{1,64}"));
    }
    Ok(Failure {
        category: v.category,
        addresses: v
            .addresses
            .iter()
            .take(1000)
            .map(|a| grant::printable(a, 512))
            .collect(),
        detail: v.detail.map(|d| grant::printable(&d, 2048)),
    })
}

fn failure_view(f: &Failure) -> FailureView {
    FailureView {
        category: f.category.clone(),
        addresses: f.addresses.clone(),
        detail: f.detail.clone(),
    }
}

fn baseline_name(b: BaselineStatus) -> &'static str {
    match b {
        BaselineStatus::None => "none",
        BaselineStatus::Applied => "applied",
        BaselineStatus::Uncertain => "uncertain",
    }
}

fn scope_from_wire(w: JobScopeWire) -> Result<JobScope, Fail> {
    Ok(match w {
        JobScopeWire::Trust(t) => JobScope::Trust(TrustScope {
            project: t.project,
            baseline: t.baseline,
            candidate: t.candidate,
            diff: t.diff,
            schema: t.schema,
            policy_version: t.policy_version,
            files_changed: t.files_changed,
            lines_added: t.lines_added,
            lines_removed: t.lines_removed,
            schema_changed: t.schema_changed,
        }),
        JobScopeWire::Apply(a) => JobScope::Apply(ApplyScope {
            project: a.project,
            revision: a.revision,
            schema: a.schema,
            manifest: a.manifest,
            baseline_manifest: a.baseline_manifest,
            baseline_status: match a.baseline_status.as_str() {
                "none" => BaselineStatus::None,
                "applied" => BaselineStatus::Applied,
                "uncertain" => BaselineStatus::Uncertain,
                other => return Err(bad_request(format!("unknown baseline_status {other:?}"))),
            },
            plan: a.plan,
            destructive: a.destructive,
            counts: Counts {
                create: a.counts.create,
                update: a.counts.update,
                replace: a.counts.replace,
                delete: a.counts.delete,
            },
            addresses: a.addresses,
        }),
    })
}

fn scope_to_wire(s: &JobScope) -> JobScopeWire {
    match s {
        JobScope::Trust(t) => JobScopeWire::Trust(TrustScopeWire {
            project: t.project.clone(),
            baseline: t.baseline.clone(),
            candidate: t.candidate.clone(),
            diff: t.diff.clone(),
            schema: t.schema.clone(),
            policy_version: t.policy_version,
            files_changed: t.files_changed,
            lines_added: t.lines_added,
            lines_removed: t.lines_removed,
            schema_changed: t.schema_changed,
        }),
        JobScope::Apply(a) => JobScopeWire::Apply(ApplyScopeWire {
            project: a.project.clone(),
            revision: a.revision.clone(),
            schema: a.schema.clone(),
            manifest: a.manifest.clone(),
            baseline_manifest: a.baseline_manifest.clone(),
            baseline_status: baseline_name(a.baseline_status).to_owned(),
            plan: a.plan.clone(),
            destructive: a.destructive,
            counts: CountsWire {
                create: a.counts.create,
                update: a.counts.update,
                replace: a.counts.replace,
                delete: a.counts.delete,
            },
            addresses: a.addresses.clone(),
        }),
    }
}

/// Parse `"{action} {address}\n"` lines; `None` unless the text is exactly
/// what [`scope::address_text`] would write for the changes it names.
fn parse_address_text(text: &str) -> Option<Vec<(Action, String)>> {
    let mut changes = Vec::new();
    for line in text.split_terminator('\n') {
        let (action, address) = line.split_once(' ')?;
        let action = match action {
            "create" => Action::Create,
            "update" => Action::Update,
            "replace" => Action::Replace,
            "delete" => Action::Delete,
            _ => return None,
        };
        changes.push((action, address.to_owned()));
    }
    (scope::address_text(&changes).as_deref() == Some(text)).then_some(changes)
}

/// True when `text` parses as a JSON object, which the approve page needs in
/// order to list the variable changes.
fn is_json_object(text: &str) -> bool {
    matches!(
        serde_json::from_str::<serde_json::Value>(text),
        Ok(serde_json::Value::Object(_))
    )
}

/// Check every digest in a submitted scope against the text the approver
/// will read, and the counts and destructive flag against the addresses.
fn check_consistency(scope: &JobScopeWire, display: &DisplayWire) -> Result<(), Fail> {
    match scope {
        JobScopeWire::Trust(t) => {
            if display.manifest.is_some()
                || display.baseline_manifest.is_some()
                || display.address_text.is_some()
            {
                return Err(inconsistent("a trust display carries apply-only fields"));
            }
            if display.external {
                if display.diff.is_some() {
                    return Err(inconsistent(
                        "an external trust display must not carry a diff",
                    ));
                }
                if display.verify_command.as_deref().is_none_or(str::is_empty) {
                    return Err(inconsistent(
                        "an external trust display needs a verify_command",
                    ));
                }
                return Ok(());
            }
            if display.verify_command.is_some() {
                return Err(inconsistent(
                    "a trust display with a diff must not carry a verify_command",
                ));
            }
            let diff = display
                .diff
                .as_deref()
                .ok_or_else(|| inconsistent("the display carries no diff"))?;
            if store::sha256_hex(diff) != t.diff {
                return Err(inconsistent("the diff digest does not match the display"));
            }
        }
        JobScopeWire::Apply(a) => {
            if display.diff.is_some() || display.external || display.verify_command.is_some() {
                return Err(inconsistent("an apply display carries trust-only fields"));
            }
            let manifest = display
                .manifest
                .as_deref()
                .ok_or_else(|| inconsistent("the display carries no manifest"))?;
            if store::sha256_hex(manifest) != a.manifest {
                return Err(inconsistent(
                    "the manifest digest does not match the display",
                ));
            }
            if !is_json_object(manifest) {
                return Err(inconsistent("the manifest is not a JSON object"));
            }
            match (&a.baseline_manifest, &display.baseline_manifest) {
                (None, None) => {}
                (Some(digest), Some(text)) if store::sha256_hex(text) == *digest => {
                    if !is_json_object(text) {
                        return Err(inconsistent("the baseline manifest is not a JSON object"));
                    }
                }
                _ => {
                    return Err(inconsistent(
                        "the baseline manifest digest does not match the display",
                    ));
                }
            }
            if (a.baseline_status == "none") != a.baseline_manifest.is_none() {
                return Err(inconsistent(
                    "the baseline status does not match the baseline manifest",
                ));
            }
            let text = display
                .address_text
                .as_deref()
                .ok_or_else(|| inconsistent("the display carries no address text"))?;
            if store::sha256_hex(text) != a.addresses {
                return Err(inconsistent(
                    "the address digest does not match the display",
                ));
            }
            let changes = parse_address_text(text)
                .ok_or_else(|| inconsistent("the address text is not well formed"))?;
            let count =
                |want: Action| changes.iter().filter(|(action, _)| *action == want).count() as u64;
            let counts = &a.counts;
            if count(Action::Create) != u64::from(counts.create)
                || count(Action::Update) != u64::from(counts.update)
                || count(Action::Replace) != u64::from(counts.replace)
                || count(Action::Delete) != u64::from(counts.delete)
            {
                return Err(inconsistent("the counts do not match the addresses"));
            }
            if a.destructive != (counts.delete > 0 || counts.replace > 0) {
                return Err(inconsistent(
                    "the destructive flag does not match the counts",
                ));
            }
        }
    }
    Ok(())
}

/// Make `records` what the daemon trusts, in memory and in `Jobs`. A project
/// with no record is trusted at nothing.
fn sync_trusted(d: &Daemon, inner: &mut Inner, records: Vec<TrustRecord>) {
    inner.trusted = records
        .into_iter()
        .map(|r| (r.project.clone(), r))
        .collect();
    for project in d.config.projects.keys() {
        let digest = inner.trusted.get(project).map(|r| r.digest.clone());
        inner.jobs.set_trusted(project, digest);
    }
}

/// Read `trusted.json` again, so a `shoephoned untrust` run since the last
/// look takes effect without a restart. Fails closed: if the file cannot be
/// read, the caller is refused rather than served from a copy that may be
/// out of date.
fn refresh_trusted(d: &Daemon, inner: &mut Inner) -> Result<(), Fail> {
    let records = d.store.load_trusted().map_err(|e| {
        eprintln!("shoephoned: trusted: {e}");
        Fail::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust_unreadable",
            "the trust registry could not be read",
        )
    })?;
    sync_trusted(d, inner, records);
    Ok(())
}

fn runner_job(job: &Job, trusted: &BTreeMap<String, TrustRecord>) -> RunnerJob {
    let (kind, manifest, allow_destroy) = match &job.kind {
        JobKind::Trust { .. } => ("trust", None, false),
        JobKind::Apply {
            manifest,
            allow_destroy,
        } => ("apply", Some(manifest.clone()), *allow_destroy),
    };
    RunnerJob {
        id: job.id,
        project: job.project.clone(),
        kind: kind.to_owned(),
        state: match job.state {
            JobState::Approved { .. } => "approved",
            _ => "working",
        }
        .to_owned(),
        manifest,
        allow_destroy,
        trusted: trusted.get(&job.project).cloned(),
    }
}

async fn runner_poll(State(d): App, headers: HeaderMap, body: Bytes) -> Reply<Option<RunnerJob>> {
    let runner = authenticate(&d, &headers, "POST", "/api/runner/poll", &body, None)?;
    let (now, policy) = (now(), d.config.policy());
    d.audited(|inner| {
        refresh_trusted(&d, inner)?;
        inner.jobs.tick(now, inner.grants.gate_mut(), &policy);
        prune_jobs(inner, now);
        let job = inner.jobs.poll(now, inner.grants.gate_mut(), &runner);
        Ok(Json(job.map(|j| runner_job(&j, &inner.trusted))))
    })
}

async fn runner_archive(
    State(d): App,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Response, Fail> {
    let path = format!("/api/runner/archive/{id}");
    let runner = authenticate(&d, &headers, "GET", &path, b"", Some(id))?;
    let (now, policy) = (now(), d.config.policy());
    let bytes = d.with(|inner| {
        inner.jobs.tick(now, inner.grants.gate_mut(), &policy);
        prune_jobs(inner, now);
        let working = inner
            .jobs
            .job(now, id)
            .is_some_and(|j| matches!(&j.state, JobState::Working { runner: r } if *r == runner));
        if working {
            inner.archives.get(&id).cloned()
        } else {
            None
        }
    });
    match bytes {
        Some(bytes) => Ok(([(header::CONTENT_TYPE, "application/gzip")], bytes).into_response()),
        None => Err(Fail::new(
            StatusCode::NOT_FOUND,
            "no_archive",
            "no archive is available for that job",
        )),
    }
}

async fn runner_submit(State(d): App, headers: HeaderMap, body: Bytes) -> Reply<serde_json::Value> {
    let runner = authenticate(
        &d,
        &headers,
        "POST",
        "/api/runner/submit",
        &body,
        body_id(&body),
    )?;
    let req: SubmitBody = parse_body(&body)?;
    check_consistency(&req.scope, &req.display)?;
    let scope = scope_from_wire(req.scope)?;
    let now = now();
    d.audited(|inner| {
        let mut entropy = ca::OsEntropy;
        inner.jobs.submit(
            now,
            inner.grants.gate_mut(),
            &runner,
            req.id,
            scope,
            &mut entropy,
        )?;
        inner.displays.insert(req.id, req.display);
        prune_jobs(inner, now);
        Ok(Json(serde_json::json!({})))
    })
}

async fn runner_refuse(State(d): App, headers: HeaderMap, body: Bytes) -> Reply<serde_json::Value> {
    let runner = authenticate(
        &d,
        &headers,
        "POST",
        "/api/runner/refuse",
        &body,
        body_id(&body),
    )?;
    let req: RefuseBody = parse_body(&body)?;
    let failure = failure_from_view(req.failure)?;
    let result = match req.result.as_str() {
        "refused" => JobResult::Refused(failure),
        "plan_failed" => JobResult::PlanFailed(failure),
        other => return Err(bad_request(format!("unknown result {other:?}"))),
    };
    let now = now();
    d.with(|inner| {
        inner
            .jobs
            .refuse(now, inner.grants.gate_mut(), &runner, req.id, result)?;
        prune_jobs(inner, now);
        Ok(Json(serde_json::json!({})))
    })
}

async fn runner_claim(State(d): App, headers: HeaderMap, body: Bytes) -> Reply<JobScopeWire> {
    let runner = authenticate(
        &d,
        &headers,
        "POST",
        "/api/runner/claim",
        &body,
        body_id(&body),
    )?;
    let req: ById = parse_body(&body)?;
    let now = now();
    d.audited(|inner| {
        refresh_trusted(&d, inner)?;
        let scope = inner.jobs.claim(now, &runner, req.id)?;
        if let JobScope::Trust(t) = &scope {
            inner.claimed.insert(req.id, t.clone());
        }
        prune_jobs(inner, now);
        Ok(Json(scope_to_wire(&scope)))
    })
}

async fn runner_finish(State(d): App, headers: HeaderMap, body: Bytes) -> Reply<serde_json::Value> {
    let runner = authenticate(
        &d,
        &headers,
        "POST",
        "/api/runner/finish",
        &body,
        body_id(&body),
    )?;
    let req: FinishBody = parse_body(&body)?;
    let result = match (req.result.as_str(), req.failure.clone()) {
        ("trusted", _) => JobResult::Trusted,
        ("applied", _) => JobResult::Applied,
        ("outcome_unknown", _) => JobResult::OutcomeUnknown,
        ("apply_failed", Some(f)) => JobResult::ApplyFailed(failure_from_view(f)?),
        ("apply_failed", None) => return Err(bad_request("apply_failed needs a failure")),
        (other, _) => return Err(bad_request(format!("unknown result {other:?}"))),
    };
    let now = now();
    // Only `trusted` goes through `audited`: it changes what a project may
    // apply from, so it is refused up front (`ledger_unavailable`, before
    // any state changes) once the ledger cannot be trusted, and if the
    // append of its own event fails the trust is taken back (see
    // `undo_trust`). Every other outcome stays on `with`, as `kill` and
    // `decline` do, so a job can always be ended and a runner can always say
    // what happened to an apply.
    if result == JobResult::Trusted {
        d.audited_or_undo(
            |inner| finish_trusted(&d, inner, now, &runner, &req),
            |inner, undo| undo_trust(&d, inner, undo),
        )
    } else {
        d.with(|inner| finish_other(inner, now, &runner, &req, result))
    }
}

fn finish_failure(e: Refusal) -> Fail {
    match e {
        Refusal::ScopeMismatch => Fail::new(
            StatusCode::BAD_REQUEST,
            "scope_mismatch",
            "that result does not fit this kind of job",
        ),
        other => other.into(),
    }
}

/// The project a finish names: the job's, or, for a job the daemon does not
/// know, the one the runner says.
fn finish_project(inner: &mut Inner, now: SystemTime, req: &FinishBody) -> Result<String, Fail> {
    match inner.jobs.job(now, req.id) {
        Some(job) => Ok(job.project.clone()),
        None => req.project.clone().ok_or_else(|| {
            Fail::new(
                StatusCode::BAD_REQUEST,
                "project_required",
                "the daemon does not know that job; say which project it belongs to",
            )
        }),
    }
}

fn finish_other(
    inner: &mut Inner,
    now: SystemTime,
    runner: &str,
    req: &FinishBody,
    result: JobResult,
) -> Reply<serde_json::Value> {
    let project = finish_project(inner, now, req)?;
    inner
        .jobs
        .finish(now, runner, &project, req.id, result)
        .map_err(finish_failure)?;
    inner.claimed.remove(&req.id);
    prune_jobs(inner, now);
    Ok(Json(serde_json::json!({})))
}

/// What it takes to put a trust back as it was.
struct TrustUndo {
    id: u64,
    record: TrustRecord,
    previous: Option<TrustRecord>,
    scope: TrustScope,
    meta: Option<JobMeta>,
}

/// Record a trust. It goes on disk before the job is marked done, so a
/// failed write leaves the job Claimed and the runner can retry; the caller
/// takes it back with [`undo_trust`] if the ledger then cannot record it.
fn finish_trusted(
    d: &Daemon,
    inner: &mut Inner,
    now: SystemTime,
    runner: &str,
    req: &FinishBody,
) -> Result<(Json<serde_json::Value>, TrustUndo), Fail> {
    refresh_trusted(d, inner)?;
    let project = finish_project(inner, now, req)?;
    // Check first that `Jobs::finish` will accept it.
    let (is_trust, claimed) = match inner.jobs.job(now, req.id) {
        Some(job) => (
            matches!(job.kind, JobKind::Trust { .. }),
            job.state == JobState::Claimed,
        ),
        None => return Err(Refusal::NoSuchRequest.into()),
    };
    if inner.jobs.runner_of(&project) != Some(runner) {
        return Err(Refusal::WrongRunner.into());
    }
    if !is_trust {
        return Err(finish_failure(Refusal::ScopeMismatch));
    }
    let scope = match inner.claimed.get(&req.id) {
        Some(scope) if claimed => scope.clone(),
        _ => return Err(Refusal::NoSuchRequest.into()),
    };
    let record = TrustRecord {
        project: project.clone(),
        digest: scope.candidate.clone(),
        schema: scope.schema.clone(),
        job: req.id,
        at: store::unix(now),
    };
    let mut previous = None;
    let mut stale = false;
    // A failed write deliberately does not set `ledger_failed`: that flag
    // is sticky until restart and would refuse the retry this ordering
    // exists to allow. Nothing was recorded anywhere, so no audit gap
    // opened; the job is still Claimed and the runner is told to retry.
    let written = d.store.update_trusted(|mut records| {
        previous = records.iter().find(|r| r.project == project).cloned();
        // The trust may have changed (an `untrust`) since the claim; the
        // approver signed a change against the baseline in the scope.
        if previous.as_ref().map(|r| &r.digest) != scope.baseline.as_ref() {
            stale = true;
            return (None, records);
        }
        records.retain(|r| r.project != project);
        records.push(record.clone());
        records.sort_by(|a, b| a.project.cmp(&b.project));
        (Some(records.clone()), records)
    });
    let records = written.map_err(|e| {
        eprintln!("shoephoned: trusted: {e}");
        Fail::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust_save_failed",
            "the trust record could not be saved; the job is still claimed, retry",
        )
    })?;
    if stale {
        sync_trusted(d, inner, records);
        inner.jobs.refuse_claimed(now, req.id, "stale_baseline");
        inner.claimed.remove(&req.id);
        prune_jobs(inner, now);
        return Err(Refusal::StaleBaseline.into());
    }
    let undo = TrustUndo {
        id: req.id,
        record: record.clone(),
        previous,
        scope,
        meta: inner.job_meta.get(&req.id).cloned(),
    };
    if let Err(e) = inner
        .jobs
        .finish(now, runner, &project, req.id, JobResult::Trusted)
    {
        if !restore_trusted_file(d, &undo) {
            // Near-unreachable: the pre-checks above make `Jobs::finish`
            // accept this. If it fails anyway and the file cannot be put
            // back, an unaudited record is on disk. Trust nothing for the
            // project and refuse audited calls (including the reload in
            // `refresh_trusted`) until a restart, when reconcile drops it.
            inner.trusted.remove(&project);
            inner.jobs.set_trusted(&project, None);
            inner.ledger_failed = Some(format!(
                "trust for {project:?} could not be rolled back; restart to reconcile"
            ));
        }
        return Err(finish_failure(e));
    }
    inner.claimed.remove(&req.id);
    sync_trusted(d, inner, records);
    prune_jobs(inner, now);
    Ok((Json(serde_json::json!({})), undo))
}

/// Put the project's record in `trusted.json` back as it was, unless
/// something else (an `untrust`, a later trust) has changed it since.
fn restore_trusted_file(d: &Daemon, undo: &TrustUndo) -> bool {
    let project = &undo.record.project;
    let restored = d.store.update_trusted(|mut records| {
        if records.iter().find(|r| &r.project == project) != Some(&undo.record) {
            return (None, ());
        }
        records.retain(|r| &r.project != project);
        records.extend(undo.previous.clone());
        records.sort_by(|a, b| a.project.cmp(&b.project));
        (Some(records), ())
    });
    if let Err(e) = restored {
        eprintln!("shoephoned: trusted: rolling back: {e}");
        return false;
    }
    true
}

/// The ledger could not record a trust: take it back on disk and in memory,
/// and leave the job Claimed. The ledger is now marked failed, so the daemon
/// refuses further approvals until it restarts with a writable one.
fn undo_trust(d: &Daemon, inner: &mut Inner, undo: TrustUndo) {
    let restored = restore_trusted_file(d, &undo);
    inner.jobs.reopen_trusted(undo.id);
    inner.claimed.insert(undo.id, undo.scope);
    if let Some(meta) = undo.meta {
        inner.job_meta.insert(undo.id, meta);
    }
    let reloaded = if restored {
        d.store.load_trusted().ok()
    } else {
        None
    };
    match reloaded {
        Some(records) => sync_trusted(d, inner, records),
        None => {
            // The file could not be put back, so the trust nobody can audit
            // may still be on disk (startup reconciliation drops it). Fail
            // closed for this project in the meantime.
            let project = undo.record.project;
            inner.trusted.remove(&project);
            inner.jobs.set_trusted(&project, None);
        }
    }
}

/// Approve job `id` the way a verified ceremony would, with no ceremony.
#[cfg(feature = "test-hooks")]
fn approve_waiting_job(
    d: &Daemon,
    inner: &mut Inner,
    now: SystemTime,
    policy: &Policy,
    id: u64,
) -> Result<Json<serde_json::Value>, Fail> {
    refresh_trusted(d, inner)?;
    let (nonce, scope) = match inner.jobs.job(now, id).map(|j| j.state.clone()) {
        Some(JobState::Waiting { scope, nonce, .. }) => (nonce, scope),
        _ => return Err(Refusal::NoSuchRequest.into()),
    };
    inner
        .jobs
        .approve(now, inner.grants.gate_mut(), policy, id, &nonce, &scope)?;
    Ok(Json(serde_json::json!({ "approved": id })))
}

/// Approves the job waiting on the approver, as the approver's device would.
/// Only compiled with `test-hooks`.
#[cfg(feature = "test-hooks")]
async fn test_approve_job(State(d): App, Json(body): Json<ById>) -> Reply<serde_json::Value> {
    let (now, policy) = (now(), d.config.policy());
    d.audited(|inner| approve_waiting_job(&d, inner, now, &policy, body.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_bound_credentials_pass() {
        assert!(refuse_synced(false, false, false).is_ok());
    }

    #[test]
    fn either_backup_flag_is_refused_by_default() {
        let be = refuse_synced(true, false, false).unwrap_err();
        assert_eq!(be.1.code, "synced_credential");
        assert!(refuse_synced(false, true, false).is_err());
        assert!(refuse_synced(true, true, false).is_err());
    }

    #[test]
    fn the_stopgap_admits_synced_credentials() {
        assert!(refuse_synced(true, true, true).is_ok());
    }

    #[test]
    fn ct_eq_is_exact() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn push_registration_needs_the_right_secret() {
        let hash = store::sha256_hex("correct-secret");
        assert!(check_push_secret(Some(&hash), "correct-secret").is_ok());

        let wrong = check_push_secret(Some(&hash), "wrong-secret").unwrap_err();
        assert_eq!(wrong.1.code, "bad_secret");

        let missing = check_push_secret(None, "anything").unwrap_err();
        assert_eq!(missing.1.code, "reenroll_required");
    }

    #[test]
    fn push_for_job_is_exhaustive() {
        use crate::job::JobEvent as E;
        let at = SystemTime::UNIX_EPOCH;
        let (id, project) = (1, "net".to_owned());
        let cases = [
            (
                E::Requested {
                    id,
                    project: project.clone(),
                    kind: "trust",
                    reason: "r".into(),
                    at,
                },
                Push::JobRequested,
            ),
            (
                E::Requested {
                    id,
                    project: project.clone(),
                    kind: "apply",
                    reason: "r".into(),
                    at,
                },
                Push::JobRequested,
            ),
            (
                E::Started {
                    id,
                    project: project.clone(),
                    kind: "apply",
                    at,
                },
                Push::PlanStarted,
            ),
            (
                E::Waiting {
                    id,
                    project: project.clone(),
                    kind: "trust",
                    at,
                },
                Push::TrustWaiting,
            ),
            (
                E::Waiting {
                    id,
                    project: project.clone(),
                    kind: "apply",
                    at,
                },
                Push::ApplyWaiting,
            ),
            (
                E::Approved {
                    id,
                    project: project.clone(),
                    at,
                },
                Push::JobApproved,
            ),
            (
                E::Refused {
                    id,
                    project: project.clone(),
                    category: "plan_too_old".into(),
                    at,
                },
                Push::PlanRefused,
            ),
            (
                E::Applied {
                    id,
                    project: project.clone(),
                    at,
                },
                Push::Applied,
            ),
            (
                E::Trusted {
                    id,
                    project: project.clone(),
                    at,
                },
                Push::Trusted,
            ),
            (
                E::ApplyFailed {
                    id,
                    project: project.clone(),
                    at,
                },
                Push::ApplyFailed,
            ),
            (
                E::OutcomeUnknown {
                    id,
                    project: project.clone(),
                    at,
                },
                Push::OutcomeUnknown,
            ),
            (
                E::Declined {
                    id,
                    project: project.clone(),
                    at,
                },
                Push::RequestDeclined,
            ),
            (
                E::TimedOut {
                    id,
                    project: project.clone(),
                    at,
                },
                Push::RequestTimedOut,
            ),
            (E::Killed { id, project, at }, Push::JobKilled),
        ];
        for (event, expected) in cases {
            assert_eq!(push_for_job(&event), expected, "{event:?}");
        }
    }

    fn test_webauthn() -> Webauthn {
        let origin = Url::parse("http://localhost").expect("static URL");
        WebauthnBuilder::new("localhost", &origin)
            .expect("static rp_id/origin")
            .rp_name("test")
            .build()
            .expect("static config")
    }

    #[test]
    fn bind_challenge_overwrites_both_the_options_and_the_state() {
        let webauthn = test_webauthn();
        // An empty credential list is accepted: `start_securitykey_authentication`
        // only consults `creds.first()` when no policy override is given, and it
        // always supplies one.
        let keys: Vec<SecurityKey> = Vec::new();
        let (rcr, auth) = webauthn
            .start_securitykey_authentication(&keys)
            .expect("empty credential list is accepted");
        let challenge = [7u8; 32];

        let (rcr, auth) =
            bind_challenge(rcr, auth, &challenge).expect("bind_challenge over static input");

        assert_eq!(
            rcr.public_key.challenge,
            Base64UrlSafeData::from(&challenge)
        );

        // Re-serializing the returned state must show the same challenge, so
        // `finish_securitykey_authentication` (which reads it out of `auth`)
        // verifies an assertion against the bytes the options actually asked
        // the device to sign.
        let value = serde_json::to_value(&auth).expect("SecurityKeyAuthentication serializes");
        let seen = value["ast"]["challenge"]
            .as_str()
            .expect("ast.challenge is a string");
        let expected = serde_json::to_value(Base64UrlSafeData::from(&challenge))
            .expect("Base64UrlSafeData serializes");
        assert_eq!(serde_json::Value::String(seen.to_owned()), expected);
    }
}
