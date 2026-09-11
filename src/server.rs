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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use webauthn_rs::prelude::*;

use crate::api::*;
use crate::ca::{self, UserCa};
use crate::config::Config;
use crate::exit::VERSION;
use crate::grant::{self, Approval, Entropy, Event, Grants, Pending, Refusal, Scope};
use crate::notify::{Apns, Delivery, Notifier, Push};
use crate::store::{self, Device, EnrollCode, LedgerEntry, Store};

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

struct ApproveCeremony {
    id: u64,
    nonce: String,
    scope: Scope,
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
        let events = self.drain_and_append(&mut inner);
        let targets = push_targets(&inner);
        drop(inner);
        self.dispatch_pushes(&events, targets);
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
        let mut inner = self.inner.lock().expect("daemon lock");
        if inner.ledger_failed.is_some() {
            return Err(Self::ledger_unavailable());
        }
        let out = f(&mut inner);
        let events = self.drain_and_append(&mut inner);
        let append_failed = inner.ledger_failed.is_some();
        let targets = push_targets(&inner);
        drop(inner);
        self.dispatch_pushes(&events, targets);
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
    fn drain_and_append(&self, inner: &mut Inner) -> Vec<Event> {
        let events = inner.grants.take_events();
        if !events.is_empty() {
            let entries: Vec<LedgerEntry> = events.iter().map(LedgerEntry::from).collect();
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
    }

    /// Send the content-free pushes for this call's events. Always called
    /// after the lock is released: notifier and APNs delivery can block, or
    /// need the tokio runtime, and neither should happen while another
    /// caller is waiting on the daemon lock.
    fn dispatch_pushes(&self, events: &[Event], targets: Vec<(String, Option<Vec<String>>)>) {
        if events.is_empty() {
            return;
        }
        // Only these three reach the phone. Declined and TimedOut are
        // either the approver's own doing or nothing happening, and Issued
        // is the agent collecting what was already approved.
        let pushes: Vec<Push> = events
            .iter()
            .filter_map(|e| match e {
                Event::Requested { .. } => Some(Push::RequestWaiting),
                Event::Approved { .. } => Some(Push::WindowOpened),
                Event::Killed { .. } => Some(Push::WindowKilled),
                _ => None,
            })
            .collect();
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
                        match a.send(*p, t).await {
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
        let router = router.route("/api/test/approve", post(test_approve));
        router.with_state(self)
    }
}

type App = State<Arc<Daemon>>;

fn now() -> SystemTime {
    SystemTime::now()
}

/// Each device's push token with the kinds it asked for; `None` means all.
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
    d.with(|inner| {
        inner.grants.kill(now, &body.host)?;
        // A ceremony for the request that kill just declined is stale.
        if inner.grants.pending(now).is_none() {
            inner.approve = None;
        }
        Ok::<_, Refusal>(())
    })?;
    Ok(Json(serde_json::json!({ "killed": body.host })))
}

async fn pending(State(d): App) -> Reply<ApproverState> {
    let now = now();
    let ttl = d.config.policy().pending_ttl;
    let state = d.with(|inner| ApproverState {
        pending: inner.grants.pending(now).map(|p| pending_view(p, ttl)),
        enrolled: inner.devices.len(),
        windows: window_views(inner, now),
    });
    Ok(Json(state))
}

async fn approve_start(State(d): App, Json(body): Json<ById>) -> Reply<RequestChallengeResponse> {
    let now = now();
    d.with(|inner| {
        if inner.devices.is_empty() {
            return Err(Fail::new(
                StatusCode::PRECONDITION_FAILED,
                "no_devices",
                "no approver device is enrolled; run `shoephoned enroll` at the console",
            ));
        }
        let p = inner
            .grants
            .pending(now)
            .filter(|p| p.id == body.id)
            .cloned()
            .ok_or(Refusal::NoSuchRequest)?;
        let keys: Vec<SecurityKey> = inner.devices.iter().map(|x| x.key.clone()).collect();
        let (challenge, auth) = d
            .webauthn
            .start_securitykey_authentication(&keys)
            .map_err(|e| Fail::internal(format!("webauthn: {e}")))?;
        let bound = grant::bound_challenge(&p.scope, &p.nonce);
        let (challenge, auth) = bind_challenge(challenge, auth, &bound).map_err(Fail::internal)?;
        inner.approve = Some(ApproveCeremony {
            id: p.id,
            nonce: p.nonce,
            scope: p.scope,
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
    let now = now();
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
        let approval = Approval {
            id: ceremony.id,
            nonce: ceremony.nonce,
            scope: ceremony.scope,
        };
        let window = inner.grants.approve(now, &approval)?;
        Ok(Json(serde_json::json!({
            "approved": window.id,
            "host": window.scope.host,
            "ends_at": store::unix(window.scope.ends_at),
            "device": device_name,
        })))
    })
}

async fn decline(State(d): App, Json(body): Json<ById>) -> Reply<serde_json::Value> {
    let now = now();
    d.with(|inner| {
        inner.approve = None;
        inner.grants.decline(now, body.id)
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
    let now = now();
    d.audited(|inner| {
        let p = inner
            .grants
            .pending(now)
            .filter(|p| p.id == body.id)
            .cloned()
            .ok_or(Refusal::NoSuchRequest)?;
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
