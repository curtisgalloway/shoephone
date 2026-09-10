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
//! WebAuthn generates its own random challenge; the daemon binds that
//! challenge to the pending request's id, nonce and enforced scope when the
//! ceremony starts, and only that snapshot is submitted to
//! [`Grants::approve`] when the assertion verifies. A request that changed
//! underneath the ceremony is rejected there.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use webauthn_rs::prelude::*;

use crate::api::*;
use crate::ca::{self, UserCa};
use crate::config::Config;
use crate::exit::VERSION;
use crate::grant::{Approval, Event, Grants, Pending, Refusal, Scope};
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
        }
        let grants = Grants::new(config.policy(), config.principals.clone());
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
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self.inner.lock().expect("daemon lock");
        let out = f(&mut inner);
        let events = inner.grants.take_events();
        // Each device's token with the kinds it asked for; None means all.
        let targets: Vec<(String, Option<Vec<String>>)> = inner
            .devices
            .iter()
            .filter_map(|d| d.push_token.clone().map(|t| (t, d.push_kinds.clone())))
            .collect();
        drop(inner);
        if !events.is_empty() {
            let entries: Vec<LedgerEntry> = events.iter().map(LedgerEntry::from).collect();
            if let Err(e) = self.store.append_ledger(&entries) {
                eprintln!("shoephoned: ledger: {e}");
            }
            // Only these three reach the phone. Declined and TimedOut are
            // either the approver's own doing or nothing happening, and
            // Issued is the agent collecting what was already approved.
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
        out
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
        ends_at: store::unix(p.scope.ends_at),
        match_code: p.match_code.clone(),
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
    let p = d.with(|inner| {
        let mut entropy = ca::OsEntropy;
        inner.grants.request(
            now,
            &mut entropy,
            &body.host,
            &key,
            &body.requester,
            &body.reason,
            body.context.as_deref(),
            wanted,
        )
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
    let cert = d.with(|inner| inner.grants.issue(now, &body.host, &key))?;
    let signed =
        d.ca.sign(&cert, &body.host)
            .and_then(|c| c.to_openssh().map_err(ca::Error::from))
            .map_err(|e| Fail::internal(e.to_string()))?;
    Ok(Json(IssueReply {
        certificate: signed,
        serial: cert.serial,
        valid_before: store::unix(cert.valid_before),
        ends_at: store::unix(cert.window_ends_at),
    }))
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
    d.with(|inner| {
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
        inner.devices.push(Device {
            name: ceremony.device_name.clone(),
            enrolled_at: store::unix(now),
            key,
            push_token: None,
            push_kinds: None,
        });
        d.store
            .save_devices(&inner.devices)
            .map_err(Fail::internal)?;
        d.store.clear_enroll_code().map_err(Fail::internal)?;
        eprintln!("shoephoned: enrolled device {:?}", ceremony.device_name);
        Ok(Json(
            serde_json::json!({ "enrolled": ceremony.device_name }),
        ))
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
/// enrolled with. Unauthenticated like the rest of the approver API: the
/// worst a stranger on the WireGuard network can do with it is point the
/// content-free pushes at the wrong phone, and the app re-registers on
/// every launch.
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

async fn ledger(State(d): App) -> Reply<Vec<LedgerEntry>> {
    d.store.read_ledger(50).map(Json).map_err(Fail::internal)
}

/// Test hook: approve the pending request with no ceremony at all. Only
/// compiled with the `test-hooks` feature, which integration tests enable
/// and deployed builds must not.
#[cfg(feature = "test-hooks")]
async fn test_approve(State(d): App, Json(body): Json<ById>) -> Reply<serde_json::Value> {
    let now = now();
    d.with(|inner| {
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
    use super::refuse_synced;

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
}
