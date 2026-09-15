// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The grant state machine, for one approver and one user CA.
//!
//! Everything security-relevant that does not need cryptography lives here,
//! with no I/O and no clock of its own: every method takes `now`, and the
//! only randomness arrives through [`Entropy`], so the whole thing is
//! exercised by plain unit tests. The daemon wraps it in a mutex, feeds it
//! the wall clock and the OS random source, verifies the approver's WebAuthn
//! assertion over a challenge derived from [`Scope::bytes_to_sign`] (see
//! [`bound_challenge`]) *before* calling [`Grants::approve`], and hands each
//! [`Certificate`] to the signer.
//!
//! The invariants from `AGENTS.md`, restated as the rules this module holds:
//!
//! - The scope the approver signs is the daemon's enforced scope, built here
//!   from policy and the per-host principal table, never from request prose.
//! - An approval is accepted only if its nonce and its scope match the one
//!   pending request exactly. A nonce is consumed by the first verdict.
//! - Certificates go only to the approved key and end at the window, or one
//!   TTL from now, whichever is sooner.
//! - The rate cap and the cooldown are keyed on nothing the requester chooses.
//! - Every outcome is appended to an event list for the approver's device.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HOUR: Duration = Duration::from_secs(60 * 60);

/// A source of random bytes. The daemon supplies the operating system's;
/// tests supply a counter.
pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Server-side caps. Nothing in a request can raise any of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Window length when the request does not ask for one.
    pub default_window: Duration,
    /// Longest window the daemon enforces; a request asking for more is
    /// clamped, and the approver sees the clamped value.
    pub max_window: Duration,
    /// Lifetime of each certificate issued inside a window. Expiry and the
    /// kill switch both work by refusing to hand out (or renew) a
    /// certificate older than this once they fire, so this duration bounds
    /// how long a *new* login can happen afterward. Neither one terminates a
    /// session that is already open: the certificate authenticated that
    /// connection once, and sshd does not re-check it for the rest of the
    /// session's life. Bounding an already-open session is a host-side
    /// concern (an idle timeout, a hard session-length limit), not this
    /// daemon's.
    pub cert_ttl: Duration,
    /// How long a request waits for a verdict before it times out.
    pub pending_ttl: Duration,
    /// Requests accepted per rolling hour, for this approver, across every
    /// requester.
    pub max_requests_per_hour: usize,
    /// The first cooldown after a decline or timeout; it doubles on each
    /// consecutive strike. See [`Grants::cooldown_after`].
    pub base_cooldown: Duration,
    /// Where the doubling stops.
    pub max_cooldown: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_window: Duration::from_secs(60 * 60),
            max_window: Duration::from_secs(4 * 60 * 60),
            cert_ttl: Duration::from_secs(15 * 60),
            pending_ttl: Duration::from_secs(5 * 60),
            max_requests_per_hour: 6,
            base_cooldown: Duration::from_secs(5 * 60),
            max_cooldown: Duration::from_secs(60 * 60),
        }
    }
}

/// The enforced scope: exactly what the approver sees and signs.
///
/// `ends_at` is fixed when the request is filed, not when it is approved, so
/// the time shown on the phone is the time the certificate chain will honor.
/// A slow approval shortens the window rather than moving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub host: String,
    /// The principal sshd on `host` will accept, from the daemon's table.
    pub principal: String,
    /// The requesting session's public key, one OpenSSH `authorized_keys`
    /// style line, trimmed. Every certificate in the window goes to this key.
    pub public_key: String,
    pub ends_at: SystemTime,
}

impl Scope {
    /// The exact bytes the approver's device signs, together with the nonce.
    /// Line-oriented and versioned so a future field cannot be confused with
    /// an old one. Every field is newline-free by construction: hosts come
    /// from the principal table and keys are rejected if they carry control
    /// characters.
    pub fn bytes_to_sign(&self, nonce: &str) -> Vec<u8> {
        format!(
            "shoephone-scope-v1\nhost={}\nprincipal={}\nkey={}\nends_at={}\nnonce={}\n",
            self.host,
            self.principal,
            self.public_key,
            unix(self.ends_at),
            nonce
        )
        .into_bytes()
    }
}

/// SHA-256 of `scope.bytes_to_sign(nonce)`: the WebAuthn challenge the
/// approver's device must sign, in place of the random challenge the
/// WebAuthn library would otherwise generate. Binding the challenge itself
/// to the displayed scope, rather than binding it out of band, means the
/// approver's own recomputation of this digest (from the fields the approve
/// page showed) either matches the challenge it is about to sign or it does
/// not: there is no separate value a dishonest channel could relay unchanged
/// while lying about the scope on screen.
pub fn bound_challenge(scope: &Scope, nonce: &str) -> [u8; 32] {
    use ssh_key::sha2::{Digest, Sha256};
    let digest = Sha256::digest(scope.bytes_to_sign(nonce));
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// A request awaiting a verdict. There is at most one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: u64,
    pub scope: Scope,
    /// Single-use, 256 bits, lowercase hex. Bound to this request only.
    pub nonce: String,
    /// Short code the CLI prints and the phone shows. Not a secret, not an
    /// input: the person compares them.
    pub match_code: String,
    pub created: SystemTime,
    /// The requesting machine's self-reported name. Display only; untrusted.
    pub requester: String,
    /// The requester's stated purpose. Display only; untrusted; never empty.
    pub reason: String,
    /// A link to the requesting session, if the requester gave one.
    pub context: Option<String>,
}

/// What the approver's verified signature covered. The daemon builds this
/// from the client's submission only after the WebAuthn assertion checks out
/// over a challenge equal to [`bound_challenge`]`(&scope, &nonce)`: SHA-256 of
/// `scope.bytes_to_sign(&nonce)`, not those bytes directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub id: u64,
    pub nonce: String,
    pub scope: Scope,
}

/// An approved scope, open until `scope.ends_at` or until killed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub id: u64,
    pub scope: Scope,
    pub started: SystemTime,
    /// The certificate last handed out for this window, if any. A
    /// re-request soon after gets this one back instead of a fresh serial;
    /// see [`Grants::issue`].
    pub last_issued: Option<LastIssued>,
}

/// The certificate `Grants::issue` most recently minted for a window, kept
/// so a re-request can be told to reuse it instead of minting again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastIssued {
    pub serial: u64,
    pub valid_after: SystemTime,
    pub valid_before: SystemTime,
}

/// A signing request for the CA. Nothing here is chosen by the requester
/// except the key, which is the one the approver saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub serial: u64,
    pub principal: String,
    pub public_key: String,
    pub valid_after: SystemTime,
    pub valid_before: SystemTime,
    /// When the window this certificate was issued from closes.
    pub window_ends_at: SystemTime,
}

/// What [`Grants::issue`] handed back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issuance {
    /// A certificate minted by this call.
    Fresh(Certificate),
    /// The window already has a certificate more than half its own TTL from
    /// expiring; re-serve it rather than minting (and logging) a new one.
    /// No [`Event`] is pushed for a reuse.
    Reuse {
        window_id: u64,
        serial: u64,
        valid_before: SystemTime,
        window_ends_at: SystemTime,
    },
}

/// Why a call did nothing. None of these leak anything the requester does
/// not already know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The host is not in the principal table.
    UnknownHost,
    /// The key is empty or carries control characters.
    BadKey,
    /// The request gave no reason.
    NoReason,
    /// Another request is already waiting for a verdict.
    Busy,
    /// A recent decline or timeout; try again at `until`.
    Cooldown { until: SystemTime },
    /// The hourly cap is spent; try again at `until`.
    RateCapped { until: SystemTime },
    /// No pending request has that id (it was decided, or timed out).
    NoSuchRequest,
    /// The signed nonce is not this request's nonce.
    NonceMismatch,
    /// The signed scope is not the enforced scope.
    ScopeMismatch,
    /// No open window for that host.
    NoWindow,
    /// A window is open for that host, but for a different key.
    KeyMismatch,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::UnknownHost => write!(f, "host is not one this daemon signs for"),
            Refusal::BadKey => write!(f, "public key is empty or malformed"),
            Refusal::NoReason => write!(f, "a request must say why admin is needed"),
            Refusal::Busy => write!(f, "another request is awaiting a verdict"),
            Refusal::Cooldown { until } => {
                write!(f, "cooling down after a decline until {}", unix(*until))
            }
            Refusal::RateCapped { until } => {
                write!(f, "hourly request cap reached until {}", unix(*until))
            }
            Refusal::NoSuchRequest => write!(f, "no pending request with that id"),
            Refusal::NonceMismatch => write!(f, "signature does not cover this request's nonce"),
            Refusal::ScopeMismatch => write!(f, "signature does not cover the enforced scope"),
            Refusal::NoWindow => write!(f, "no approved window for that host"),
            Refusal::KeyMismatch => write!(f, "window was approved for a different key"),
        }
    }
}

impl std::error::Error for Refusal {}

/// One entry for the approver's ledger. The daemon drains these with
/// [`Grants::take_events`] and pushes them to the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Requested {
        id: u64,
        host: String,
        reason: String,
        context: Option<String>,
        at: SystemTime,
    },
    Approved {
        id: u64,
        host: String,
        ends_at: SystemTime,
        at: SystemTime,
    },
    Declined {
        id: u64,
        host: String,
        at: SystemTime,
    },
    TimedOut {
        id: u64,
        host: String,
        at: SystemTime,
    },
    Issued {
        /// The window, which carries the id of the request that opened it.
        id: u64,
        serial: u64,
        host: String,
        valid_before: SystemTime,
        at: SystemTime,
    },
    /// One per window closed, so the ledger can tie it to its request.
    Killed {
        id: u64,
        host: String,
        at: SystemTime,
    },
}

/// How a pending request ended without a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Declined,
    TimedOut,
}

/// The state for one approver. The daemon holds one of these per CA.
#[derive(Debug)]
pub struct Grants {
    policy: Policy,
    /// host -> principal, fixed at startup from the daemon's config.
    principals: BTreeMap<String, String>,
    next_id: u64,
    pending: Option<Pending>,
    windows: Vec<Window>,
    /// Times of accepted requests in the last hour, oldest first.
    accepted: VecDeque<SystemTime>,
    cooldown_until: Option<SystemTime>,
    /// Consecutive requests that ended without approval.
    strikes: u32,
    events: Vec<Event>,
    /// The latest `now` this instance has ever been ticked with. Every
    /// public method clamps its `now` argument up to this before doing
    /// anything else, so a clock that steps backward cannot hand out a
    /// certificate whose `valid_after` precedes one already issued, or
    /// resurrect a window or cooldown that already lapsed. See
    /// [`Grants::tick`].
    high_water: SystemTime,
}

impl Grants {
    /// `next_id` seeds the id/serial counter; the daemon persists it across
    /// restarts (see `Store::load_next_id`) so an id or serial is never
    /// reused, which matters because both appear in the audit ledger.
    pub fn new(policy: Policy, principals: BTreeMap<String, String>, next_id: u64) -> Self {
        Self {
            policy,
            principals,
            next_id,
            pending: None,
            windows: Vec::new(),
            accepted: VecDeque::new(),
            cooldown_until: None,
            strikes: 0,
            events: Vec::new(),
            high_water: UNIX_EPOCH,
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The next id [`Grants::request`] or [`Grants::issue`] will hand out.
    /// The daemon persists this after it changes, so a restart does not
    /// reuse an id or serial already written to the ledger.
    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    /// File a request. On success the returned [`Pending`] carries the
    /// enforced scope, the nonce and the match code; the CLI shows the match
    /// code and polls.
    // Seven inputs is the whole request, each one a distinct decision the
    // caller makes; a struct would only rename the problem.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        now: SystemTime,
        entropy: &mut dyn Entropy,
        host: &str,
        public_key: &str,
        requester: &str,
        reason: &str,
        context: Option<&str>,
        wanted: Option<Duration>,
    ) -> Result<Pending, Refusal> {
        let now = self.tick(now);
        let reason = printable(reason.trim(), 200);
        if reason.is_empty() {
            return Err(Refusal::NoReason);
        }
        // A link is only ever displayed, but it is a link the person will
        // tap: https, no whitespace, bounded.
        let context = context
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(|c| printable(c, 512))
            .filter(|c| c.starts_with("https://") && !c.chars().any(char::is_whitespace));
        let principal = self
            .principals
            .get(host)
            .cloned()
            .ok_or(Refusal::UnknownHost)?;
        let public_key = public_key.trim();
        if public_key.is_empty() || public_key.chars().any(char::is_control) {
            return Err(Refusal::BadKey);
        }
        if self.pending.is_some() {
            return Err(Refusal::Busy);
        }
        if let Some(until) = self.cooldown_until.filter(|u| *u > now) {
            return Err(Refusal::Cooldown { until });
        }
        if self.accepted.len() >= self.policy.max_requests_per_hour {
            let oldest = self.accepted.front().copied().unwrap_or(now);
            return Err(Refusal::RateCapped {
                until: oldest + HOUR,
            });
        }

        let window = wanted
            .unwrap_or(self.policy.default_window)
            .min(self.policy.max_window);
        let id = self.take_id();
        let pending = Pending {
            id,
            scope: Scope {
                host: host.to_owned(),
                principal,
                public_key: public_key.to_owned(),
                ends_at: now + window,
            },
            nonce: hex_nonce(entropy),
            match_code: match_code(entropy),
            created: now,
            requester: printable(requester, 64),
            reason: reason.clone(),
            context: context.clone(),
        };
        self.accepted.push_back(now);
        self.events.push(Event::Requested {
            id,
            host: host.to_owned(),
            reason,
            context,
            at: now,
        });
        self.pending = Some(pending.clone());
        Ok(pending)
    }

    /// The request awaiting a verdict, if any. This is what the approve page
    /// fetches; the enforced scope in it is the only scope the page may show.
    pub fn pending(&mut self, now: SystemTime) -> Option<&Pending> {
        self.tick(now);
        self.pending.as_ref()
    }

    /// Accept a verified approval and open its window. The signature has
    /// already been checked by the caller; this checks that what was signed
    /// is what is pending.
    pub fn approve(&mut self, now: SystemTime, approval: &Approval) -> Result<Window, Refusal> {
        let now = self.tick(now);
        let pending = self
            .pending
            .as_ref()
            .filter(|p| p.id == approval.id)
            .ok_or(Refusal::NoSuchRequest)?;
        if !constant_time_eq(pending.nonce.as_bytes(), approval.nonce.as_bytes()) {
            return Err(Refusal::NonceMismatch);
        }
        if pending.scope != approval.scope {
            return Err(Refusal::ScopeMismatch);
        }
        let pending = self.pending.take().expect("checked above");
        let window = Window {
            id: pending.id,
            scope: pending.scope,
            started: now,
            last_issued: None,
        };
        self.strikes = 0;
        self.cooldown_until = None;
        self.events.push(Event::Approved {
            id: window.id,
            host: window.scope.host.clone(),
            ends_at: window.scope.ends_at,
            at: now,
        });
        self.windows.push(window.clone());
        Ok(window)
    }

    /// Decline the pending request. Nothing is issued and a cooldown starts.
    pub fn decline(&mut self, now: SystemTime, id: u64) -> Result<(), Refusal> {
        let now = self.tick(now);
        let pending = self
            .pending
            .take_if(|p| p.id == id)
            .ok_or(Refusal::NoSuchRequest)?;
        self.events.push(Event::Declined {
            id: pending.id,
            host: pending.scope.host,
            at: now,
        });
        self.strike(now, Outcome::Declined);
        Ok(())
    }

    /// Issue a certificate inside an open window. Called on the first grant
    /// and on every silent re-request; the CLI never sees a difference.
    ///
    /// A re-request less than half a certificate's TTL after the last one
    /// minted for this window, while that certificate still has time left,
    /// gets the same certificate back ([`Issuance::Reuse`]) instead of a
    /// fresh serial: the daemon calls this once per `issue` HTTP request,
    /// and a client that polls or renews slightly early must not cause a
    /// new certificate to be minted, signed, and logged for work that never
    /// used the old one. `force_fresh` exists for the daemon's own
    /// cache-miss fallback: if it ever holds a `Reuse` answer with no
    /// signed certificate to go with it, it calls this again with
    /// `force_fresh` set so a certificate always comes back.
    pub fn issue(
        &mut self,
        now: SystemTime,
        host: &str,
        public_key: &str,
        force_fresh: bool,
    ) -> Result<Issuance, Refusal> {
        let now = self.tick(now);
        let public_key = public_key.trim();
        // Select on host and key together. Two windows can be open for one
        // host (a second request is allowed while a window is open, and a
        // new window is a new approval), and picking by host alone would
        // refuse a key that was legitimately approved for the other one.
        if !self.windows.iter().any(|w| w.scope.host == host) {
            return Err(Refusal::NoWindow);
        }
        let idx = self
            .windows
            .iter()
            .enumerate()
            .filter(|(_, w)| w.scope.host == host && w.scope.public_key == public_key)
            .max_by_key(|(_, w)| w.scope.ends_at)
            .map(|(i, _)| i)
            .ok_or(Refusal::KeyMismatch)?;
        let window = &self.windows[idx];
        let window_id = window.id;
        let window_ends_at = window.scope.ends_at;
        let half_ttl = self.policy.cert_ttl / 2;
        if let Some(last) = window.last_issued.filter(|last| {
            !force_fresh && now < last.valid_after + half_ttl && last.valid_before > now
        }) {
            return Ok(Issuance::Reuse {
                window_id,
                serial: last.serial,
                valid_before: last.valid_before,
                window_ends_at,
            });
        }
        let principal = window.scope.principal.clone();
        let public_key = window.scope.public_key.clone();
        // `window`'s borrow of `self.windows` ends with the clone above;
        // `take_id` needs `&mut self`.
        let valid_before = (now + self.policy.cert_ttl).min(window_ends_at);
        let serial = self.take_id();
        let cert = Certificate {
            serial,
            principal,
            public_key,
            valid_after: now,
            valid_before,
            window_ends_at,
        };
        self.windows[idx].last_issued = Some(LastIssued {
            serial: cert.serial,
            valid_after: cert.valid_after,
            valid_before: cert.valid_before,
        });
        self.events.push(Event::Issued {
            id: window_id,
            serial: cert.serial,
            host: host.to_owned(),
            valid_before,
            at: now,
        });
        Ok(Issuance::Fresh(cert))
    }

    /// The kill switch: close every window for a host. Certificates already
    /// issued run out within one TTL.
    ///
    /// A request still pending for that host is declined too, with the
    /// usual cooldown: kill means "stop", and a tap on the phone a moment
    /// later must not reopen what was just closed.
    pub fn kill(&mut self, now: SystemTime, host: &str) -> Result<(), Refusal> {
        let now = self.tick(now);
        let (closed, kept): (Vec<Window>, Vec<Window>) =
            self.windows.drain(..).partition(|w| w.scope.host == host);
        self.windows = kept;
        let pending = self.pending.take_if(|p| p.scope.host == host);
        if closed.is_empty() && pending.is_none() {
            return Err(Refusal::NoWindow);
        }
        if let Some(p) = pending {
            self.events.push(Event::Declined {
                id: p.id,
                host: p.scope.host,
                at: now,
            });
            self.strike(now, Outcome::Declined);
        }
        for w in closed {
            self.events.push(Event::Killed {
                id: w.id,
                host: host.to_owned(),
                at: now,
            });
        }
        Ok(())
    }

    /// Windows still open at `now`.
    pub fn windows(&mut self, now: SystemTime) -> &[Window] {
        self.tick(now);
        &self.windows
    }

    /// How many things are outstanding: open windows, plus a request still
    /// waiting for a verdict. What the phone's app icon badges.
    ///
    /// Both halves count because both want the person, and the request wants
    /// them more: a window is a state of the world, a pending request is a
    /// question with a five-minute fuse. At most one request is pending at a
    /// time, so this is the window count plus zero or one.
    pub fn outstanding(&mut self, now: SystemTime) -> u64 {
        self.tick(now);
        self.windows.len() as u64 + u64::from(self.pending.is_some())
    }

    /// Drain the ledger entries recorded since the last drain.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// How long requests are refused after a request ends without approval.
    /// `self.strikes` has already been incremented for this outcome and is
    /// reset to zero by an approval, and only by an approval.
    ///
    /// The rule: the base cooldown, doubling with each consecutive strike,
    /// capped at [`Policy::max_cooldown`]. A timeout counts exactly like a
    /// decline. The person did not say no, but an agent that files requests
    /// nobody answers is the habituation pattern this cap exists to break,
    /// and `SKILL.md` already tells the agent both cost a cooldown. With the
    /// defaults, strikes cost 5, 10, 20, 40, then 60 minutes each; the cap
    /// keeps a bad afternoon from becoming a locked-out week, while five
    /// unanswered requests still cost over two hours.
    fn cooldown_after(&self, outcome: Outcome) -> Duration {
        let _ = outcome;
        let doublings = self.strikes.saturating_sub(1).min(16);
        (self.policy.base_cooldown * 2u32.pow(doublings)).min(self.policy.max_cooldown)
    }

    fn strike(&mut self, now: SystemTime, outcome: Outcome) {
        self.strike_at(now, outcome);
    }

    /// Record a strike as of `at` and start the cooldown counting from
    /// there. `decline` and `kill` pass `now`, since the person's verdict
    /// (or the kill) happened right then; a timeout passes the moment the
    /// pending request actually expired, which is earlier than `now` when
    /// nothing polled the daemon between expiry and this tick. See
    /// [`Grants::tick`].
    fn strike_at(&mut self, at: SystemTime, outcome: Outcome) {
        self.strikes = self.strikes.saturating_add(1);
        self.cooldown_until = Some(at + self.cooldown_after(outcome));
    }

    /// Advance time: expire the pending request, drop closed windows, and
    /// forget accepted requests older than an hour. Returns `now` clamped to
    /// never run behind the latest time this instance has already seen
    /// (`self.high_water`), which every public method uses for everything
    /// that follows, so a clock that steps backward cannot hand out a
    /// certificate whose `valid_after` precedes one already issued, or
    /// resurrect a window or cooldown that already lapsed.
    ///
    /// A pending request that has expired is timed out as of the moment it
    /// actually expired (`p.created + ttl`), not as of `now`: the cooldown
    /// that follows a timeout must count from when the person's window to
    /// answer actually closed, not from whenever some later call happened
    /// to notice.
    fn tick(&mut self, now: SystemTime) -> SystemTime {
        let now = now.max(self.high_water);
        self.high_water = now;
        let ttl = self.policy.pending_ttl;
        if let Some(p) = self.pending.take_if(|p| p.created + ttl <= now) {
            let expired_at = p.created + ttl;
            self.events.push(Event::TimedOut {
                id: p.id,
                host: p.scope.host,
                at: expired_at,
            });
            self.strike_at(expired_at, Outcome::TimedOut);
        }
        self.windows.retain(|w| w.scope.ends_at > now);
        while self.accepted.front().is_some_and(|t| *t + HOUR <= now) {
            self.accepted.pop_front();
        }
        now
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_nonce(entropy: &mut dyn Entropy) -> String {
    let mut buf = [0u8; 32];
    entropy.fill(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Eight characters from an alphabet without look-alikes, as `XXXX-XXXX`.
/// The alphabet has 32 symbols so one masked byte maps uniformly.
fn match_code(entropy: &mut dyn Entropy) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = [0u8; 8];
    entropy.fill(&mut buf);
    let mut code = String::with_capacity(9);
    for (i, b) in buf.iter().enumerate() {
        if i == 4 {
            code.push('-');
        }
        code.push(ALPHABET[(b & 31) as usize] as char);
    }
    code
}

fn printable(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExampl session";
    const OTHER_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherOtherOtherOtherOtherOtherOtherOtherOth rogue";
    const MIN: Duration = Duration::from_secs(60);

    struct Counter(u8);

    impl Entropy for Counter {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000 + secs)
    }

    fn grants() -> Grants {
        let mut principals = BTreeMap::new();
        principals.insert("web01".to_owned(), "agent-admin:web01".to_owned());
        principals.insert("db01".to_owned(), "agent-admin:db01".to_owned());
        Grants::new(Policy::default(), principals, 1)
    }

    fn approval_for(p: &Pending) -> Approval {
        Approval {
            id: p.id,
            nonce: p.nonce.clone(),
            scope: p.scope.clone(),
        }
    }

    fn approved(g: &mut Grants, now: SystemTime) -> Window {
        let p = g
            .request(
                now,
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                None,
            )
            .unwrap();
        g.approve(now, &approval_for(&p)).unwrap()
    }

    #[test]
    fn request_builds_the_enforced_scope_from_policy_not_prose() {
        let mut g = grants();
        let p = g
            .request(
                t(0),
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                None,
            )
            .unwrap();
        assert_eq!(p.scope.principal, "agent-admin:web01");
        assert_eq!(p.scope.ends_at, t(3600));
        assert_eq!(p.nonce.len(), 64);
        assert_eq!(p.match_code, "ABCD-EFGH");
        g.decline(t(0), p.id).unwrap();

        let later = t(3600);
        let p = g
            .request(
                later,
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                Some(9 * HOUR),
            )
            .unwrap();
        assert_eq!(
            p.scope.ends_at,
            later + 4 * HOUR,
            "window clamps to the max"
        );
    }

    #[test]
    fn unknown_hosts_and_bad_keys_are_refused_before_anything_counts() {
        let mut g = grants();
        let r = g.request(
            t(0),
            &mut Counter(0),
            "nope",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        );
        assert_eq!(r, Err(Refusal::UnknownHost));
        let r = g.request(
            t(0),
            &mut Counter(0),
            "web01",
            "ssh-ed25519 AAA\nevil",
            "x",
            "deploy",
            None,
            None,
        );
        assert_eq!(r, Err(Refusal::BadKey));
        let r = g.request(
            t(0),
            &mut Counter(0),
            "web01",
            "   ",
            "x",
            "deploy",
            None,
            None,
        );
        assert_eq!(r, Err(Refusal::BadKey));
        assert!(g.accepted.is_empty(), "refusals do not spend the rate cap");
        assert!(g.take_events().is_empty());
    }

    #[test]
    fn one_pending_request_at_a_time() {
        let mut g = grants();
        g.request(
            t(0),
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        )
        .unwrap();
        let r = g.request(
            t(1),
            &mut Counter(0),
            "db01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        );
        assert_eq!(r, Err(Refusal::Busy));
    }

    #[test]
    fn approval_must_cover_this_nonce_and_this_scope() {
        let mut g = grants();
        let p = g
            .request(
                t(0),
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                None,
            )
            .unwrap();

        let mut wrong_nonce = approval_for(&p);
        wrong_nonce.nonce = "00".repeat(32);
        assert_eq!(g.approve(t(1), &wrong_nonce), Err(Refusal::NonceMismatch));

        let mut lied_about_window = approval_for(&p);
        lied_about_window.scope.ends_at = t(8 * 3600);
        assert_eq!(
            g.approve(t(1), &lied_about_window),
            Err(Refusal::ScopeMismatch)
        );

        let mut other_host = approval_for(&p);
        other_host.scope.host = "db01".to_owned();
        assert_eq!(g.approve(t(1), &other_host), Err(Refusal::ScopeMismatch));

        let mut wrong_id = approval_for(&p);
        wrong_id.id += 1;
        assert_eq!(g.approve(t(1), &wrong_id), Err(Refusal::NoSuchRequest));

        let w = g.approve(t(1), &approval_for(&p)).unwrap();
        assert_eq!(w.scope, p.scope);
        assert_eq!(g.windows(t(1)).len(), 1);
    }

    #[test]
    fn an_approval_cannot_be_replayed() {
        let mut g = grants();
        let p = g
            .request(
                t(0),
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                None,
            )
            .unwrap();
        let a = approval_for(&p);
        g.approve(t(1), &a).unwrap();
        assert_eq!(g.approve(t(2), &a), Err(Refusal::NoSuchRequest));
        assert_eq!(g.windows(t(2)).len(), 1);
    }

    /// Unwrap an [`Issuance`] this test expects to be fresh; panics with the
    /// actual value otherwise, which is more useful than a bare `unwrap`.
    fn fresh(i: Issuance) -> Certificate {
        match i {
            Issuance::Fresh(c) => c,
            other => panic!("expected a fresh certificate, got {other:?}"),
        }
    }

    #[test]
    fn certificates_go_only_to_the_approved_key_and_never_outlive_the_window() {
        let mut g = grants();
        let w = approved(&mut g, t(0));

        assert_eq!(
            g.issue(t(1), "web01", OTHER_KEY, false),
            Err(Refusal::KeyMismatch)
        );
        assert_eq!(g.issue(t(1), "db01", KEY, false), Err(Refusal::NoWindow));

        let c = fresh(g.issue(t(60), "web01", KEY, false).unwrap());
        assert_eq!(c.principal, "agent-admin:web01");
        assert_eq!(c.public_key, KEY);
        assert_eq!(c.valid_after, t(60));
        assert_eq!(c.valid_before, t(60) + 15 * MIN);

        // Past half the certificate's TTL and still short of the window's
        // end, a re-request mints again rather than reusing.
        let near_end = w.scope.ends_at - 5 * MIN;
        let c2 = fresh(g.issue(near_end, "web01", KEY, false).unwrap());
        assert_eq!(c2.valid_before, w.scope.ends_at, "clipped to the window");
        assert!(c2.serial > c.serial);

        assert_eq!(
            g.issue(w.scope.ends_at, "web01", KEY, false),
            Err(Refusal::NoWindow),
            "the window is closed at its end, inclusive"
        );
    }

    #[test]
    fn two_windows_on_one_host_each_serve_their_own_key() {
        let mut g = grants();
        let w1 = approved(&mut g, t(0));
        let later = t(600);
        let p = g
            .request(
                later,
                &mut Counter(0),
                "web01",
                OTHER_KEY,
                "rogue",
                "deploy",
                None,
                None,
            )
            .unwrap();
        let w2 = g.approve(later, &approval_for(&p)).unwrap();
        assert!(w2.scope.ends_at > w1.scope.ends_at);

        let c1 = fresh(g.issue(t(1200), "web01", KEY, false).unwrap());
        assert_eq!(
            c1.window_ends_at, w1.scope.ends_at,
            "the first key's own window"
        );
        let c2 = fresh(g.issue(t(1200), "web01", OTHER_KEY, false).unwrap());
        assert_eq!(c2.window_ends_at, w2.scope.ends_at);
        let third =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIThirdThirdThirdThirdThirdThirdThirdThirdThi x";
        assert_eq!(
            g.issue(t(1200), "web01", third, false),
            Err(Refusal::KeyMismatch)
        );
        assert_eq!(g.issue(t(1200), "db01", KEY, false), Err(Refusal::NoWindow));
    }

    #[test]
    fn repeated_issuance_inside_a_window_re_serves_the_last_certificate() {
        let mut g = grants();
        approved(&mut g, t(0));

        let first = fresh(g.issue(t(1), "web01", KEY, false).unwrap());

        match g.issue(t(2), "web01", KEY, false).unwrap() {
            Issuance::Reuse { serial, .. } => assert_eq!(
                serial, first.serial,
                "a re-request a second later gets the same certificate back"
            ),
            other @ Issuance::Fresh(_) => {
                panic!("a re-request a second later must reuse, got {other:?}")
            }
        }

        // `force_fresh` always mints, even while a reuse would otherwise
        // apply: it exists for the daemon's cache-miss fallback, and a
        // fallback that could itself return a reuse would defeat the point.
        let forced = fresh(g.issue(t(2), "web01", KEY, true).unwrap());
        assert!(forced.serial > first.serial, "force_fresh always mints");

        // Past half the certificate TTL from the certificate actually on
        // file (`forced`, since it replaced `first` in the window's
        // `last_issued`), a plain re-request mints again rather than
        // reusing.
        let half_ttl = Policy::default().cert_ttl / 2;
        let later = t(2) + half_ttl + Duration::from_secs(1);
        match g.issue(later, "web01", KEY, false).unwrap() {
            Issuance::Fresh(c) => assert!(
                c.serial > forced.serial,
                "past half the TTL a fresh certificate is minted"
            ),
            other @ Issuance::Reuse { .. } => {
                panic!("past half the TTL this must be fresh, got {other:?}")
            }
        }
    }

    #[test]
    fn time_never_runs_backward_inside_grants() {
        let mut g = grants();
        // A 60-minute window opened at t(1000) ends at t(4600).
        let w = approved(&mut g, t(1000));

        let first = fresh(g.issue(t(2000), "web01", KEY, true).unwrap());
        assert_eq!(first.valid_after, t(2000));

        // The clock steps backward; `force_fresh` still mints, but the
        // certificate's `valid_after` must not move behind t(2000), the
        // latest time this `Grants` has already seen.
        let stepped_back = fresh(g.issue(t(500), "web01", KEY, true).unwrap());
        assert_eq!(
            stepped_back.valid_after,
            t(2000),
            "time must not run backward"
        );
        assert!(stepped_back.serial > first.serial);

        // Advance past the window's end (t(4600)); it closes for good.
        assert_eq!(
            g.issue(t(5000), "web01", KEY, true),
            Err(Refusal::NoWindow),
            "the window has expired"
        );
        assert!(w.scope.ends_at < t(5000));

        // A clock that steps backward again must not resurrect it.
        assert_eq!(
            g.issue(t(4000), "web01", KEY, true),
            Err(Refusal::NoWindow),
            "an expired window must stay expired even if the clock steps back"
        );
    }

    #[test]
    fn kill_also_declines_a_pending_request_for_that_host() {
        let mut g = grants();
        approved(&mut g, t(0));
        let p = g
            .request(
                t(10),
                &mut Counter(0),
                "web01",
                OTHER_KEY,
                "rogue",
                "deploy",
                None,
                None,
            )
            .unwrap();
        g.kill(t(20), "web01").unwrap();
        assert!(
            g.pending(t(21)).is_none(),
            "the pending request went with the window"
        );
        assert_eq!(
            g.approve(t(21), &approval_for(&p)),
            Err(Refusal::NoSuchRequest)
        );
        assert!(
            g.cooldown_until.is_some(),
            "a kill costs the requester a cooldown"
        );
        let kinds: Vec<bool> = g
            .take_events()
            .iter()
            .map(|e| matches!(e, Event::Declined { .. } | Event::Killed { .. }))
            .collect();
        assert_eq!(&kinds[kinds.len() - 2..], [true, true]);

        let mut g = grants();
        g.request(
            t(0),
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        )
        .unwrap();
        g.kill(t(1), "web01").unwrap();
        assert!(
            g.pending(t(2)).is_none(),
            "kill with no window still cancels the request"
        );
        assert_eq!(g.kill(t(3), "web01"), Err(Refusal::NoWindow));
    }

    #[test]
    fn outstanding_counts_windows_and_a_waiting_request() {
        let mut g = grants();
        assert_eq!(g.outstanding(t(0)), 0, "nothing open, nothing waiting");

        g.request(
            t(0),
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        )
        .unwrap();
        assert_eq!(g.outstanding(t(1)), 1, "a request waiting counts");

        let p = g.pending(t(1)).unwrap().clone();
        g.approve(t(2), &approval_for(&p)).unwrap();
        assert_eq!(
            g.outstanding(t(2)),
            1,
            "approving trades the request for a window, it does not add one"
        );

        g.kill(t(3), "web01").unwrap();
        assert_eq!(g.outstanding(t(3)), 0, "killing the window clears it");

        // And expiry, which sends no push at all: the count is still right
        // whenever it is next asked, even though nothing announced it.
        approved(&mut g, t(10));
        assert_eq!(g.outstanding(t(11)), 1);
        let far = t(10) + Policy::default().max_window + Duration::from_secs(1);
        assert_eq!(g.outstanding(far), 0, "an expired window stops counting");
    }

    #[test]
    fn kill_closes_the_window() {
        let mut g = grants();
        approved(&mut g, t(0));
        assert_eq!(g.kill(t(1), "db01"), Err(Refusal::NoWindow));
        g.kill(t(1), "web01").unwrap();
        assert_eq!(g.issue(t(2), "web01", KEY, false), Err(Refusal::NoWindow));
        assert!(g.windows(t(2)).is_empty());
    }

    #[test]
    fn a_pending_request_times_out_and_is_recorded() {
        let mut g = grants();
        let p = g
            .request(
                t(0),
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                None,
            )
            .unwrap();
        assert!(g.pending(t(299)).is_some());
        assert!(g.pending(t(300)).is_none());
        assert_eq!(
            g.approve(t(301), &approval_for(&p)),
            Err(Refusal::NoSuchRequest),
            "a late approval of an expired request issues nothing"
        );
        let events = g.take_events();
        assert!(matches!(events.last(), Some(Event::TimedOut { id, .. }) if *id == p.id));
    }

    #[test]
    fn timeout_cooldown_counts_from_the_requests_expiry_not_from_discovery() {
        let ttl = Policy::default().pending_ttl;
        let base_cooldown = Policy::default().base_cooldown;
        let created = t(0);

        // Nothing ever polled this `Grants` between the request expiring
        // and this later call, but the cooldown it started must still be
        // measured from the expiry, not from now: by this point it has
        // already run out, and the request is accepted.
        let mut g = grants();
        g.request(
            created,
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        )
        .unwrap();
        let late = created + ttl + base_cooldown + Duration::from_secs(1);
        let r = g.request(
            late,
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        );
        assert!(
            r.is_ok(),
            "a cooldown counted from expiry has already run out: {r:?}"
        );

        // Just after the request expired, its cooldown is still running,
        // and it ends at expiry plus the base cooldown.
        let mut g = grants();
        g.request(
            created,
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        )
        .unwrap();
        let just_after_expiry = created + ttl + Duration::from_secs(1);
        let r = g.request(
            just_after_expiry,
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        );
        assert_eq!(
            r,
            Err(Refusal::Cooldown {
                until: created + ttl + base_cooldown
            })
        );
    }

    #[test]
    fn a_decline_costs_at_least_the_base_cooldown() {
        let mut g = grants();
        let p = g
            .request(
                t(0),
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                None,
            )
            .unwrap();
        g.decline(t(10), p.id).unwrap();
        let r = g.request(
            t(11),
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "deploy",
            None,
            None,
        );
        assert!(matches!(r, Err(Refusal::Cooldown { until }) if until >= t(10) + 5 * MIN));
    }

    #[test]
    fn an_approval_resets_the_cooldown() {
        let mut g = grants();
        let p = g
            .request(
                t(0),
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                None,
            )
            .unwrap();
        g.decline(t(10), p.id).unwrap();
        let after = t(10) + 5 * MIN;
        approved(&mut g, after);
        assert_eq!(g.strikes, 0);
        assert_eq!(g.cooldown_until, None);
    }

    #[test]
    fn cooldown_doubles_per_strike_up_to_the_cap_and_timeouts_count() {
        let mut g = grants();
        let mut now = t(0);
        let mut seen = Vec::new();
        for strike in 0..6u32 {
            let p = g
                .request(
                    now,
                    &mut Counter(0),
                    "web01",
                    KEY,
                    "laptop",
                    "deploy",
                    None,
                    None,
                )
                .unwrap();
            if strike % 2 == 0 {
                g.decline(now, p.id).unwrap();
            } else {
                assert!(g.pending(now + 5 * MIN).is_none(), "timed out");
                now += 5 * MIN;
            }
            let until = g.cooldown_until.unwrap();
            seen.push(until.duration_since(now).unwrap());
            now = until;
        }
        assert_eq!(
            seen,
            [5 * MIN, 10 * MIN, 20 * MIN, 40 * MIN, 60 * MIN, 60 * MIN]
        );
    }

    #[test]
    fn the_hourly_cap_counts_every_requester_together() {
        let mut g = grants();
        for i in 0..6u64 {
            let now = t(i * 60);
            let p = g
                .request(
                    now,
                    &mut Counter(0),
                    "web01",
                    KEY,
                    &format!("laptop-{i}"),
                    "deploy",
                    None,
                    None,
                )
                .unwrap();
            g.approve(now, &approval_for(&p)).unwrap();
        }
        let r = g.request(
            t(400),
            &mut Counter(0),
            "db01",
            OTHER_KEY,
            "rogue",
            "deploy",
            None,
            None,
        );
        assert_eq!(r, Err(Refusal::RateCapped { until: t(3600) }));
        assert!(
            g.request(
                t(3600),
                &mut Counter(0),
                "db01",
                OTHER_KEY,
                "rogue",
                "deploy",
                None,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn bytes_to_sign_are_stable() {
        let scope = Scope {
            host: "web01".to_owned(),
            principal: "agent-admin:web01".to_owned(),
            public_key: "ssh-ed25519 AAAA key".to_owned(),
            ends_at: t(3600),
        };
        let bytes = scope.bytes_to_sign("abc123");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "shoephone-scope-v1\nhost=web01\nprincipal=agent-admin:web01\nkey=ssh-ed25519 AAAA key\nends_at=1800003600\nnonce=abc123\n"
        );
    }

    #[test]
    fn bound_challenge_is_sha256_of_bytes_to_sign() {
        let scope = Scope {
            host: "web01".to_owned(),
            principal: "agent-admin:web01".to_owned(),
            public_key: "ssh-ed25519 AAAA key".to_owned(),
            ends_at: t(3600),
        };
        let challenge = bound_challenge(&scope, "abc123");
        let hex: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
        // Computed once with `shasum -a 256` over the same bytes
        // `bytes_to_sign_are_stable` asserts above.
        assert_eq!(
            hex,
            "247cc1ea3aa1105567d6c526cc4b32ecea5c9ccb440247497cb07caecc1bc48d"
        );
    }

    #[test]
    fn the_ledger_sees_every_outcome() {
        let mut g = grants();
        let p = g
            .request(
                t(0),
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                "deploy",
                None,
                None,
            )
            .unwrap();
        g.decline(t(1), p.id).unwrap();
        let w = approved(&mut g, t(600));
        g.issue(t(601), "web01", KEY, false).unwrap();
        g.kill(t(602), "web01").unwrap();
        let kinds: Vec<&str> = g
            .take_events()
            .iter()
            .map(|e| match e {
                Event::Requested { .. } => "requested",
                Event::Approved { .. } => "approved",
                Event::Declined { .. } => "declined",
                Event::TimedOut { .. } => "timed_out",
                Event::Issued { .. } => "issued",
                Event::Killed { .. } => "killed",
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "requested",
                "declined",
                "requested",
                "approved",
                "issued",
                "killed"
            ]
        );
        assert_eq!(w.id, 2);
        assert!(g.take_events().is_empty(), "drained");
    }

    #[test]
    fn match_code_avoids_lookalikes_and_nonce_is_hex() {
        let mut all = Counter(0);
        let code = match_code(&mut all);
        assert_eq!(code.len(), 9);
        for c in code.chars().filter(|c| *c != '-') {
            assert!(!"0O1IL".contains(c), "{code}");
        }
        let nonce = hex_nonce(&mut Counter(250));
        assert!(nonce.starts_with("fafbfcfdfeff0001"));
    }

    #[test]
    fn a_request_needs_a_reason_and_it_is_kept_printable_and_short() {
        let mut g = grants();
        let r = g.request(
            t(0),
            &mut Counter(0),
            "web01",
            KEY,
            "laptop",
            "   ",
            None,
            None,
        );
        assert_eq!(r, Err(Refusal::NoReason));
        let long = format!("rotate\x07 the {} key", "x".repeat(300));
        let p = g
            .request(
                t(0),
                &mut Counter(0),
                "web01",
                KEY,
                "laptop",
                &long,
                None,
                None,
            )
            .unwrap();
        assert!(!p.reason.contains('\x07'));
        assert_eq!(p.reason.chars().count(), 200);
        assert!(
            matches!(g.take_events().as_slice(), [Event::Requested { reason, .. }] if reason == &p.reason)
        );
    }

    #[test]
    fn context_is_kept_only_when_it_is_an_https_link() {
        let mut g = grants();
        for (given, kept) in [
            (
                Some("https://claude.ai/code/session_1"),
                Some("https://claude.ai/code/session_1"),
            ),
            (Some("http://example.com"), None),
            (Some("https://a b"), None),
            (Some("  "), None),
            (None, None),
        ] {
            let p = g
                .request(
                    t(0),
                    &mut Counter(0),
                    "web01",
                    KEY,
                    "laptop",
                    "deploy",
                    given,
                    None,
                )
                .unwrap();
            assert_eq!(p.context.as_deref(), kept, "{given:?}");
            g.decline(t(1), p.id).unwrap();
            g.cooldown_until = None;
        }
    }
}
