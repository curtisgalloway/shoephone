// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The grant state machine, for one approver and one user CA.
//!
//! Everything security-relevant that does not need cryptography lives here,
//! with no I/O and no clock of its own: every method takes `now`, and the
//! only randomness arrives through [`Entropy`], so the whole thing is
//! exercised by plain unit tests. The daemon wraps it in a mutex, feeds it
//! the wall clock and the OS random source, verifies the approver's WebAuthn
//! assertion over [`Scope::bytes_to_sign`] *before* calling
//! [`Grants::approve`], and hands each [`Certificate`] to the signer.
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
    /// Lifetime of each certificate issued inside a window. This is also the
    /// worst-case latency of the kill switch.
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
}

/// What the approver's verified signature covered. The daemon builds this
/// from the client's submission only after the WebAuthn assertion checks out
/// over `scope.bytes_to_sign(&nonce)`.
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

/// Why a call did nothing. None of these leak anything the requester does
/// not already know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The host is not in the principal table.
    UnknownHost,
    /// The key is empty or carries control characters.
    BadKey,
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
        serial: u64,
        host: String,
        valid_before: SystemTime,
        at: SystemTime,
    },
    Killed {
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
}

impl Grants {
    pub fn new(policy: Policy, principals: BTreeMap<String, String>) -> Self {
        Self {
            policy,
            principals,
            next_id: 1,
            pending: None,
            windows: Vec::new(),
            accepted: VecDeque::new(),
            cooldown_until: None,
            strikes: 0,
            events: Vec::new(),
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// File a request. On success the returned [`Pending`] carries the
    /// enforced scope, the nonce and the match code; the CLI shows the match
    /// code and polls.
    pub fn request(
        &mut self,
        now: SystemTime,
        entropy: &mut dyn Entropy,
        host: &str,
        public_key: &str,
        requester: &str,
        wanted: Option<Duration>,
    ) -> Result<Pending, Refusal> {
        self.tick(now);
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
        };
        self.accepted.push_back(now);
        self.events.push(Event::Requested {
            id,
            host: host.to_owned(),
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
        self.tick(now);
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
        self.tick(now);
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
    pub fn issue(
        &mut self,
        now: SystemTime,
        host: &str,
        public_key: &str,
    ) -> Result<Certificate, Refusal> {
        self.tick(now);
        let public_key = public_key.trim();
        // Select on host and key together. Two windows can be open for one
        // host (a second request is allowed while a window is open, and a
        // new window is a new approval), and picking by host alone would
        // refuse a key that was legitimately approved for the other one.
        let mut for_host = self
            .windows
            .iter()
            .filter(|w| w.scope.host == host)
            .peekable();
        if for_host.peek().is_none() {
            return Err(Refusal::NoWindow);
        }
        let window = for_host
            .filter(|w| w.scope.public_key == public_key)
            .max_by_key(|w| w.scope.ends_at)
            .ok_or(Refusal::KeyMismatch)?;
        let valid_before = (now + self.policy.cert_ttl).min(window.scope.ends_at);
        let cert = Certificate {
            serial: 0,
            principal: window.scope.principal.clone(),
            public_key: window.scope.public_key.clone(),
            valid_after: now,
            valid_before,
            window_ends_at: window.scope.ends_at,
        };
        let cert = Certificate {
            serial: self.take_id(),
            ..cert
        };
        self.events.push(Event::Issued {
            serial: cert.serial,
            host: host.to_owned(),
            valid_before,
            at: now,
        });
        Ok(cert)
    }

    /// The kill switch: close every window for a host. Certificates already
    /// issued run out within one TTL.
    ///
    /// A request still pending for that host is declined too, with the
    /// usual cooldown: kill means "stop", and a tap on the phone a moment
    /// later must not reopen what was just closed.
    pub fn kill(&mut self, now: SystemTime, host: &str) -> Result<(), Refusal> {
        self.tick(now);
        let before = self.windows.len();
        self.windows.retain(|w| w.scope.host != host);
        let pending = self.pending.take_if(|p| p.scope.host == host);
        if self.windows.len() == before && pending.is_none() {
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
        self.events.push(Event::Killed {
            host: host.to_owned(),
            at: now,
        });
        Ok(())
    }

    /// Windows still open at `now`.
    pub fn windows(&mut self, now: SystemTime) -> &[Window] {
        self.tick(now);
        &self.windows
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
        self.strikes = self.strikes.saturating_add(1);
        self.cooldown_until = Some(now + self.cooldown_after(outcome));
    }

    /// Advance time: expire the pending request, drop closed windows, and
    /// forget accepted requests older than an hour.
    fn tick(&mut self, now: SystemTime) {
        let ttl = self.policy.pending_ttl;
        if let Some(p) = self.pending.take_if(|p| p.created + ttl <= now) {
            self.events.push(Event::TimedOut {
                id: p.id,
                host: p.scope.host,
                at: now,
            });
            self.strike(now, Outcome::TimedOut);
        }
        self.windows.retain(|w| w.scope.ends_at > now);
        while self.accepted.front().is_some_and(|t| *t + HOUR <= now) {
            self.accepted.pop_front();
        }
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
        Grants::new(Policy::default(), principals)
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
            .request(now, &mut Counter(0), "web01", KEY, "laptop", None)
            .unwrap();
        g.approve(now, &approval_for(&p)).unwrap()
    }

    #[test]
    fn request_builds_the_enforced_scope_from_policy_not_prose() {
        let mut g = grants();
        let p = g
            .request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
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
        let r = g.request(t(0), &mut Counter(0), "nope", KEY, "laptop", None);
        assert_eq!(r, Err(Refusal::UnknownHost));
        let r = g.request(
            t(0),
            &mut Counter(0),
            "web01",
            "ssh-ed25519 AAA\nevil",
            "x",
            None,
        );
        assert_eq!(r, Err(Refusal::BadKey));
        let r = g.request(t(0), &mut Counter(0), "web01", "   ", "x", None);
        assert_eq!(r, Err(Refusal::BadKey));
        assert!(g.accepted.is_empty(), "refusals do not spend the rate cap");
        assert!(g.take_events().is_empty());
    }

    #[test]
    fn one_pending_request_at_a_time() {
        let mut g = grants();
        g.request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
            .unwrap();
        let r = g.request(t(1), &mut Counter(0), "db01", KEY, "laptop", None);
        assert_eq!(r, Err(Refusal::Busy));
    }

    #[test]
    fn approval_must_cover_this_nonce_and_this_scope() {
        let mut g = grants();
        let p = g
            .request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
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
            .request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
            .unwrap();
        let a = approval_for(&p);
        g.approve(t(1), &a).unwrap();
        assert_eq!(g.approve(t(2), &a), Err(Refusal::NoSuchRequest));
        assert_eq!(g.windows(t(2)).len(), 1);
    }

    #[test]
    fn certificates_go_only_to_the_approved_key_and_never_outlive_the_window() {
        let mut g = grants();
        let w = approved(&mut g, t(0));

        assert_eq!(g.issue(t(1), "web01", OTHER_KEY), Err(Refusal::KeyMismatch));
        assert_eq!(g.issue(t(1), "db01", KEY), Err(Refusal::NoWindow));

        let c = g.issue(t(60), "web01", KEY).unwrap();
        assert_eq!(c.principal, "agent-admin:web01");
        assert_eq!(c.public_key, KEY);
        assert_eq!(c.valid_after, t(60));
        assert_eq!(c.valid_before, t(60) + 15 * MIN);

        let near_end = w.scope.ends_at - 5 * MIN;
        let c2 = g.issue(near_end, "web01", KEY).unwrap();
        assert_eq!(c2.valid_before, w.scope.ends_at, "clipped to the window");
        assert!(c2.serial > c.serial);

        assert_eq!(
            g.issue(w.scope.ends_at, "web01", KEY),
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
            .request(later, &mut Counter(0), "web01", OTHER_KEY, "rogue", None)
            .unwrap();
        let w2 = g.approve(later, &approval_for(&p)).unwrap();
        assert!(w2.scope.ends_at > w1.scope.ends_at);

        let c1 = g.issue(t(1200), "web01", KEY).unwrap();
        assert_eq!(
            c1.window_ends_at, w1.scope.ends_at,
            "the first key's own window"
        );
        let c2 = g.issue(t(1200), "web01", OTHER_KEY).unwrap();
        assert_eq!(c2.window_ends_at, w2.scope.ends_at);
        let third =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIThirdThirdThirdThirdThirdThirdThirdThirdThi x";
        assert_eq!(g.issue(t(1200), "web01", third), Err(Refusal::KeyMismatch));
        assert_eq!(g.issue(t(1200), "db01", KEY), Err(Refusal::NoWindow));
    }

    #[test]
    fn kill_also_declines_a_pending_request_for_that_host() {
        let mut g = grants();
        approved(&mut g, t(0));
        let p = g
            .request(t(10), &mut Counter(0), "web01", OTHER_KEY, "rogue", None)
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
        g.request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
            .unwrap();
        g.kill(t(1), "web01").unwrap();
        assert!(
            g.pending(t(2)).is_none(),
            "kill with no window still cancels the request"
        );
        assert_eq!(g.kill(t(3), "web01"), Err(Refusal::NoWindow));
    }

    #[test]
    fn kill_closes_the_window() {
        let mut g = grants();
        approved(&mut g, t(0));
        assert_eq!(g.kill(t(1), "db01"), Err(Refusal::NoWindow));
        g.kill(t(1), "web01").unwrap();
        assert_eq!(g.issue(t(2), "web01", KEY), Err(Refusal::NoWindow));
        assert!(g.windows(t(2)).is_empty());
    }

    #[test]
    fn a_pending_request_times_out_and_is_recorded() {
        let mut g = grants();
        let p = g
            .request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
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
    fn a_decline_costs_at_least_the_base_cooldown() {
        let mut g = grants();
        let p = g
            .request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
            .unwrap();
        g.decline(t(10), p.id).unwrap();
        let r = g.request(t(11), &mut Counter(0), "web01", KEY, "laptop", None);
        assert!(matches!(r, Err(Refusal::Cooldown { until }) if until >= t(10) + 5 * MIN));
    }

    #[test]
    fn an_approval_resets_the_cooldown() {
        let mut g = grants();
        let p = g
            .request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
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
                .request(now, &mut Counter(0), "web01", KEY, "laptop", None)
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
                    None,
                )
                .unwrap();
            g.approve(now, &approval_for(&p)).unwrap();
        }
        let r = g.request(t(400), &mut Counter(0), "db01", OTHER_KEY, "rogue", None);
        assert_eq!(r, Err(Refusal::RateCapped { until: t(3600) }));
        assert!(
            g.request(t(3600), &mut Counter(0), "db01", OTHER_KEY, "rogue", None)
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
    fn the_ledger_sees_every_outcome() {
        let mut g = grants();
        let p = g
            .request(t(0), &mut Counter(0), "web01", KEY, "laptop", None)
            .unwrap();
        g.decline(t(1), p.id).unwrap();
        let w = approved(&mut g, t(600));
        g.issue(t(601), "web01", KEY).unwrap();
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
}
