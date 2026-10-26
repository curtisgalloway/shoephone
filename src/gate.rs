// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The rules every kind of request shares: one request awaiting a verdict at
//! a time, a rolling hourly cap, and a cooldown that grows with each request
//! that ends without approval.
//!
//! SSH grants and Terraform jobs both pass through one [`Gate`], so a job
//! cannot dodge the cap by not being an SSH grant, and the approver is never
//! asked two questions at once. Like [`crate::grant`], it has no clock of its
//! own: every method takes the time it should act as of.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

use crate::grant::{Policy, Refusal};

pub(crate) const HOUR: Duration = Duration::from_secs(60 * 60);

/// What holds the gate's single slot: a request awaiting a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occupant {
    /// An SSH grant request, by its id.
    Ssh(u64),
    /// A Terraform job, by its id.
    Job(u64),
}

/// The shared slot, rate cap and cooldown for one approver.
#[derive(Debug, Default)]
pub struct Gate {
    occupant: Option<Occupant>,
    /// Times of accepted requests in the last hour, oldest first.
    pub(crate) accepted: VecDeque<SystemTime>,
    pub(crate) cooldown_until: Option<SystemTime>,
    /// Consecutive requests that ended without approval.
    pub(crate) strikes: u32,
}

impl Gate {
    pub fn new() -> Gate {
        Gate::default()
    }

    /// Let a request in, or say why not. Checks, in this order, that the slot
    /// is free, that no cooldown is running, and that the hourly cap is not
    /// spent. On success the acceptance counts against the cap and
    /// `occupant` holds the slot until [`Gate::release`].
    pub fn admit(
        &mut self,
        now: SystemTime,
        policy: &Policy,
        occupant: Occupant,
    ) -> Result<(), Refusal> {
        if self.occupant.is_some() {
            return Err(Refusal::Busy);
        }
        if let Some(until) = self.cooldown_until.filter(|u| *u > now) {
            return Err(Refusal::Cooldown { until });
        }
        if self.accepted.len() >= policy.max_requests_per_hour {
            let oldest = self.accepted.front().copied().unwrap_or(now);
            return Err(Refusal::RateCapped {
                until: oldest + HOUR,
            });
        }
        self.accepted.push_back(now);
        self.occupant = Some(occupant);
        Ok(())
    }

    /// What [`Gate::admit`] would say at `now`, changing nothing: not even
    /// the expiry of old acceptances, which are simply not counted.
    pub fn check(&self, now: SystemTime, policy: &Policy) -> Result<(), Refusal> {
        if self.occupant.is_some() {
            return Err(Refusal::Busy);
        }
        if let Some(until) = self.cooldown_until.filter(|u| *u > now) {
            return Err(Refusal::Cooldown { until });
        }
        let mut live = self.accepted.iter().filter(|t| **t + HOUR > now);
        if live.clone().count() >= policy.max_requests_per_hour {
            let oldest = live.next().copied().unwrap_or(now);
            return Err(Refusal::RateCapped {
                until: oldest + HOUR,
            });
        }
        Ok(())
    }

    /// Free the slot, if `occupant` is the one holding it. The acceptance
    /// stays counted against the cap.
    pub fn release(&mut self, occupant: Occupant) {
        if self.occupant == Some(occupant) {
            self.occupant = None;
        }
    }

    /// Who holds the slot, if anyone.
    pub fn busy(&self) -> Option<Occupant> {
        self.occupant
    }

    /// Record a request that ended without approval as of `at`, and start the
    /// cooldown counting from there. A decline or kill passes the moment it
    /// happened; a timeout passes the moment the request actually expired,
    /// which is earlier than "now" when nothing polled in between.
    ///
    /// The cooldown is the base cooldown, doubling with each consecutive
    /// strike, capped at [`Policy::max_cooldown`]. A timeout counts exactly
    /// like a decline. The person did not say no, but an agent that files
    /// requests nobody answers is the habituation pattern this cap exists to
    /// break, and `SKILL.md` already tells the agent both cost a cooldown. With
    /// the defaults, strikes cost 5, 10, 20, 40, then 60 minutes each; the cap
    /// keeps a bad afternoon from becoming a locked-out week, while five
    /// unanswered requests still cost over two hours.
    pub fn strike_at(&mut self, at: SystemTime, policy: &Policy) {
        self.strikes = self.strikes.saturating_add(1);
        let doublings = self.strikes.saturating_sub(1).min(16);
        let cooldown = (policy.base_cooldown * 2u32.pow(doublings)).min(policy.max_cooldown);
        self.cooldown_until = Some(at + cooldown);
    }

    /// An approval: forget the strikes and end any cooldown. Only an approval
    /// does this.
    pub fn approved(&mut self) {
        self.strikes = 0;
        self.cooldown_until = None;
    }

    /// Forget accepted requests older than an hour.
    pub fn tick(&mut self, now: SystemTime) {
        while self.accepted.front().is_some_and(|t| *t + HOUR <= now) {
            self.accepted.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::grant::{Entropy, Grants};

    const MIN: Duration = Duration::from_secs(60);

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000 + secs)
    }

    struct Zeros;

    impl Entropy for Zeros {
        fn fill(&mut self, buf: &mut [u8]) {
            buf.fill(0);
        }
    }

    #[test]
    fn one_request_at_a_time() {
        let p = Policy::default();
        let mut gate = Gate::new();
        assert_eq!(gate.busy(), None);
        gate.admit(t(0), &p, Occupant::Ssh(1)).unwrap();
        assert_eq!(gate.busy(), Some(Occupant::Ssh(1)));
        assert_eq!(gate.admit(t(1), &p, Occupant::Job(2)), Err(Refusal::Busy));
        gate.release(Occupant::Job(2));
        assert_eq!(gate.busy(), Some(Occupant::Ssh(1)), "not the holder");
        gate.release(Occupant::Ssh(1));
        assert_eq!(gate.busy(), None);
        gate.admit(t(2), &p, Occupant::Job(2)).unwrap();
    }

    #[test]
    fn refusals_do_not_spend_the_cap() {
        let p = Policy::default();
        let mut gate = Gate::new();
        gate.admit(t(0), &p, Occupant::Ssh(1)).unwrap();
        let _ = gate.admit(t(1), &p, Occupant::Ssh(2));
        assert_eq!(gate.accepted.len(), 1);
    }

    #[test]
    fn cooldown_doubles_per_strike_up_to_the_cap() {
        let p = Policy::default();
        let mut gate = Gate::new();
        let mut now = t(0);
        let mut seen = Vec::new();
        for id in 0..6u64 {
            gate.admit(now, &p, Occupant::Ssh(id)).unwrap();
            gate.release(Occupant::Ssh(id));
            gate.strike_at(now, &p);
            let until = gate.cooldown_until.unwrap();
            seen.push(until.duration_since(now).unwrap());
            assert_eq!(
                gate.admit(now, &p, Occupant::Ssh(99)),
                Err(Refusal::Cooldown { until })
            );
            now = until;
        }
        assert_eq!(
            seen,
            [5 * MIN, 10 * MIN, 20 * MIN, 40 * MIN, 60 * MIN, 60 * MIN]
        );
    }

    #[test]
    fn an_approval_resets_the_strikes_and_the_cooldown() {
        let p = Policy::default();
        let mut gate = Gate::new();
        gate.strike_at(t(0), &p);
        gate.strike_at(t(0), &p);
        gate.approved();
        assert_eq!(gate.strikes, 0);
        assert_eq!(gate.cooldown_until, None);
        gate.strike_at(t(0), &p);
        assert_eq!(gate.cooldown_until, Some(t(0) + 5 * MIN), "back to base");
    }

    #[test]
    fn the_hourly_cap_counts_every_occupant_together() {
        let p = Policy::default();
        let mut gate = Gate::new();
        for i in 0..6u64 {
            let occupant = if i % 2 == 0 {
                Occupant::Ssh(i)
            } else {
                Occupant::Job(i)
            };
            gate.admit(t(i * 60), &p, occupant).unwrap();
            gate.release(occupant);
        }
        assert_eq!(
            gate.admit(t(400), &p, Occupant::Job(7)),
            Err(Refusal::RateCapped { until: t(3600) })
        );
        gate.tick(t(3600));
        assert!(gate.admit(t(3600), &p, Occupant::Job(7)).is_ok());
    }

    #[test]
    fn job_occupant_blocks_ssh_request() {
        let p = Policy::default();
        let mut principals = BTreeMap::new();
        principals.insert("web01".to_owned(), "agent-admin:web01".to_owned());
        let mut grants = Grants::new(p.clone(), principals, 1);
        grants.gate_mut().admit(t(0), &p, Occupant::Job(1)).unwrap();
        let r = grants.request(
            t(1),
            &mut Zeros,
            "web01",
            "ssh-ed25519 AAAA key",
            "laptop",
            "deploy",
            None,
            None,
        );
        assert_eq!(r, Err(Refusal::Busy));
    }
}
