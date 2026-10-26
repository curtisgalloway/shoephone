// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The life of a Terraform job: a runner plans it, the approver signs the
//! plan's scope, and the runner claims the approval once and acts on it.
//!
//! This is the sibling of [`crate::grant`] and has the same shape: a pure
//! state machine with no I/O, no clock of its own (every method takes the
//! time it should act as of) and no randomness except through [`Entropy`].
//! A job shares the approver's one slot, rate cap and cooldown with SSH
//! grants through [`Gate`], so the approver is never asked two questions at
//! once.
//!
//! A job holds the gate's slot from [`Jobs::request`] through `Queued`,
//! `Working` and `Waiting`, and releases it on every way out of those
//! states. `Approved` and `Claimed` jobs do not hold it, so an SSH request
//! can be filed while an apply runs; [`Jobs::request`] still refuses `Busy`
//! while any job is not `Done`, so there is never more than one job.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::gate::{Gate, Occupant};
use crate::grant::{Entropy, Policy, Refusal, constant_time_eq, hex_nonce, match_code, printable};
use crate::scope::{ApplyScope, TrustScope};

/// What a job asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobKind {
    /// Trust a code change, identified by the digest of its archive.
    Trust { archive_sha256: String },
    /// Apply a plan. `manifest` is the agent's raw JSON text, kept as the
    /// bytes it sent.
    Apply {
        manifest: String,
        allow_destroy: bool,
    },
}

impl JobKind {
    fn name(&self) -> &'static str {
        match self {
            JobKind::Trust { .. } => "trust",
            JobKind::Apply { .. } => "apply",
        }
    }
}

/// The scope the approver signs, as the daemon enforces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobScope {
    Trust(TrustScope),
    Apply(ApplyScope),
}

impl JobScope {
    fn project(&self) -> &str {
        match self {
            JobScope::Trust(s) => &s.project,
            JobScope::Apply(s) => &s.project,
        }
    }

    fn is_well_formed(&self) -> bool {
        match self {
            JobScope::Trust(s) => s.is_well_formed(),
            JobScope::Apply(s) => s.is_well_formed(),
        }
    }

    fn matches(&self, kind: &JobKind) -> bool {
        matches!(
            (self, kind),
            (JobScope::Trust(_), JobKind::Trust { .. })
                | (JobScope::Apply(_), JobKind::Apply { .. })
        )
    }
}

/// Why a job did not complete, as the runner reports it. `detail` is
/// runner-authored text only; the daemon never puts agent prose in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub category: String,
    pub addresses: Vec<String>,
    pub detail: Option<String>,
}

/// How a job ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobResult {
    Trusted,
    Applied,
    /// The runner declined to plan (policy, bad input).
    Refused(Failure),
    /// Planning failed, or ran out of time.
    PlanFailed(Failure),
    ApplyFailed(Failure),
    /// The runner lost track of whether the apply finished.
    OutcomeUnknown,
    Declined,
    TimedOut,
    Killed,
}

/// Where a job is in its life.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    /// Filed, not yet picked up by the project's runner.
    Queued,
    /// The runner is planning.
    Working {
        runner: String,
    },
    /// The scope is submitted and frozen; the approver has not answered.
    Waiting {
        scope: JobScope,
        nonce: String,
        since: SystemTime,
    },
    /// The approver said yes; the runner has not claimed it yet.
    Approved {
        scope: JobScope,
    },
    /// The runner took the approval and is acting on it.
    Claimed,
    Done(JobResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: u64,
    pub project: String,
    pub kind: JobKind,
    pub state: JobState,
    pub reason: String,
    pub created: SystemTime,
    /// Shown on the phone and printed by the requester, so a person can see
    /// that the two are talking about the same request.
    pub match_code: String,
}

/// One entry for the approver's ledger, drained with [`Jobs::take_events`].
/// `kind` is `"trust"` or `"apply"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobEvent {
    Requested {
        id: u64,
        project: String,
        kind: &'static str,
        reason: String,
        at: SystemTime,
    },
    Started {
        id: u64,
        project: String,
        kind: &'static str,
        at: SystemTime,
    },
    Waiting {
        id: u64,
        project: String,
        kind: &'static str,
        at: SystemTime,
    },
    Approved {
        id: u64,
        project: String,
        at: SystemTime,
    },
    /// Planning ended without a scope: the runner refused or failed, or
    /// planning timed out.
    Refused {
        id: u64,
        project: String,
        category: String,
        at: SystemTime,
    },
    Applied {
        id: u64,
        project: String,
        at: SystemTime,
    },
    Trusted {
        id: u64,
        project: String,
        at: SystemTime,
    },
    ApplyFailed {
        id: u64,
        project: String,
        at: SystemTime,
    },
    OutcomeUnknown {
        id: u64,
        project: String,
        at: SystemTime,
    },
    Declined {
        id: u64,
        project: String,
        at: SystemTime,
    },
    TimedOut {
        id: u64,
        project: String,
        at: SystemTime,
    },
    Killed {
        id: u64,
        project: String,
        at: SystemTime,
    },
}

/// A job plus what the policy said when it was filed. `approve` takes no
/// policy, so the two limits it enforces travel with the job.
#[derive(Debug)]
struct Entry {
    job: Job,
    /// When the scope was submitted, i.e. how old the plan is.
    plan_at: Option<SystemTime>,
    plan_timeout: Duration,
    approval_ttl: Duration,
    max_plan_age: Duration,
}

/// Fail a `Queued` or `Working` job that outlived `plan_timeout`, dated to
/// when it lapsed, with no strike. Returns whether it did.
fn lapse_planning(
    entry: &mut Entry,
    events: &mut Vec<JobEvent>,
    gate: &mut Gate,
    now: SystemTime,
) -> bool {
    if !matches!(entry.job.state, JobState::Queued | JobState::Working { .. }) {
        return false;
    }
    let lapsed = entry.job.created + entry.plan_timeout;
    if lapsed > now {
        return false;
    }
    entry.job.state = JobState::Done(JobResult::PlanFailed(Failure {
        category: "plan_timeout".into(),
        addresses: Vec::new(),
        detail: None,
    }));
    events.push(JobEvent::Refused {
        id: entry.job.id,
        project: entry.job.project.clone(),
        category: "plan_timeout".into(),
        at: lapsed,
    });
    gate.release(Occupant::Job(entry.job.id));
    true
}

/// Time out an `Approved` job nobody claimed within `max_plan_age` of its
/// plan, dated to when it lapsed, with no strike. Returns whether it did.
fn lapse_approved(entry: &mut Entry, events: &mut Vec<JobEvent>, now: SystemTime) -> bool {
    if !matches!(entry.job.state, JobState::Approved { .. }) {
        return false;
    }
    let lapsed = entry.plan_at.unwrap_or(entry.job.created) + entry.max_plan_age;
    if lapsed > now {
        return false;
    }
    entry.job.state = JobState::Done(JobResult::TimedOut);
    events.push(JobEvent::TimedOut {
        id: entry.job.id,
        project: entry.job.project.clone(),
        at: lapsed,
    });
    true
}

/// Time out a `Waiting` job whose approval window has closed, dated to when
/// it lapsed, with a strike as of that moment. Returns whether it did.
fn lapse_waiting(
    entry: &mut Entry,
    events: &mut Vec<JobEvent>,
    gate: &mut Gate,
    policy: &Policy,
    now: SystemTime,
) -> bool {
    let JobState::Waiting { since, .. } = &entry.job.state else {
        return false;
    };
    let lapsed = *since + entry.approval_ttl;
    if lapsed > now {
        return false;
    }
    entry.job.state = JobState::Done(JobResult::TimedOut);
    events.push(JobEvent::TimedOut {
        id: entry.job.id,
        project: entry.job.project.clone(),
        at: lapsed,
    });
    gate.release(Occupant::Job(entry.job.id));
    gate.strike_at(lapsed, policy);
    true
}

/// End a job as `Refused` without striking: the agent did not cause it.
fn refuse_unstruck(entry: &mut Entry, events: &mut Vec<JobEvent>, now: SystemTime, category: &str) {
    entry.job.state = JobState::Done(JobResult::Refused(Failure {
        category: category.into(),
        addresses: Vec::new(),
        detail: None,
    }));
    events.push(JobEvent::Refused {
        id: entry.job.id,
        project: entry.job.project.clone(),
        category: category.into(),
        at: now,
    });
}

/// [`refuse_unstruck`] for a job that still holds the slot.
fn refuse_waiting(
    entry: &mut Entry,
    events: &mut Vec<JobEvent>,
    gate: &mut Gate,
    now: SystemTime,
    category: &str,
) {
    refuse_unstruck(entry, events, now, category);
    gate.release(Occupant::Job(entry.job.id));
}

/// Every job this instance has seen, and the rules for moving them along.
#[derive(Debug)]
pub struct Jobs {
    /// Project to the name of the runner that serves it.
    projects: BTreeMap<String, String>,
    /// The currently trusted candidate digest, per project.
    trusted: BTreeMap<String, Option<String>>,
    entries: Vec<Entry>,
    events: Vec<JobEvent>,
    /// The latest `now` any method has seen; every method clamps up to it,
    /// as [`crate::grant::Grants`] does, so a clock that steps backward
    /// cannot resurrect an expired job.
    high_water: SystemTime,
}

impl Jobs {
    pub fn new(projects: BTreeMap<String, String>) -> Jobs {
        Jobs {
            projects,
            trusted: BTreeMap::new(),
            entries: Vec::new(),
            events: Vec::new(),
            high_water: UNIX_EPOCH,
        }
    }

    /// Record which candidate is trusted for `project` now. A trust scope
    /// whose baseline differs is refused at approval as stale.
    pub fn set_trusted(&mut self, project: &str, digest: Option<String>) {
        self.trusted.insert(project.to_owned(), digest);
    }

    /// Drain the ledger entries recorded since the last call.
    pub fn take_events(&mut self) -> Vec<JobEvent> {
        std::mem::take(&mut self.events)
    }

    fn clamp(&mut self, now: SystemTime) -> SystemTime {
        let now = now.max(self.high_water);
        self.high_water = now;
        now
    }

    fn index(&self, id: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.job.id == id)
    }

    fn runner_of(&self, project: &str) -> Option<&str> {
        self.projects.get(project).map(String::as_str)
    }

    /// File a job. Refuses an unknown project, an empty reason, and, in this
    /// order, a job already active, then the gate's busy, cooldown and cap.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        now: SystemTime,
        gate: &mut Gate,
        policy: &Policy,
        entropy: &mut dyn Entropy,
        id: u64,
        project: &str,
        kind: JobKind,
        reason: &str,
    ) -> Result<Job, Refusal> {
        let now = self.clamp(now);
        if !self.projects.contains_key(project) {
            return Err(Refusal::UnknownProject);
        }
        let reason = printable(reason.trim(), 200);
        if reason.is_empty() {
            return Err(Refusal::NoReason);
        }
        if self
            .entries
            .iter()
            .any(|e| !matches!(e.job.state, JobState::Done(_)))
        {
            return Err(Refusal::Busy);
        }
        gate.tick(now);
        gate.admit(now, policy, Occupant::Job(id))?;
        let job = Job {
            id,
            project: project.to_owned(),
            kind,
            state: JobState::Queued,
            reason,
            created: now,
            match_code: match_code(entropy),
        };
        self.events.push(JobEvent::Requested {
            id,
            project: job.project.clone(),
            kind: job.kind.name(),
            reason: job.reason.clone(),
            at: now,
        });
        self.entries.push(Entry {
            job: job.clone(),
            plan_at: None,
            plan_timeout: policy.plan_timeout,
            approval_ttl: policy.approval_ttl,
            max_plan_age: policy.max_plan_age,
        });
        Ok(job)
    }

    /// The runner asks for work, on any project it serves. A `Queued` job
    /// moves to `Working`; an `Approved` one is returned as it is, until
    /// claimed. A job past its limit is expired here instead of handed out.
    pub fn poll(&mut self, now: SystemTime, gate: &mut Gate, runner: &str) -> Option<Job> {
        let now = self.clamp(now);
        for i in 0..self.entries.len() {
            let entry = &mut self.entries[i];
            if self.projects.get(&entry.job.project).map(String::as_str) != Some(runner) {
                continue;
            }
            if lapse_planning(entry, &mut self.events, gate, now)
                || lapse_approved(entry, &mut self.events, now)
            {
                continue;
            }
            match &entry.job.state {
                JobState::Queued => {
                    entry.job.state = JobState::Working {
                        runner: runner.to_owned(),
                    };
                    self.events.push(JobEvent::Started {
                        id: entry.job.id,
                        project: entry.job.project.clone(),
                        kind: entry.job.kind.name(),
                        at: now,
                    });
                    return Some(entry.job.clone());
                }
                JobState::Approved { .. } => return Some(entry.job.clone()),
                JobState::Working { .. }
                | JobState::Waiting { .. }
                | JobState::Claimed
                | JobState::Done(_) => {}
            }
        }
        None
    }

    /// The runner hands in the scope it planned. Accepted once, from
    /// `Working`, from the assigned runner; the scope is frozen from then on
    /// and the job waits on the approver under a fresh nonce.
    pub fn submit(
        &mut self,
        now: SystemTime,
        gate: &mut Gate,
        runner: &str,
        id: u64,
        scope: JobScope,
        entropy: &mut dyn Entropy,
    ) -> Result<(), Refusal> {
        let now = self.clamp(now);
        let i = self.index(id).ok_or(Refusal::NoSuchRequest)?;
        let entry = &mut self.entries[i];
        if lapse_planning(entry, &mut self.events, gate, now) {
            return Err(Refusal::NoSuchRequest);
        }
        match &entry.job.state {
            JobState::Working { runner: assigned } if assigned == runner => {}
            JobState::Working { .. } => return Err(Refusal::WrongRunner),
            JobState::Waiting { .. } | JobState::Approved { .. } | JobState::Claimed => {
                return Err(Refusal::ScopeFrozen);
            }
            JobState::Queued | JobState::Done(_) => return Err(Refusal::NoSuchRequest),
        }
        if !scope.is_well_formed() {
            return Err(Refusal::MalformedScope);
        }
        if !scope.matches(&entry.job.kind) || scope.project() != entry.job.project {
            return Err(Refusal::ScopeMismatch);
        }
        entry.job.state = JobState::Waiting {
            scope,
            nonce: hex_nonce(entropy),
            since: now,
        };
        entry.plan_at = Some(now);
        self.events.push(JobEvent::Waiting {
            id,
            project: entry.job.project.clone(),
            kind: entry.job.kind.name(),
            at: now,
        });
        Ok(())
    }

    /// The runner ends planning without a scope: `Refused` or `PlanFailed`.
    /// No strike; the approver was never asked. Takes the gate because the
    /// job gives its slot back.
    pub fn refuse(
        &mut self,
        now: SystemTime,
        gate: &mut Gate,
        runner: &str,
        id: u64,
        result: JobResult,
    ) -> Result<(), Refusal> {
        let now = self.clamp(now);
        let category = match &result {
            JobResult::Refused(f) | JobResult::PlanFailed(f) => f.category.clone(),
            JobResult::Trusted
            | JobResult::Applied
            | JobResult::ApplyFailed(_)
            | JobResult::OutcomeUnknown
            | JobResult::Declined
            | JobResult::TimedOut
            | JobResult::Killed => return Err(Refusal::ScopeMismatch),
        };
        let i = self.index(id).ok_or(Refusal::NoSuchRequest)?;
        let entry = &mut self.entries[i];
        if lapse_planning(entry, &mut self.events, gate, now) {
            return Err(Refusal::NoSuchRequest);
        }
        match &entry.job.state {
            JobState::Working { runner: assigned } if assigned == runner => {}
            JobState::Working { .. } => return Err(Refusal::WrongRunner),
            JobState::Queued
            | JobState::Waiting { .. }
            | JobState::Approved { .. }
            | JobState::Claimed
            | JobState::Done(_) => return Err(Refusal::NoSuchRequest),
        }
        entry.job.state = JobState::Done(result);
        self.events.push(JobEvent::Refused {
            id,
            project: entry.job.project.clone(),
            category,
            at: now,
        });
        gate.release(Occupant::Job(id));
        Ok(())
    }

    /// The approver signs. The nonce is compared in constant time and the
    /// scope by equality against the one frozen at submit. A trust scope
    /// must name the baseline currently trusted; an apply plan must be no
    /// older than the policy's `max_plan_age`. On success the job is
    /// `Approved`, the strikes are forgotten and the slot is free.
    ///
    /// Any refusal leaves the job `Waiting`; it will time out by itself.
    pub fn approve(
        &mut self,
        now: SystemTime,
        gate: &mut Gate,
        policy: &Policy,
        id: u64,
        nonce: &str,
        scope: &JobScope,
    ) -> Result<(), Refusal> {
        let now = self.clamp(now);
        let i = self.index(id).ok_or(Refusal::NoSuchRequest)?;
        if lapse_waiting(&mut self.entries[i], &mut self.events, gate, policy, now) {
            return Err(Refusal::NoSuchRequest);
        }
        let entry = &self.entries[i];
        let JobState::Waiting {
            scope: frozen,
            nonce: expected,
            since,
        } = &entry.job.state
        else {
            return Err(Refusal::NoSuchRequest);
        };
        if !constant_time_eq(nonce.as_bytes(), expected.as_bytes()) {
            return Err(Refusal::NonceMismatch);
        }
        if !scope.matches(&entry.job.kind) || scope != frozen {
            return Err(Refusal::ScopeMismatch);
        }
        match scope {
            JobScope::Apply(_) => {
                if *since + entry.max_plan_age <= now {
                    let entry = &mut self.entries[i];
                    refuse_waiting(entry, &mut self.events, gate, now, "plan_too_old");
                    return Err(Refusal::PlanTooOld);
                }
            }
            JobScope::Trust(t) => {
                let current = self.trusted.get(&t.project).cloned().flatten();
                if t.baseline != current {
                    let entry = &mut self.entries[i];
                    refuse_waiting(entry, &mut self.events, gate, now, "stale_baseline");
                    return Err(Refusal::StaleBaseline);
                }
            }
        }
        let frozen = frozen.clone();
        let entry = &mut self.entries[i];
        entry.job.state = JobState::Approved { scope: frozen };
        self.events.push(JobEvent::Approved {
            id,
            project: entry.job.project.clone(),
            at: now,
        });
        gate.approved();
        gate.release(Occupant::Job(id));
        Ok(())
    }

    /// The approver says no. Costs a cooldown.
    pub fn decline(
        &mut self,
        now: SystemTime,
        gate: &mut Gate,
        policy: &Policy,
        id: u64,
    ) -> Result<(), Refusal> {
        let now = self.clamp(now);
        let i = self.index(id).ok_or(Refusal::NoSuchRequest)?;
        let entry = &mut self.entries[i];
        if !matches!(entry.job.state, JobState::Waiting { .. }) {
            return Err(Refusal::NoSuchRequest);
        }
        entry.job.state = JobState::Done(JobResult::Declined);
        self.events.push(JobEvent::Declined {
            id,
            project: entry.job.project.clone(),
            at: now,
        });
        gate.release(Occupant::Job(id));
        gate.strike_at(now, policy);
        Ok(())
    }

    /// The runner takes the approval, once, and gets the scope that was
    /// signed.
    pub fn claim(&mut self, now: SystemTime, runner: &str, id: u64) -> Result<JobScope, Refusal> {
        let now = self.clamp(now);
        let i = self.index(id).ok_or(Refusal::NoSuchRequest)?;
        let assigned = self.runner_of(&self.entries[i].job.project);
        if assigned != Some(runner) {
            return Err(Refusal::WrongRunner);
        }
        let entry = &mut self.entries[i];
        if lapse_approved(entry, &mut self.events, now) {
            return Err(Refusal::PlanTooOld);
        }
        match &entry.job.state {
            JobState::Approved { scope } => {
                let scope = scope.clone();
                if let JobScope::Trust(t) = &scope {
                    let current = self.trusted.get(&t.project).cloned().flatten();
                    if t.baseline != current {
                        refuse_unstruck(entry, &mut self.events, now, "stale_baseline");
                        return Err(Refusal::StaleBaseline);
                    }
                }
                entry.job.state = JobState::Claimed;
                Ok(scope)
            }
            JobState::Claimed => Err(Refusal::AlreadyClaimed),
            JobState::Queued
            | JobState::Working { .. }
            | JobState::Waiting { .. }
            | JobState::Done(_) => Err(Refusal::NoSuchRequest),
        }
    }

    /// The runner reports how a claimed job ended. A result for an id this
    /// instance does not know (the daemon restarted mid-apply) is accepted
    /// only as `OutcomeUnknown`, and recorded as a bare event for `project`, which the runner
    /// must serve.
    pub fn finish(
        &mut self,
        now: SystemTime,
        runner: &str,
        project: &str,
        id: u64,
        result: JobResult,
    ) -> Result<(), Refusal> {
        let now = self.clamp(now);
        let Some(i) = self.index(id) else {
            if result != JobResult::OutcomeUnknown {
                return Err(Refusal::NoSuchRequest);
            }
            if self.runner_of(project) != Some(runner) {
                return Err(Refusal::WrongRunner);
            }
            let project = project.to_owned();
            self.events.push(JobEvent::OutcomeUnknown {
                id,
                project,
                at: now,
            });
            return Ok(());
        };
        if self.entries[i].job.project != project
            || self.runner_of(&self.entries[i].job.project) != Some(runner)
        {
            return Err(Refusal::WrongRunner);
        }
        let entry = &mut self.entries[i];
        if entry.job.state != JobState::Claimed {
            return Err(Refusal::NoSuchRequest);
        }
        let project = entry.job.project.clone();
        let is_trust = matches!(entry.job.kind, JobKind::Trust { .. });
        let event = match (&result, is_trust) {
            (JobResult::Trusted, true) => JobEvent::Trusted {
                id,
                project,
                at: now,
            },
            (JobResult::Applied, false) => JobEvent::Applied {
                id,
                project,
                at: now,
            },
            (JobResult::ApplyFailed(_), _) => JobEvent::ApplyFailed {
                id,
                project,
                at: now,
            },
            (JobResult::OutcomeUnknown, _) => JobEvent::OutcomeUnknown {
                id,
                project,
                at: now,
            },
            (JobResult::Trusted, false)
            | (JobResult::Applied, true)
            | (JobResult::Refused(_), _)
            | (JobResult::PlanFailed(_), _)
            | (JobResult::Declined, _)
            | (JobResult::TimedOut, _)
            | (JobResult::Killed, _) => return Err(Refusal::ScopeMismatch),
        };
        entry.job.state = JobState::Done(result);
        self.events.push(event);
        Ok(())
    }

    /// The kill switch for one project. A job still waiting on a person is
    /// declined with the usual cooldown, so a tap a moment later cannot
    /// reopen it. An approval not yet claimed is voided. A claimed job is
    /// already running and is left to finish.
    pub fn kill(
        &mut self,
        now: SystemTime,
        gate: &mut Gate,
        policy: &Policy,
        project: &str,
    ) -> Result<(), Refusal> {
        let now = self.clamp(now);
        if !self.projects.contains_key(project) {
            return Err(Refusal::UnknownProject);
        }
        for entry in self.entries.iter_mut().filter(|e| e.job.project == project) {
            let id = entry.job.id;
            match &entry.job.state {
                JobState::Queued | JobState::Working { .. } => gate.release(Occupant::Job(id)),
                JobState::Waiting { .. } => {
                    gate.release(Occupant::Job(id));
                    gate.strike_at(now, policy);
                }
                JobState::Approved { .. } => {}
                JobState::Claimed | JobState::Done(_) => continue,
            }
            entry.job.state = JobState::Done(JobResult::Killed);
            self.events.push(JobEvent::Killed {
                id,
                project: entry.job.project.clone(),
                at: now,
            });
        }
        Ok(())
    }

    /// Advance time. Each timeout is dated to when it actually lapsed, not
    /// to `now`, so a cooldown counts from the moment the person's chance to
    /// answer closed.
    ///
    /// - `Queued` or `Working` past `plan_timeout` from creation fails as
    ///   `plan_timeout`, with no strike: nobody was asked.
    /// - `Waiting` past the approval window times out, with a strike.
    /// - `Approved` and unclaimed past `max_plan_age` from the plan times
    ///   out, with no strike: the approver did answer.
    pub fn tick(&mut self, now: SystemTime, gate: &mut Gate, policy: &Policy) {
        let now = self.clamp(now);
        for entry in &mut self.entries {
            if lapse_planning(entry, &mut self.events, gate, now)
                || lapse_approved(entry, &mut self.events, now)
            {
                continue;
            }
            lapse_waiting(entry, &mut self.events, gate, policy, now);
        }
    }

    pub fn job(&mut self, now: SystemTime, id: u64) -> Option<&Job> {
        self.clamp(now);
        self.entries.iter().find(|e| e.job.id == id).map(|e| &e.job)
    }

    /// The job awaiting the approver's verdict, if any.
    pub fn waiting(&mut self, now: SystemTime) -> Option<&Job> {
        self.clamp(now);
        self.entries
            .iter()
            .find(|e| matches!(e.job.state, JobState::Waiting { .. }))
            .map(|e| &e.job)
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::scope::{BaselineStatus, Counts};

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

    fn jobs() -> Jobs {
        let mut projects = BTreeMap::new();
        projects.insert("web".to_owned(), "runner-a".to_owned());
        projects.insert("db".to_owned(), "runner-b".to_owned());
        Jobs::new(projects)
    }

    fn trust_kind() -> JobKind {
        JobKind::Trust {
            archive_sha256: "a".repeat(64),
        }
    }

    fn apply_kind() -> JobKind {
        JobKind::Apply {
            manifest: "{}".into(),
            allow_destroy: false,
        }
    }

    fn trust_scope() -> JobScope {
        JobScope::Trust(TrustScope {
            project: "web".into(),
            baseline: None,
            candidate: "a".repeat(64),
            diff: "b".repeat(64),
            schema: "c".repeat(64),
            policy_version: 1,
            files_changed: 1,
            lines_added: 1,
            lines_removed: 0,
            schema_changed: false,
        })
    }

    fn apply_scope() -> JobScope {
        JobScope::Apply(ApplyScope {
            project: "web".into(),
            revision: "a".repeat(64),
            schema: "b".repeat(64),
            manifest: "c".repeat(64),
            baseline_manifest: None,
            baseline_status: BaselineStatus::None,
            plan: "d".repeat(64),
            destructive: false,
            counts: Counts {
                create: 1,
                update: 0,
                replace: 0,
                delete: 0,
            },
            addresses: "e".repeat(64),
        })
    }

    struct Rig {
        jobs: Jobs,
        gate: Gate,
        policy: Policy,
        entropy: Counter,
    }

    impl Rig {
        fn new() -> Rig {
            Rig {
                jobs: jobs(),
                gate: Gate::new(),
                policy: Policy::default(),
                entropy: Counter(0),
            }
        }

        fn request(&mut self, now: SystemTime, id: u64, kind: JobKind) -> Result<Job, Refusal> {
            self.jobs.request(
                now,
                &mut self.gate,
                &self.policy,
                &mut self.entropy,
                id,
                "web",
                kind,
                "change the thing",
            )
        }

        fn submit(&mut self, now: SystemTime, id: u64, scope: JobScope) -> Result<(), Refusal> {
            self.jobs.submit(
                now,
                &mut self.gate,
                "runner-a",
                id,
                scope,
                &mut self.entropy,
            )
        }

        fn nonce(&mut self, id: u64) -> String {
            match &self.jobs.job(t(0), id).unwrap().state {
                JobState::Waiting { nonce, .. } => nonce.clone(),
                other => panic!("not waiting: {other:?}"),
            }
        }

        /// Request, poll and submit; leaves the job Waiting.
        fn waiting(&mut self, id: u64, kind: JobKind, scope: JobScope) -> String {
            self.request(t(0), id, kind).unwrap();
            self.jobs.poll(t(1), &mut self.gate, "runner-a").unwrap();
            self.submit(t(2), id, scope).unwrap();
            self.nonce(id)
        }

        fn approve(
            &mut self,
            now: SystemTime,
            id: u64,
            nonce: &str,
            s: &JobScope,
        ) -> Result<(), Refusal> {
            self.jobs
                .approve(now, &mut self.gate, &self.policy, id, nonce, s)
        }

        fn tick(&mut self, now: SystemTime) {
            self.jobs.tick(now, &mut self.gate, &self.policy);
        }

        fn state(&mut self, id: u64) -> JobState {
            self.jobs.job(t(0), id).unwrap().state.clone()
        }
    }

    #[test]
    fn request_occupies_the_gate() {
        let mut r = Rig::new();
        let job = r.request(t(0), 7, trust_kind()).unwrap();
        assert_eq!(job.state, JobState::Queued);
        assert_eq!(job.id, 7);
        assert_eq!(job.match_code.len(), 9);
        assert_eq!(r.gate.busy(), Some(Occupant::Job(7)));
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Requested {
                id: 7,
                project: "web".into(),
                kind: "trust",
                reason: "change the thing".into(),
                at: t(0),
            }]
        );
        assert_eq!(r.request(t(1), 8, trust_kind()), Err(Refusal::Busy));
    }

    #[test]
    fn unknown_project_is_refused() {
        let mut r = Rig::new();
        let res = r.jobs.request(
            t(0),
            &mut r.gate,
            &r.policy,
            &mut r.entropy,
            1,
            "nope",
            trust_kind(),
            "why",
        );
        assert_eq!(res, Err(Refusal::UnknownProject));
        assert_eq!(r.gate.busy(), None);
        assert!(r.jobs.take_events().is_empty());
        let res = r.jobs.request(
            t(0),
            &mut r.gate,
            &r.policy,
            &mut r.entropy,
            1,
            "web",
            trust_kind(),
            "  ",
        );
        assert_eq!(res, Err(Refusal::NoReason));
    }

    #[test]
    fn poll_assigns_only_to_the_projects_runner() {
        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        r.jobs.take_events();
        assert!(r.jobs.poll(t(1), &mut r.gate, "runner-b").is_none());
        assert!(r.jobs.poll(t(1), &mut r.gate, "stranger").is_none());
        assert_eq!(r.state(1), JobState::Queued);
        let job = r.jobs.poll(t(2), &mut r.gate, "runner-a").unwrap();
        assert_eq!(
            job.state,
            JobState::Working {
                runner: "runner-a".into()
            }
        );
        assert!(
            r.jobs.poll(t(3), &mut r.gate, "runner-a").is_none(),
            "taken once"
        );
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Started {
                id: 1,
                project: "web".into(),
                kind: "trust",
                at: t(2),
            }]
        );
        assert_eq!(
            r.jobs.submit(
                t(3),
                &mut r.gate,
                "runner-b",
                1,
                trust_scope(),
                &mut r.entropy
            ),
            Err(Refusal::WrongRunner)
        );
    }

    #[test]
    fn submit_moves_to_waiting_with_fresh_nonce() {
        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        assert_eq!(
            r.submit(t(1), 1, trust_scope()),
            Err(Refusal::NoSuchRequest),
            "not yet polled"
        );
        r.jobs.poll(t(1), &mut r.gate, "runner-a").unwrap();
        r.jobs.take_events();
        r.submit(t(2), 1, trust_scope()).unwrap();
        let nonce = r.nonce(1);
        assert_eq!(nonce.len(), 64);
        match r.state(1) {
            JobState::Waiting { scope, since, .. } => {
                assert_eq!(scope, trust_scope());
                assert_eq!(since, t(2));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(r.gate.busy(), Some(Occupant::Job(1)));
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Waiting {
                id: 1,
                project: "web".into(),
                kind: "trust",
                at: t(2),
            }]
        );
        assert_eq!(r.jobs.waiting(t(3)).map(|j| j.id), Some(1));
    }

    #[test]
    fn malformed_or_mismatched_scope_is_refused_at_submit() {
        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        r.jobs.poll(t(1), &mut r.gate, "runner-a").unwrap();
        let JobScope::Trust(mut bad) = trust_scope() else {
            unreachable!()
        };
        bad.project = "web\nbaseline=none".into();
        assert_eq!(
            r.submit(t(2), 1, JobScope::Trust(bad)),
            Err(Refusal::MalformedScope)
        );
        assert_eq!(
            r.submit(t(2), 1, apply_scope()),
            Err(Refusal::ScopeMismatch)
        );
    }

    #[test]
    fn second_submit_is_scope_frozen() {
        let mut r = Rig::new();
        r.waiting(1, trust_kind(), trust_scope());
        let before = r.state(1);
        let JobScope::Trust(mut other) = trust_scope() else {
            unreachable!()
        };
        other.diff = "f".repeat(64);
        assert_eq!(
            r.submit(t(3), 1, JobScope::Trust(other)),
            Err(Refusal::ScopeFrozen)
        );
        assert_eq!(r.state(1), before);
    }

    #[test]
    fn approve_with_wrong_nonce_is_refused() {
        let mut r = Rig::new();
        r.waiting(1, trust_kind(), trust_scope());
        r.jobs.take_events();
        let bad = "0".repeat(64);
        assert_eq!(
            r.approve(t(3), 1, &bad, &trust_scope()),
            Err(Refusal::NonceMismatch)
        );
        assert!(matches!(r.state(1), JobState::Waiting { .. }));
        assert_eq!(r.gate.busy(), Some(Occupant::Job(1)));
        assert!(r.jobs.take_events().is_empty());
    }

    #[test]
    fn approve_with_changed_scope_is_refused() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        let JobScope::Trust(mut other) = trust_scope() else {
            unreachable!()
        };
        other.lines_added = 99;
        assert_eq!(
            r.approve(t(3), 1, &nonce, &JobScope::Trust(other)),
            Err(Refusal::ScopeMismatch)
        );
        assert_eq!(
            r.approve(t(3), 1, &nonce, &apply_scope()),
            Err(Refusal::ScopeMismatch),
            "wrong kind"
        );
        assert!(matches!(r.state(1), JobState::Waiting { .. }));
    }

    #[test]
    fn approve_twice_is_refused() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        r.jobs.take_events();
        r.approve(t(3), 1, &nonce, &trust_scope()).unwrap();
        assert_eq!(
            r.state(1),
            JobState::Approved {
                scope: trust_scope()
            }
        );
        assert_eq!(r.gate.busy(), None, "approved jobs free the slot");
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Approved {
                id: 1,
                project: "web".into(),
                at: t(3),
            }]
        );
        assert_eq!(
            r.approve(t(4), 1, &nonce, &trust_scope()),
            Err(Refusal::NoSuchRequest)
        );
        assert!(r.jobs.take_events().is_empty());
    }

    #[test]
    fn claim_is_single_use() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        r.approve(t(3), 1, &nonce, &trust_scope()).unwrap();
        assert_eq!(r.jobs.claim(t(4), "runner-b", 1), Err(Refusal::WrongRunner));
        let again = r.jobs.poll(t(4), &mut r.gate, "runner-a").unwrap();
        assert!(matches!(again.state, JobState::Approved { .. }));
        assert_eq!(r.jobs.claim(t(5), "runner-a", 1), Ok(trust_scope()));
        assert_eq!(r.state(1), JobState::Claimed);
        assert_eq!(
            r.jobs.claim(t(6), "runner-a", 1),
            Err(Refusal::AlreadyClaimed)
        );
        assert!(r.jobs.poll(t(7), &mut r.gate, "runner-a").is_none());
    }

    #[test]
    fn kill_voids_unclaimed_approval() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        r.approve(t(3), 1, &nonce, &trust_scope()).unwrap();
        r.jobs.take_events();
        r.jobs.kill(t(4), &mut r.gate, &r.policy, "web").unwrap();
        assert_eq!(r.state(1), JobState::Done(JobResult::Killed));
        assert_eq!(
            r.jobs.claim(t(5), "runner-a", 1),
            Err(Refusal::NoSuchRequest)
        );
        assert_eq!(r.gate.strikes, 0, "the verdict was already given");
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Killed {
                id: 1,
                project: "web".into(),
                at: t(4),
            }]
        );
        assert_eq!(
            r.jobs.kill(t(4), &mut r.gate, &r.policy, "nope"),
            Err(Refusal::UnknownProject)
        );
    }

    #[test]
    fn kill_while_waiting_strikes_and_frees_the_slot() {
        let mut r = Rig::new();
        r.waiting(1, trust_kind(), trust_scope());
        r.jobs.kill(t(4), &mut r.gate, &r.policy, "web").unwrap();
        assert_eq!(r.state(1), JobState::Done(JobResult::Killed));
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 1);
        assert_eq!(r.gate.cooldown_until, Some(t(4) + 5 * MIN));
    }

    #[test]
    fn kill_leaves_claimed_job_running() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, apply_kind(), apply_scope());
        r.approve(t(3), 1, &nonce, &apply_scope()).unwrap();
        r.jobs.claim(t(4), "runner-a", 1).unwrap();
        r.jobs.take_events();
        r.jobs.kill(t(5), &mut r.gate, &r.policy, "web").unwrap();
        assert_eq!(r.state(1), JobState::Claimed);
        assert!(r.jobs.take_events().is_empty());
        assert_eq!(r.request(t(6), 2, trust_kind()), Err(Refusal::Busy));
        r.jobs
            .finish(t(7), "runner-a", "web", 1, JobResult::Applied)
            .unwrap();
        assert_eq!(r.state(1), JobState::Done(JobResult::Applied));
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Applied {
                id: 1,
                project: "web".into(),
                at: t(7),
            }]
        );
        assert!(r.request(t(8), 2, trust_kind()).is_ok());
    }

    #[test]
    fn late_submit_after_kill_is_refused() {
        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        r.jobs.poll(t(1), &mut r.gate, "runner-a").unwrap();
        r.jobs.kill(t(2), &mut r.gate, &r.policy, "web").unwrap();
        assert_eq!(r.gate.strikes, 0, "nobody was asked yet");
        assert_eq!(r.gate.busy(), None);
        assert_eq!(
            r.submit(t(3), 1, trust_scope()),
            Err(Refusal::NoSuchRequest)
        );
        assert_eq!(
            r.jobs.refuse(
                t(3),
                &mut r.gate,
                "runner-a",
                1,
                JobResult::Refused(failure("x"))
            ),
            Err(Refusal::NoSuchRequest)
        );
        assert_eq!(r.state(1), JobState::Done(JobResult::Killed));
    }

    fn failure(category: &str) -> Failure {
        Failure {
            category: category.into(),
            addresses: vec![],
            detail: None,
        }
    }

    #[test]
    fn refuse_ends_the_job_without_strike() {
        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        r.jobs.poll(t(1), &mut r.gate, "runner-a").unwrap();
        r.jobs.take_events();
        r.jobs
            .refuse(
                t(2),
                &mut r.gate,
                "runner-a",
                1,
                JobResult::PlanFailed(failure("tf_error")),
            )
            .unwrap();
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 0);
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Refused {
                id: 1,
                project: "web".into(),
                category: "tf_error".into(),
                at: t(2),
            }]
        );
    }

    #[test]
    fn planning_timeout_is_plan_failed_without_strike() {
        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        r.jobs.poll(t(1), &mut r.gate, "runner-a").unwrap();
        r.jobs.take_events();
        r.tick(t(9 * 60));
        assert!(matches!(r.state(1), JobState::Working { .. }));
        r.tick(t(11 * 60));
        assert_eq!(
            r.state(1),
            JobState::Done(JobResult::PlanFailed(failure("plan_timeout")))
        );
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 0);
        assert_eq!(r.gate.cooldown_until, None);
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Refused {
                id: 1,
                project: "web".into(),
                category: "plan_timeout".into(),
                at: t(10 * 60),
            }]
        );
        assert_eq!(
            r.submit(t(11 * 60), 1, trust_scope()),
            Err(Refusal::NoSuchRequest)
        );
    }

    #[test]
    fn approval_timeout_strikes() {
        let mut r = Rig::new();
        r.waiting(1, trust_kind(), trust_scope());
        r.jobs.take_events();
        r.tick(t(2) + 4 * MIN);
        assert!(matches!(r.state(1), JobState::Waiting { .. }));
        r.tick(t(2) + 6 * MIN);
        assert_eq!(r.state(1), JobState::Done(JobResult::TimedOut));
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 1);
        assert_eq!(r.gate.cooldown_until, Some(t(2) + 10 * MIN));
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::TimedOut {
                id: 1,
                project: "web".into(),
                at: t(2) + 5 * MIN,
            }]
        );
    }

    #[test]
    fn decline_strikes_and_frees_the_slot() {
        let mut r = Rig::new();
        r.waiting(1, trust_kind(), trust_scope());
        r.jobs.take_events();
        r.jobs.decline(t(3), &mut r.gate, &r.policy, 1).unwrap();
        assert_eq!(r.state(1), JobState::Done(JobResult::Declined));
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 1);
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Declined {
                id: 1,
                project: "web".into(),
                at: t(3),
            }]
        );
        assert_eq!(
            r.jobs.decline(t(4), &mut r.gate, &r.policy, 1),
            Err(Refusal::NoSuchRequest)
        );
    }

    #[test]
    fn approved_but_unclaimed_expires_at_max_plan_age() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, apply_kind(), apply_scope());
        r.approve(t(3), 1, &nonce, &apply_scope()).unwrap();
        r.jobs.take_events();
        r.tick(t(2) + 14 * MIN);
        assert!(matches!(r.state(1), JobState::Approved { .. }));
        r.tick(t(2) + 16 * MIN);
        assert_eq!(r.state(1), JobState::Done(JobResult::TimedOut));
        assert_eq!(r.gate.strikes, 0);
        assert_eq!(
            r.jobs.claim(t(2) + 17 * MIN, "runner-a", 1),
            Err(Refusal::NoSuchRequest)
        );
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::TimedOut {
                id: 1,
                project: "web".into(),
                at: t(2) + 15 * MIN,
            }]
        );
    }

    #[test]
    fn apply_plan_older_than_max_age_cannot_be_approved() {
        let mut r = Rig::new();
        r.policy.approval_ttl = 30 * MIN;
        let nonce = r.waiting(1, apply_kind(), apply_scope());
        assert_eq!(
            r.approve(t(2) + 16 * MIN, 1, &nonce, &apply_scope()),
            Err(Refusal::PlanTooOld)
        );
        assert_eq!(
            r.state(1),
            JobState::Done(JobResult::Refused(failure("plan_too_old")))
        );
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 0);
        let mut r = Rig::new();
        r.policy.approval_ttl = 30 * MIN;
        let nonce = r.waiting(1, apply_kind(), apply_scope());
        assert!(
            r.approve(t(2) + 14 * MIN, 1, &nonce, &apply_scope())
                .is_ok()
        );
    }

    #[test]
    fn approve_after_the_approval_window_is_refused() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        assert_eq!(
            r.approve(t(2) + 6 * MIN, 1, &nonce, &trust_scope()),
            Err(Refusal::NoSuchRequest)
        );
    }

    #[test]
    fn finish_unknown_id_with_outcome_unknown_is_recorded() {
        let mut r = Rig::new();
        r.jobs
            .finish(t(1), "runner-a", "web", 99, JobResult::OutcomeUnknown)
            .unwrap();
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::OutcomeUnknown {
                id: 99,
                project: "web".into(),
                at: t(1),
            }]
        );
        assert!(r.jobs.job(t(1), 99).is_none());
        assert_eq!(
            r.jobs
                .finish(t(2), "runner-a", "web", 99, JobResult::Applied),
            Err(Refusal::NoSuchRequest)
        );
        assert_eq!(
            r.jobs
                .finish(t(2), "stranger", "web", 99, JobResult::OutcomeUnknown),
            Err(Refusal::WrongRunner)
        );
    }

    #[test]
    fn ssh_request_blocks_job_request() {
        let mut r = Rig::new();
        r.gate.admit(t(0), &r.policy, Occupant::Ssh(5)).unwrap();
        assert_eq!(r.request(t(1), 6, trust_kind()), Err(Refusal::Busy));
        assert!(r.jobs.take_events().is_empty());
    }

    #[test]
    fn ssh_request_is_allowed_while_an_apply_runs() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, apply_kind(), apply_scope());
        r.approve(t(3), 1, &nonce, &apply_scope()).unwrap();
        r.jobs.claim(t(4), "runner-a", 1).unwrap();
        assert!(r.gate.admit(t(5), &r.policy, Occupant::Ssh(5)).is_ok());
    }

    #[test]
    fn trust_with_stale_baseline_is_refused() {
        let mut r = Rig::new();
        r.jobs.set_trusted("web", Some("9".repeat(64)));
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        r.jobs.take_events();
        assert_eq!(
            r.approve(t(3), 1, &nonce, &trust_scope()),
            Err(Refusal::StaleBaseline)
        );
        assert_eq!(
            r.state(1),
            JobState::Done(JobResult::Refused(failure("stale_baseline")))
        );
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 0);
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::Refused {
                id: 1,
                project: "web".into(),
                category: "stale_baseline".into(),
                at: t(3),
            }]
        );
        r.jobs.set_trusted("web", None);
        let nonce = r.waiting(2, trust_kind(), trust_scope());
        assert!(r.approve(t(3), 2, &nonce, &trust_scope()).is_ok());
    }

    #[test]
    fn trust_claim_after_baseline_change_is_refused() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        r.approve(t(3), 1, &nonce, &trust_scope()).unwrap();
        r.jobs.set_trusted("web", Some("9".repeat(64)));
        r.jobs.take_events();
        assert_eq!(
            r.jobs.claim(t(4), "runner-a", 1),
            Err(Refusal::StaleBaseline)
        );
        assert_eq!(
            r.state(1),
            JobState::Done(JobResult::Refused(failure("stale_baseline")))
        );
        assert_eq!(r.gate.strikes, 0);
        assert_eq!(
            r.jobs.claim(t(5), "runner-a", 1),
            Err(Refusal::NoSuchRequest)
        );
        assert_eq!(r.jobs.take_events().len(), 1);
    }

    #[test]
    fn claim_after_max_plan_age_without_tick_is_refused() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, apply_kind(), apply_scope());
        r.approve(t(3), 1, &nonce, &apply_scope()).unwrap();
        r.jobs.take_events();
        assert_eq!(
            r.jobs.claim(t(2) + 16 * MIN, "runner-a", 1),
            Err(Refusal::PlanTooOld)
        );
        assert_eq!(r.state(1), JobState::Done(JobResult::TimedOut));
        assert_eq!(r.gate.strikes, 0);
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::TimedOut {
                id: 1,
                project: "web".into(),
                at: t(2) + 15 * MIN,
            }]
        );
        let mut r = Rig::new();
        let nonce = r.waiting(1, apply_kind(), apply_scope());
        r.approve(t(3), 1, &nonce, &apply_scope()).unwrap();
        assert!(
            r.jobs
                .poll(t(2) + 16 * MIN, &mut r.gate, "runner-a")
                .is_none()
        );
        assert_eq!(r.state(1), JobState::Done(JobResult::TimedOut));
    }

    #[test]
    fn submit_after_plan_timeout_without_tick_is_refused() {
        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        r.jobs.poll(t(1), &mut r.gate, "runner-a").unwrap();
        r.jobs.take_events();
        assert_eq!(
            r.submit(t(11 * 60), 1, trust_scope()),
            Err(Refusal::NoSuchRequest)
        );
        assert_eq!(
            r.state(1),
            JobState::Done(JobResult::PlanFailed(failure("plan_timeout")))
        );
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 0);
        assert_eq!(r.jobs.take_events().len(), 1);

        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        assert!(r.jobs.poll(t(11 * 60), &mut r.gate, "runner-a").is_none());
        assert_eq!(r.gate.busy(), None);
        assert!(matches!(
            r.state(1),
            JobState::Done(JobResult::PlanFailed(_))
        ));
    }

    #[test]
    fn one_runner_serves_two_projects() {
        // "db" sorts first, so a lookup that takes only the runner's first
        // project would serve "db" jobs and miss "web" ones.
        let mut projects = BTreeMap::new();
        projects.insert("web".to_owned(), "shared".to_owned());
        projects.insert("db".to_owned(), "shared".to_owned());
        let mut r = Rig::new();
        r.jobs = Jobs::new(projects);
        for (now, id, project) in [(0, 1, "db"), (2, 2, "web")] {
            r.jobs
                .request(
                    t(now),
                    &mut r.gate,
                    &r.policy,
                    &mut r.entropy,
                    id,
                    project,
                    trust_kind(),
                    "why",
                )
                .unwrap();
            if id == 1 {
                r.jobs.kill(t(1), &mut r.gate, &r.policy, "db").unwrap();
            }
        }
        assert_eq!(
            r.jobs.poll(t(3), &mut r.gate, "shared").map(|j| j.id),
            Some(2)
        );
        r.jobs
            .finish(t(4), "shared", "web", 99, JobResult::OutcomeUnknown)
            .unwrap();
        r.jobs
            .finish(t(4), "shared", "db", 98, JobResult::OutcomeUnknown)
            .unwrap();
        assert_eq!(
            r.jobs
                .finish(t(4), "shared", "other", 97, JobResult::OutcomeUnknown),
            Err(Refusal::WrongRunner)
        );
    }

    #[test]
    fn finish_for_another_projects_job_is_wrong_runner() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, apply_kind(), apply_scope());
        r.approve(t(3), 1, &nonce, &apply_scope()).unwrap();
        r.jobs.claim(t(4), "runner-a", 1).unwrap();
        assert_eq!(
            r.jobs.finish(t(5), "runner-a", "db", 1, JobResult::Applied),
            Err(Refusal::WrongRunner)
        );
        assert_eq!(r.state(1), JobState::Claimed);
    }

    #[test]
    fn approve_past_the_window_expires_the_job_like_tick() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        r.jobs.take_events();
        assert_eq!(
            r.approve(t(2) + 7 * MIN, 1, &nonce, &trust_scope()),
            Err(Refusal::NoSuchRequest)
        );
        assert_eq!(r.state(1), JobState::Done(JobResult::TimedOut));
        assert_eq!(r.gate.busy(), None);
        assert_eq!(r.gate.strikes, 1);
        assert_eq!(r.gate.cooldown_until, Some(t(2) + 10 * MIN));
        assert_eq!(
            r.jobs.take_events(),
            vec![JobEvent::TimedOut {
                id: 1,
                project: "web".into(),
                at: t(2) + 5 * MIN,
            }]
        );
        r.tick(t(2) + 8 * MIN);
        assert!(r.jobs.take_events().is_empty(), "no second event");
        assert_eq!(r.gate.strikes, 1);
    }

    #[test]
    fn refuse_with_a_non_refusal_result_is_scope_mismatch() {
        let mut r = Rig::new();
        r.request(t(0), 1, trust_kind()).unwrap();
        r.jobs.poll(t(1), &mut r.gate, "runner-a").unwrap();
        assert_eq!(
            r.jobs
                .refuse(t(2), &mut r.gate, "runner-a", 1, JobResult::Applied),
            Err(Refusal::ScopeMismatch)
        );
    }

    #[test]
    fn clock_stepping_backward_does_not_revive_a_job() {
        let mut r = Rig::new();
        let nonce = r.waiting(1, trust_kind(), trust_scope());
        assert!(r.jobs.job(t(2) + 6 * MIN, 1).is_some());
        assert_eq!(
            r.approve(t(3), 1, &nonce, &trust_scope()),
            Err(Refusal::NoSuchRequest),
            "t(3) is clamped to the late high-water mark, past the window"
        );
    }
}
