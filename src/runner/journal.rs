// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The crash journal for a claimed job. The loop writes `claim` before it
//! asks the daemon for the approval, the executor writes `begin` before
//! Terraform starts and `end` after it returns, and the loop writes
//! `report` with the result before it sends `finish`, then `close` once the
//! daemon has it. Whatever a restart finds short of `done` is acted on at
//! startup: a claim or an apply with no result is reported as an unknown
//! outcome (a trust as `runner_restarted`), and a result not yet delivered
//! is sent again.

use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

use crate::job::Failure;
use crate::runner::state::{self, JournalFailure, Phase, ProjectPaths, write_atomic};

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

/// What the journal says is still open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unfinished {
    /// Claimed (or being claimed), nothing done yet. `kind` is `trust` or
    /// `apply`.
    Claimed { job: u64, kind: String },
    /// Terraform apply started and never returned.
    Applying { job: u64 },
    /// The result is known and the daemon may not have it.
    Reporting {
        job: u64,
        result: String,
        failure: Option<Failure>,
    },
}

/// One project's `journal.json`.
#[derive(Debug, Clone)]
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn new(paths: &ProjectPaths) -> Journal {
        Journal {
            path: paths.journal_json(),
        }
    }

    fn read(&self) -> io::Result<Option<state::Journal>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| invalid("journal.json is unreadable"))
    }

    /// The open entry, if any. An unreadable journal is an error, never a
    /// clean start: it may be hiding an unknown outcome.
    pub fn unfinished(&self) -> io::Result<Option<Unfinished>> {
        let Some(entry) = self.read()? else {
            return Ok(None);
        };
        let job = || -> io::Result<u64> {
            entry
                .job
                .parse()
                .map_err(|_| invalid("journal.json has a malformed job id"))
        };
        Ok(match entry.phase {
            Phase::Done => None,
            Phase::Applying => Some(Unfinished::Applying { job: job()? }),
            Phase::Claimed => Some(Unfinished::Claimed {
                job: job()?,
                kind: entry.kind.clone().unwrap_or_else(|| "apply".into()),
            }),
            Phase::Reporting => Some(Unfinished::Reporting {
                job: job()?,
                result: entry
                    .result
                    .clone()
                    .ok_or_else(|| invalid("journal.json has no result to report"))?,
                failure: entry.failure.clone().map(|f| Failure {
                    category: f.category,
                    addresses: f.addresses,
                    detail: f.detail,
                }),
            }),
        })
    }

    /// The job journaled `applying` with no `end`, if any.
    pub fn pending_unknown(&self) -> io::Result<Option<u64>> {
        Ok(match self.unfinished()? {
            Some(Unfinished::Applying { job }) => Some(job),
            _ => None,
        })
    }

    /// Refuses when another job's entry is still open, so one job's record
    /// can never hide another's.
    fn only(&self, job: u64) -> io::Result<()> {
        let other = match self.unfinished()? {
            None => return Ok(()),
            Some(Unfinished::Claimed { job: j, .. })
            | Some(Unfinished::Applying { job: j })
            | Some(Unfinished::Reporting { job: j, .. }) => j,
        };
        if other == job {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("job {other} is still open in the journal"),
            ))
        }
    }

    /// Records `job` (`kind` is `trust` or `apply`) as claimed. Call it
    /// before the claim is sent.
    pub fn claim(&self, job: u64, kind: &str) -> io::Result<()> {
        self.only(job)?;
        self.write(job, Phase::Claimed, None, Some(kind), None)
    }

    /// Records `job` as `applying`. Call it before Terraform starts.
    pub fn begin(&self, job: u64) -> io::Result<()> {
        self.only(job)?;
        self.write(job, Phase::Applying, None, Some("apply"), None)
    }

    /// Records that Terraform returned for `job`, with `result` (`applied`
    /// or a failure category).
    pub fn end(&self, job: u64, result: &str) -> io::Result<()> {
        self.only(job)?;
        self.write(job, Phase::Done, Some(result), Some("apply"), None)
    }

    /// Records the result to report for `job` (a finish result name) before
    /// it is sent.
    pub fn report(&self, job: u64, result: &str, failure: Option<&Failure>) -> io::Result<()> {
        self.only(job)?;
        let failure = failure.map(|f| JournalFailure {
            category: f.category.clone(),
            addresses: f.addresses.clone(),
            detail: f.detail.clone(),
        });
        self.write(job, Phase::Reporting, Some(result), None, failure)
    }

    /// Closes `job`'s entry: its result was delivered or permanently
    /// refused, or its claim never happened. Does nothing for another job.
    pub fn close(&self, job: u64) -> io::Result<()> {
        let Some(entry) = self.read()? else {
            return Ok(());
        };
        if entry.job != job.to_string() || entry.phase == Phase::Done {
            return Ok(());
        }
        self.write(
            job,
            Phase::Done,
            entry.result.as_deref(),
            entry.kind.as_deref(),
            None,
        )
    }

    fn write(
        &self,
        job: u64,
        phase: Phase,
        result: Option<&str>,
        kind: Option<&str>,
        failure: Option<JournalFailure>,
    ) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        let entry = state::Journal {
            job: job.to_string(),
            phase,
            result: result.map(str::to_string),
            kind: kind.map(str::to_string),
            failure,
        };
        let bytes = serde_json::to_vec(&entry).map_err(io::Error::other)?;
        write_atomic(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::state;

    fn read(j: &Journal) -> state::Journal {
        serde_json::from_slice(&std::fs::read(&j.path).unwrap()).unwrap()
    }

    #[test]
    fn journal_reports_started_job_as_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProjectPaths::new(dir.path(), "web").unwrap();
        let j = Journal::new(&paths);
        assert_eq!(j.pending_unknown().unwrap(), None, "no journal yet");

        j.begin(42).unwrap();
        assert_eq!(j.pending_unknown().unwrap(), Some(42));
        let entry = read(&j);
        assert_eq!(entry.job, "42");
        assert_eq!(entry.phase, state::Phase::Applying);
        assert_eq!(entry.result, None);
        // A restart reads the same file and sees the same unknown job.
        assert_eq!(Journal::new(&paths).pending_unknown().unwrap(), Some(42));

        j.end(42, "applied").unwrap();
        assert_eq!(j.pending_unknown().unwrap(), None);
        let entry = read(&j);
        assert_eq!(entry.phase, state::Phase::Done);
        assert_eq!(entry.result.as_deref(), Some("applied"));
    }

    #[test]
    fn journal_end_for_another_job_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(&ProjectPaths::new(dir.path(), "web").unwrap());
        j.begin(7).unwrap();
        assert!(j.end(8, "applied").is_err());
        assert!(j.claim(8, "apply").is_err());
        assert!(j.report(8, "applied", None).is_err());
        assert_eq!(j.pending_unknown().unwrap(), Some(7));
    }

    #[test]
    fn claim_report_close_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProjectPaths::new(dir.path(), "web").unwrap();
        let j = Journal::new(&paths);
        j.claim(3, "trust").unwrap();
        assert_eq!(
            j.unfinished().unwrap(),
            Some(Unfinished::Claimed {
                job: 3,
                kind: "trust".into()
            })
        );
        let f = Failure {
            category: "runner_restarted".into(),
            addresses: vec!["a.b".into()],
            detail: None,
        };
        j.report(3, "apply_failed", Some(&f)).unwrap();
        assert_eq!(
            Journal::new(&paths).unfinished().unwrap(),
            Some(Unfinished::Reporting {
                job: 3,
                result: "apply_failed".into(),
                failure: Some(f),
            })
        );
        j.close(4).unwrap();
        assert!(
            j.unfinished().unwrap().is_some(),
            "another job's close is a no-op"
        );
        j.close(3).unwrap();
        assert_eq!(j.unfinished().unwrap(), None);
        // A new job may now claim.
        j.claim(4, "apply").unwrap();
    }

    #[test]
    fn unreadable_journal_is_an_error_not_a_clean_start() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProjectPaths::new(dir.path(), "web").unwrap();
        let j = Journal::new(&paths);
        j.begin(1).unwrap();
        std::fs::write(paths.journal_json(), b"{\"job\":").unwrap();
        assert!(j.pending_unknown().is_err());
        assert!(j.unfinished().is_err());
        std::fs::write(
            paths.journal_json(),
            br#"{"job":"x","phase":"applying","result":null}"#,
        )
        .unwrap();
        assert!(j.pending_unknown().is_err());
    }
}
