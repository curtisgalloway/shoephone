// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The crash journal for an apply. `begin` is written before Terraform
//! starts and `end` after it returns, so a journal still saying `applying`
//! at startup means the outcome of that job is unknown.

use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

use crate::runner::state::{self, Phase, ProjectPaths, write_atomic};

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
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

    /// Records `job` as `applying`. Call it before Terraform starts.
    pub fn begin(&self, job: u64) -> io::Result<()> {
        self.write(job, Phase::Applying, None)
    }

    /// Records `job` as `done` with `result` (`applied` or a failure
    /// category). Refused when another job is still `applying`, so one
    /// job's end cannot hide another's unknown outcome.
    pub fn end(&self, job: u64, result: &str) -> io::Result<()> {
        if let Some(other) = self.pending_unknown()?
            && other != job
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("job {other} is still applying"),
            ));
        }
        self.write(job, Phase::Done, Some(result))
    }

    /// The job journaled `applying` with no `end`, if any. An unreadable
    /// journal is an error, never a clean start: it may be hiding one.
    pub fn pending_unknown(&self) -> io::Result<Option<u64>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let entry: state::Journal =
            serde_json::from_slice(&bytes).map_err(|_| invalid("journal.json is unreadable"))?;
        match entry.phase {
            Phase::Applying => entry
                .job
                .parse()
                .map(Some)
                .map_err(|_| invalid("journal.json has a malformed job id")),
            Phase::Claimed | Phase::Done => Ok(None),
        }
    }

    fn write(&self, job: u64, phase: Phase, result: Option<&str>) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        let entry = state::Journal {
            job: job.to_string(),
            phase,
            result: result.map(str::to_string),
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
        assert_eq!(j.pending_unknown().unwrap(), Some(7));
    }

    #[test]
    fn unreadable_journal_is_an_error_not_a_clean_start() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProjectPaths::new(dir.path(), "web").unwrap();
        let j = Journal::new(&paths);
        j.begin(1).unwrap();
        std::fs::write(paths.journal_json(), b"{\"job\":").unwrap();
        assert!(j.pending_unknown().is_err());
        std::fs::write(
            paths.journal_json(),
            br#"{"job":"x","phase":"applying","result":null}"#,
        )
        .unwrap();
        assert!(j.pending_unknown().is_err());
    }
}
