// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The runner's state directory: where each project's files live, and the
//! one way they are written.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The recorded baseline: what was trusted, the schema it carried, and the
/// archive header mode of each file of the trusted tree (the disk holds
/// every file 0600, so the digest's modes come from here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trusted {
    pub digest: String,
    pub schema: String,
    #[serde(default)]
    pub modes: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppliedStatus {
    Applied,
    Uncertain,
}

/// The last apply: which manifest, and whether its outcome is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub manifest: String,
    pub status: AppliedStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// The runner is claiming, or has claimed, the job and has not acted.
    Claimed,
    /// Terraform apply has started.
    Applying,
    /// The job's result is known and not yet delivered to the daemon.
    Reporting,
    Done,
}

/// A failure as the journal keeps it until it is reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalFailure {
    pub category: String,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

/// The crash journal for the job in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub job: String,
    pub phase: Phase,
    pub result: Option<String>,
    /// `trust` or `apply`, recorded at the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The failure to report with `result`, while `Reporting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<JournalFailure>,
}

/// Paths under `state_dir/projects/<name>/`.
#[derive(Debug, Clone)]
pub struct ProjectPaths {
    dir: PathBuf,
}

impl ProjectPaths {
    /// Refuses a name that is not exactly one normal path component, so a
    /// name like `..` or `a/b` cannot move state outside the project dir.
    pub fn new(state_dir: &Path, project: &str) -> Result<ProjectPaths, String> {
        let mut comps = Path::new(project).components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(c)), None) if c == std::ffi::OsStr::new(project) => {
                Ok(ProjectPaths {
                    dir: state_dir.join("projects").join(project),
                })
            }
            _ => Err(format!("invalid project name {project:?}")),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The unpacked trusted tree.
    pub fn trusted_dir(&self) -> PathBuf {
        self.dir.join("trusted")
    }

    pub fn trusted_json(&self) -> PathBuf {
        self.dir.join("trusted.json")
    }

    pub fn applied_json(&self) -> PathBuf {
        self.dir.join("applied.json")
    }

    pub fn journal_json(&self) -> PathBuf {
        self.dir.join("journal.json")
    }

    /// Root's copies of saved plans, one per job.
    pub fn plans_dir(&self) -> PathBuf {
        self.dir.join("plans")
    }
}

/// Replace `path` with `bytes` so a reader sees the old file or the new one,
/// never a mix: write a 0600 temp file beside it, fsync, rename, then fsync
/// the directory so the rename survives a crash.
///
/// The temp name is fixed (`<name>.tmp`), so this assumes a single writer per
/// target; a concurrent writer fails closed with `EEXIST`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = parent.join(tmp_name);

    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sp-runner-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_atomic_replaces_whole_file() {
        let dir = scratch("atomic");
        let f = dir.join("applied.json");
        write_atomic(&f, b"a long first version of the file").unwrap();
        write_atomic(&f, b"short").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"short");
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(dir.join("applied.json.tmp"), b"stale").unwrap();
        write_atomic(&f, b"third").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"third");
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(names.len(), 1, "no temp file may remain");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_paths_are_under_project_dir() {
        let p = ProjectPaths::new(Path::new("/var/lib/r"), "web").unwrap();
        let base = Path::new("/var/lib/r/projects/web");
        assert_eq!(p.dir(), base);
        for path in [
            p.trusted_dir(),
            p.trusted_json(),
            p.applied_json(),
            p.journal_json(),
        ] {
            assert!(path.starts_with(base), "{}", path.display());
        }
        assert_eq!(p.trusted_json(), base.join("trusted.json"));
    }

    #[test]
    fn project_paths_refuse_non_single_components() {
        for bad in [".", "..", "", "a/b", "/abs", "../x"] {
            assert!(ProjectPaths::new(Path::new("/s"), bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn journal_and_applied_round_trip_as_documented() {
        let a = Applied {
            manifest: "m".into(),
            status: AppliedStatus::Uncertain,
        };
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            r#"{"manifest":"m","status":"uncertain"}"#
        );
        let j = Journal {
            job: "j".into(),
            phase: Phase::Applying,
            result: None,
            kind: None,
            failure: None,
        };
        assert_eq!(
            serde_json::to_string(&j).unwrap(),
            r#"{"job":"j","phase":"applying","result":null}"#
        );
    }
}
