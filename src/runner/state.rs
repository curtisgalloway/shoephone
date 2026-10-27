// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The runner's state directory: where each project's files live, and the
//! one way they are written.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The recorded baseline: what was trusted and the schema it carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trusted {
    pub digest: String,
    pub schema: String,
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
    Claimed,
    Applying,
    Done,
}

/// The crash journal for the job in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub job: String,
    pub phase: Phase,
    pub result: Option<String>,
}

/// Paths under `state_dir/projects/<name>/`.
#[derive(Debug, Clone)]
pub struct ProjectPaths {
    dir: PathBuf,
}

impl ProjectPaths {
    pub fn new(state_dir: &Path, project: &str) -> ProjectPaths {
        ProjectPaths {
            dir: state_dir.join("projects").join(project),
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
}

/// Replace `path` with `bytes` so a reader sees the old file or the new one,
/// never a mix: write a 0600 temp file beside it, fsync, rename, then fsync
/// the directory so the rename survives a crash.
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
        let p = ProjectPaths::new(Path::new("/var/lib/r"), "web");
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
        };
        assert_eq!(
            serde_json::to_string(&j).unwrap(),
            r#"{"job":"j","phase":"applying","result":null}"#
        );
    }
}
