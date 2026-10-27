// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! Terraform's full output: `log_dir/<project>/<job>.log`, root-only, never
//! shown to the agent or the daemon.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::single_component;

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// A directory of ours with mode 0700 that is not a symlink. Created 0700
/// when missing; an existing one with another owner or mode is refused.
pub(super) fn private_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && m.uid() == euid() && m.mode() & 0o777 == 0o700 => Ok(()),
        Ok(_) => Err(io::Error::other("not a private directory")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        }
        Err(e) => Err(e),
    }
}

/// Opens `log_dir/<project>/<job>.log` for appending: created 0600 the
/// first time, and otherwise accepted only as a regular file of ours with
/// no group or other bits. Never follows a symlink at the file.
pub(super) fn open_log(log_dir: &Path, project: &str, job: u64) -> io::Result<File> {
    if !single_component(project) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    private_dir(log_dir)?;
    let dir = log_dir.join(project);
    private_dir(&dir)?;
    let path = dir.join(format!("{job}.log"));
    let mut opts = OpenOptions::new();
    opts.append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    match opts.clone().create_new(true).mode(0o600).open(&path) {
        Ok(f) => {
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            Ok(f)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let f = opts.open(&path)?;
            let m = f.metadata()?;
            if m.is_file() && m.uid() == euid() && m.mode() & 0o077 == 0 {
                Ok(f)
            } else {
                Err(io::Error::other("unexpected log file"))
            }
        }
        Err(e) => Err(e),
    }
}

/// Reports a pruning error by file name only.
fn report(path: &Path, e: &io::Error) {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    eprintln!("shoephone-runner: cannot prune log {name}: {}", e.kind());
}

/// Deletes regular files older than `days` in each project directory
/// under `log_dir`. Symlinks are never followed or removed. An entry that
/// fails is reported and skipped. Returns how many files went. Call it at
/// startup.
pub fn prune_logs(log_dir: &Path, days: u32) -> io::Result<usize> {
    let cutoff = SystemTime::now() - Duration::from_secs(u64::from(days) * 86_400);
    let projects = match fs::read_dir(log_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0;
    for project in projects.flatten() {
        if !project.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let entries = match fs::read_dir(project.path()) {
            Ok(r) => r,
            Err(e) => {
                report(&project.path(), &e);
                continue;
            }
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let path = entry.path();
            let old = fs::symlink_metadata(&path)
                .and_then(|m| m.modified())
                .map(|t| t < cutoff);
            match old {
                Ok(true) => match fs::remove_file(&path) {
                    Ok(()) => removed += 1,
                    Err(e) => report(&path, &e),
                },
                Ok(false) => {}
                Err(e) => report(&path, &e),
            }
        }
    }
    Ok(removed)
}
