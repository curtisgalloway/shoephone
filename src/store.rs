// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! What survives a restart: enrolled devices, the console-minted enrollment
//! code, and the ledger. All of it lives in the root-only state directory.
//!
//! Windows, nonces and counters deliberately do not persist; a restart
//! fails closed and acts as a soft kill switch.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::SecurityKey;

use crate::grant::Event;

/// One enrolled approver device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub enrolled_at: u64,
    pub key: SecurityKey,
    /// APNs device token, hex, registered by the app after enrollment.
    /// Absent for a device that has never registered (a hardware key).
    #[serde(default)]
    pub push_token: Option<String>,
}

/// A one-time enrollment code minted at the console by `shoephoned enroll`.
/// Only the SHA-256 of the code is stored, so reading the file does not
/// reveal it. It expires and is deleted on first use or after a few wrong
/// guesses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollCode {
    pub sha256: String,
    pub device_name: String,
    pub expires_at: u64,
    #[serde(default)]
    pub failures: u32,
}

impl EnrollCode {
    pub const TTL_SECS: u64 = 10 * 60;
    pub const MAX_FAILURES: u32 = 5;
}

/// A ledger line. Flattened from [`Event`] to unix seconds and plain strings
/// so the file is greppable and stable across versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEntry {
    pub at: u64,
    pub kind: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    /// The stated purpose, on the `requested` line only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&Event> for LedgerEntry {
    fn from(e: &Event) -> Self {
        let (kind, host, at, id, serial, until) = match e {
            Event::Requested { id, host, at, .. } => ("requested", host, at, Some(*id), None, None),
            Event::Approved {
                id,
                host,
                ends_at,
                at,
            } => ("approved", host, at, Some(*id), None, Some(unix(*ends_at))),
            Event::Declined { id, host, at } => ("declined", host, at, Some(*id), None, None),
            Event::TimedOut { id, host, at } => ("timed_out", host, at, Some(*id), None, None),
            Event::Issued {
                serial,
                host,
                valid_before,
                at,
            } => (
                "issued",
                host,
                at,
                None,
                Some(*serial),
                Some(unix(*valid_before)),
            ),
            Event::Killed { host, at } => ("killed", host, at, None, None, None),
        };
        LedgerEntry {
            at: unix(*at),
            kind: kind.to_owned(),
            host: host.clone(),
            id,
            serial,
            until,
            reason: match e {
                Event::Requested { reason, .. } => Some(reason.clone()),
                _ => None,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn devices_path(&self) -> PathBuf {
        self.dir.join("devices.json")
    }

    fn enroll_path(&self) -> PathBuf {
        self.dir.join("enroll-code.json")
    }

    fn ledger_path(&self) -> PathBuf {
        self.dir.join("ledger.jsonl")
    }

    pub fn load_devices(&self) -> Result<Vec<Device>, String> {
        let path = self.devices_path();
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("parsing {}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    pub fn save_devices(&self, devices: &[Device]) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(devices).map_err(|e| e.to_string())?;
        write_atomic(&self.devices_path(), &json)
    }

    pub fn load_enroll_code(&self) -> Result<Option<EnrollCode>, String> {
        let path = self.enroll_path();
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("parsing {}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    pub fn save_enroll_code(&self, code: &EnrollCode) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(code).map_err(|e| e.to_string())?;
        write_atomic(&self.enroll_path(), &json)
    }

    /// Remove the enrollment code. Only "already gone" is not an error: a
    /// code that cannot be removed would keep accepting guesses, so that
    /// failure has to reach the caller.
    pub fn clear_enroll_code(&self) -> Result<(), String> {
        let path = self.enroll_path();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("removing {}: {e}", path.display())),
        }
    }

    /// Append entries; the file is opened append-only for every write so a
    /// crash mid-batch loses at most one line.
    pub fn append_ledger(&self, entries: &[LedgerEntry]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }
        let path = self.ledger_path();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("opening {}: {e}", path.display()))?;
        for e in entries {
            let line = serde_json::to_string(e).map_err(|e| e.to_string())?;
            writeln!(f, "{line}").map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
        Ok(())
    }

    /// The most recent `limit` ledger lines, newest last.
    pub fn read_ledger(&self, limit: usize) -> Result<Vec<LedgerEntry>, String> {
        let path = self.ledger_path();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        let start = lines.len().saturating_sub(limit);
        lines[start..]
            .iter()
            .map(|l| serde_json::from_str(l).map_err(|e| format!("ledger line: {e}")))
            .collect()
    }
}

/// Write through a per-process temp name and rename into place. Callers
/// serialize writes to one path under the daemon lock; the pid in the temp
/// name keeps two daemons on one state dir from clobbering each other's
/// half-written file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, bytes).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("renaming into {}: {e}", path.display()))
}

pub fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn sha256_hex(s: &str) -> String {
    use ssh_key::sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("shoephone-store-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ledger_appends_and_reads_back_the_tail() {
        let dir = tmp("ledger");
        let store = Store::new(&dir);
        assert!(store.read_ledger(10).unwrap().is_empty());
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let events = [
            Event::Requested {
                id: 1,
                host: "web01".into(),
                reason: "deploy".into(),
                at: t0,
            },
            Event::Approved {
                id: 1,
                host: "web01".into(),
                ends_at: t0 + Duration::from_secs(3600),
                at: t0,
            },
            Event::Issued {
                serial: 2,
                host: "web01".into(),
                valid_before: t0 + Duration::from_secs(900),
                at: t0,
            },
        ];
        let entries: Vec<LedgerEntry> = events.iter().map(LedgerEntry::from).collect();
        store.append_ledger(&entries).unwrap();
        let tail = store.read_ledger(2).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].kind, "approved");
        assert_eq!(tail[0].until, Some(1_800_003_600));
        assert_eq!(tail[1].serial, Some(2));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn enroll_code_round_trips_and_clears() {
        let dir = tmp("enroll");
        let store = Store::new(&dir);
        assert!(store.load_enroll_code().unwrap().is_none());
        let code = EnrollCode {
            sha256: sha256_hex("ABCD-EFGH"),
            device_name: "phone".into(),
            expires_at: 1_800_000_600,
            failures: 0,
        };
        store.save_enroll_code(&code).unwrap();
        assert_eq!(
            store.load_enroll_code().unwrap().unwrap().sha256,
            code.sha256
        );
        store.clear_enroll_code().unwrap();
        assert!(store.load_enroll_code().unwrap().is_none());
        assert!(store.load_devices().unwrap().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
