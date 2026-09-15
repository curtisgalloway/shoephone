// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! What survives a restart: enrolled devices, the console-minted enrollment
//! code, and the ledger. All of it lives in the root-only state directory.
//!
//! Windows, nonces and counters deliberately do not persist; a restart
//! fails closed and acts as a soft kill switch.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
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
    /// Which pushes this device asked for, by [`Push::kind`] name. Absent
    /// means all of them (a device registered before the choice existed).
    #[serde(default)]
    pub push_kinds: Option<Vec<String>>,
    /// SHA-256 of the per-device secret minted at enrollment, which
    /// `push/register` requires the caller to present. Absent for a device
    /// enrolled before that check existed; such a device is refused at
    /// `push/register` until it enrolls again.
    #[serde(default)]
    pub push_secret_sha256: Option<String>,
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
    /// The entry's 1-based line number in the ledger file. Set only by
    /// [`Store::read_ledger`], never written: an entry appended fresh does
    /// not know its own line number, and a client pages backward through
    /// history using the value it read back, not one it made up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
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
    /// The requester's session link, on the `requested` line only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
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
                id,
                serial,
                host,
                valid_before,
                at,
            } => (
                "issued",
                host,
                at,
                Some(*id),
                Some(*serial),
                Some(unix(*valid_before)),
            ),
            Event::Killed { id, host, at } => ("killed", host, at, Some(*id), None, None),
        };
        LedgerEntry {
            seq: None,
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
            context: match e {
                Event::Requested { context, .. } => context.clone(),
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

    fn next_id_path(&self) -> PathBuf {
        self.dir.join("next_id")
    }

    /// The persisted id/serial counter, so a restart does not reuse an id
    /// or serial already written to the ledger.
    ///
    /// When the file is absent the count cannot simply start at 1. That is
    /// right for a fresh state directory and wrong for an upgrade from
    /// before this file existed, because the installer preserves
    /// `/var/lib/shoephone`: the ledger comes through the upgrade holding
    /// ids that a counter restarting at 1 would hand out a second time, and
    /// two different certificates under one id is exactly what the ledger
    /// exists to prevent. So an absent file is answered from the ledger
    /// instead — one id past the highest it already names.
    pub fn load_next_id(&self) -> Result<u64, String> {
        let path = self.next_id_path();
        match fs::read_to_string(&path) {
            Ok(text) => text
                .trim()
                .parse()
                .map_err(|e| format!("parsing {}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(self.highest_ledger_id()?.map_or(1, |n| n + 1))
            }
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    /// The largest id any ledger line names, or `None` for no ledger and for
    /// a ledger whose lines predate ids (`id` was added later, so those
    /// lines carry `null` and are not a gap to be filled).
    ///
    /// Unlike [`Store::read_ledger`], an unreadable file is an error rather
    /// than an empty result. A read that fails here would silently answer
    /// "start at 1" and resume the very id reuse this exists to stop, so it
    /// fails closed and the daemon refuses to start. An individual line that
    /// does not parse is still skipped: one torn by a crash mid-write must
    /// not hold up the count, and it cannot hide a larger id than the lines
    /// around it.
    fn highest_ledger_id(&self) -> Result<Option<u64>, String> {
        let path = self.ledger_path();
        let file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("opening {}: {e}", path.display())),
        };
        let mut highest = None;
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|e| format!("reading {}: {e}", path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: LedgerEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue,
            };
            highest = highest.max(entry.id);
        }
        Ok(highest)
    }

    pub fn save_next_id(&self, next_id: u64) -> Result<(), String> {
        write_atomic(&self.next_id_path(), next_id.to_string().as_bytes())
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

    /// Remove one enrolled approver by name, returning how many devices
    /// remain, or `None` when no device had that name.
    ///
    /// Lives here rather than in the `forget` verb so it is reachable from
    /// tests that enrol through the real ceremony: a device's key is a
    /// webauthn credential, which is not something to hand-write into a
    /// fixture.
    ///
    /// The caller is responsible for making sure no daemon is running. This
    /// writes `devices.json` whole, and so does a running `serve`, from its
    /// own in-memory copy.
    pub fn forget_device(&self, name: &str) -> Result<Option<usize>, String> {
        let devices = self.load_devices()?;
        let kept: Vec<Device> = devices.iter().filter(|d| d.name != name).cloned().collect();
        if kept.len() == devices.len() {
            return Ok(None);
        }
        let remaining = kept.len();
        self.save_devices(&kept)?;
        Ok(Some(remaining))
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

    /// Append entries and `fsync` before returning. The file is opened
    /// append-only for every write, which bounds a crash mid-batch to
    /// losing at most one line, but that alone says nothing about a clean
    /// process exit: without the `fsync`, a successful return here could
    /// still be sitting in the OS page cache when the machine loses power.
    /// `Daemon::audited` treats a failure here as a reason to fail closed,
    /// so "this call returned `Ok`" has to mean the bytes are actually on
    /// disk, not just handed to the kernel.
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
        f.sync_all()
            .map_err(|e| format!("syncing {}: {e}", path.display()))
    }

    /// Up to `limit` entries with `seq` (the entry's 1-based line number in
    /// the file) less than `before`, or every entry when `before` is
    /// `None`, returned oldest first. A client pages backward through
    /// history by calling with no parameters for the newest page, then
    /// repeating with `before` set to the smallest `seq` it received, until
    /// an empty page comes back; see `GET /api/ledger` in `api.rs`.
    ///
    /// Streams the file line by line rather than reading it whole, so
    /// memory stays bounded by `limit` no matter how large the ledger has
    /// grown. A line that fails to parse is skipped, with the line number
    /// logged, rather than failing the whole read: a line torn by a crash
    /// mid-write must not take the rest of the history down with it.
    pub fn read_ledger(
        &self,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<LedgerEntry>, String> {
        let path = self.ledger_path();
        let file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("opening {}: {e}", path.display())),
        };
        let mut window: VecDeque<LedgerEntry> = VecDeque::new();
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let seq = (i + 1) as u64;
            let line = line.map_err(|e| format!("reading {}: {e}", path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            if before.is_some_and(|before| seq >= before) {
                continue;
            }
            let mut entry: LedgerEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "shoephoned: ledger: skipping unparsable line {seq} in {}: {e}",
                        path.display()
                    );
                    continue;
                }
            };
            entry.seq = Some(seq);
            window.push_back(entry);
            if window.len() > limit {
                window.pop_front();
            }
        }
        Ok(window.into_iter().collect())
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
        assert!(store.read_ledger(None, 10).unwrap().is_empty());
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let events = [
            Event::Requested {
                id: 1,
                host: "web01".into(),
                reason: "deploy".into(),
                context: None,
                at: t0,
            },
            Event::Approved {
                id: 1,
                host: "web01".into(),
                ends_at: t0 + Duration::from_secs(3600),
                at: t0,
            },
            Event::Issued {
                id: 1,
                serial: 2,
                host: "web01".into(),
                valid_before: t0 + Duration::from_secs(900),
                at: t0,
            },
        ];
        let entries: Vec<LedgerEntry> = events.iter().map(LedgerEntry::from).collect();
        store.append_ledger(&entries).unwrap();
        let tail = store.read_ledger(None, 2).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].kind, "approved");
        assert_eq!(tail[0].seq, Some(2), "seq is the 1-based line number");
        assert_eq!(tail[0].until, Some(1_800_003_600));
        assert_eq!(tail[1].serial, Some(2));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_ledger_pages_backward_and_skips_a_garbage_line() {
        let dir = tmp("ledger-paging");
        let store = Store::new(&dir);
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let entries: Vec<LedgerEntry> = (1..=7u64)
            .map(|id| {
                LedgerEntry::from(&Event::Requested {
                    id,
                    host: "web01".into(),
                    reason: format!("entry {id}"),
                    context: None,
                    at: t0 + Duration::from_secs(id),
                })
            })
            .collect();
        store.append_ledger(&entries).unwrap();

        let seqs = |v: &[LedgerEntry]| -> Vec<u64> { v.iter().map(|e| e.seq.unwrap()).collect() };

        assert_eq!(seqs(&store.read_ledger(None, 3).unwrap()), [5, 6, 7]);
        assert_eq!(seqs(&store.read_ledger(Some(5), 3).unwrap()), [2, 3, 4]);
        assert_eq!(seqs(&store.read_ledger(Some(2), 3).unwrap()), [1]);
        assert!(store.read_ledger(Some(1), 3).unwrap().is_empty());

        // Corrupt line 4 in place, keeping every other line (and so every
        // other line's seq) exactly where it was.
        let path = dir.join("ledger.jsonl");
        let text = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines[3] = "{ not json";
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let all = store.read_ledger(None, 10).unwrap();
        assert_eq!(
            seqs(&all),
            [1, 2, 3, 5, 6, 7],
            "the garbage line is skipped, not fatal, and does not renumber its neighbors"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_upgrade_resumes_the_count_past_the_ledger_it_inherited() {
        // install.sh preserves /var/lib/shoephone, so a daemon that predates
        // the next_id file leaves its ledger behind. Starting over at 1 would
        // reissue ids the ledger already names.
        let dir = tmp("next-id-upgrade");
        let store = Store::new(&dir);
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let entries: Vec<LedgerEntry> = (1..=6u64)
            .map(|id| {
                LedgerEntry::from(&Event::Requested {
                    id,
                    host: "web01".into(),
                    reason: format!("entry {id}"),
                    context: None,
                    at: t0 + Duration::from_secs(id),
                })
            })
            .collect();
        store.append_ledger(&entries).unwrap();
        assert!(
            !dir.join("next_id").exists(),
            "the upgrade case: no counter"
        );

        assert_eq!(
            store.load_next_id().unwrap(),
            7,
            "one past the highest id the inherited ledger names"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_ledger_older_than_ids_does_not_shift_the_count() {
        // `id` was added after the ledger existed, so the oldest lines carry
        // null. Those are not a gap to be filled.
        let dir = tmp("next-id-idless");
        let store = Store::new(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("ledger.jsonl"),
            "{\"kind\":\"requested\",\"host\":\"web01\",\"at\":1800000000}\n",
        )
        .unwrap();
        assert_eq!(store.load_next_id().unwrap(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unreadable_ledger_refuses_to_answer_rather_than_guessing_one() {
        // Answering 1 here would silently resume the id reuse this exists to
        // stop, so the read fails closed and the daemon does not start.
        let dir = tmp("next-id-unreadable");
        fs::create_dir_all(dir.join("ledger.jsonl")).unwrap();
        let store = Store::new(&dir);
        let err = store.load_next_id().unwrap_err();
        assert!(err.contains("ledger.jsonl"), "names the file: {err}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn next_id_round_trips_and_defaults_to_one() {
        let dir = tmp("next-id");
        let store = Store::new(&dir);
        assert_eq!(
            store.load_next_id().unwrap(),
            1,
            "absent file defaults to 1"
        );
        store.save_next_id(42).unwrap();
        assert_eq!(store.load_next_id().unwrap(), 42);
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
