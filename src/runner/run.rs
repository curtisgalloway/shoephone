// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephone-runner run`: the poll loop that ties the runner together.
//!
//! One job at a time. A **trust** job is unpacked into a fresh job
//! directory owned by `review_user` and reviewed there by the
//! credential-free review worker. Root then repeats the review on its own
//! unpack of the archive and refuses `review_inconsistent` unless every
//! digest and count agrees, so a lying worker cannot change what the
//! approver signs; the worker's output stays the source of the display text,
//! while the warnings shown to the approver come from root's own review. On
//! approval root unpacks and reviews the archive once more, against the
//! trusted tree as it is then, and installs only the execution input as
//! `trusted/`.
//!
//! **Accepted deviation from the design** (Ruling 31): the spec has the
//! resolver never parse repository content. Here the root process does
//! parse it: the tar archive, the HCL scan for local modules, and the text
//! diff. Without that, a compromised worker could forge the diff the
//! operator reads. The parsers are memory-safe Rust, bounded by
//! [`Limits`].
//!
//! An **apply** job is checked against the local trusted revision and the
//! daemon's record of it, validated against the trusted schema, planned in
//! a copy of `trusted/` (never the agent's tree), and submitted with the
//! scope and display built from one plan summary; on approval it is
//! claimed, its pinned context re-checked, and applied.
//!
//! Every claim and every result is journaled before it is sent, and a
//! result the daemon has not acknowledged is re-sent, before any new work,
//! until it is delivered or refused for good (see [`Journal`]).
//!
//! Job directories live in `state_dir/jobs/<id>/` and are removed when the
//! job ends, whichever way it ends; the root-only plan copy goes with them.

use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use ssh_key::PrivateKey;

use crate::api::{
    ApplyScopeWire, CountsWire, DisplayWire, FailureView, FinishBody, JobScopeWire, MAX_WARNINGS,
    RefuseBody, RunnerJob, SubmitBody, TrustScopeWire, WarningView,
};
use crate::client::Error;
use crate::exit::Status;
use crate::job::Failure;
use crate::runner::POLICY_VERSION;
use crate::runner::client::RunnerClient;
use crate::runner::config::{ProjectConfig, RunnerConfig};
use crate::runner::exec;
use crate::runner::journal::{Journal, Unfinished};
use crate::runner::review::{self, Modes, Review, Warning};
use crate::runner::schema;
use crate::runner::state::{Applied, AppliedStatus, ProjectPaths, Trusted, write_atomic};
use crate::runner::tree::{self, Limits, Tree};
use crate::scope::{Action, TrustScope};
use crate::store::sha256_hex;

/// How often the loop polls when all is well.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// The longest wait between polls after repeated errors.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// How long a transient failure fetching an archive or sending a refusal
/// is retried within one job.
const RETRY_WINDOW: Duration = Duration::from_secs(60);
/// Largest `review.json` the runner reads back from the worker.
const MAX_REVIEW_BYTES: u64 = 64 * 1024 * 1024;

fn failure(category: &str) -> Failure {
    Failure {
        category: category.to_string(),
        addresses: Vec::new(),
        detail: None,
    }
}

fn view(f: &Failure) -> FailureView {
    FailureView {
        category: f.category.clone(),
        addresses: f.addresses.clone(),
        detail: f.detail.clone(),
    }
}

/// Why planning a job stopped short of a submit.
enum Stop {
    /// End the job with `refuse`: `result` is `refused` (policy, bad input)
    /// or `plan_failed` (the runner or Terraform could not plan it).
    Refuse(&'static str, Failure),
}

fn refused(category: &str) -> Stop {
    Stop::Refuse("refused", failure(category))
}

fn refused_with(f: Failure) -> Stop {
    Stop::Refuse("refused", f)
}

fn plan_failed(f: Failure) -> Stop {
    Stop::Refuse("plan_failed", f)
}

/// Why `startup` did not finish.
#[derive(Debug)]
pub enum StartupError {
    /// Something only the operator can fix, such as an unreadable journal.
    Fatal(String),
    /// The daemon could not be told about an earlier result yet.
    Retry(String),
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::Fatal(e) | StartupError::Retry(e) => f.write_str(e),
        }
    }
}

/// What a submitted job is waiting with, until it is claimed or ends.
#[derive(Debug)]
enum Work {
    Trust {
        /// The archive as fetched, unpacked again by root on approval.
        archive: Vec<u8>,
    },
    Apply {
        plan: PathBuf,
        plan_sha: String,
        context: String,
        canonical: String,
    },
}

impl Work {
    fn kind(&self) -> &'static str {
        match self {
            Work::Trust { .. } => "trust",
            Work::Apply { .. } => "apply",
        }
    }
}

/// The job this runner submitted and is waiting on.
#[derive(Debug)]
struct Pending {
    id: u64,
    project: String,
    job_dir: PathBuf,
    /// Exactly what was submitted; the claim must hand back the same.
    scope: JobScopeWire,
    work: Work,
}

/// A result journaled and not yet acknowledged by the daemon.
#[derive(Debug)]
struct Unreported {
    project: String,
    body: FinishBody,
    /// A trust installed locally that stands or falls with this result.
    install: bool,
    /// Whether the journal already holds this result. Nothing is sent
    /// until it does.
    journaled: bool,
}

/// How a `finish` went.
enum Sent {
    Delivered,
    Refused,
    Transient(String),
}

/// `review.json`, as the review worker writes it.
#[derive(Debug, Deserialize)]
struct ReviewFile {
    scope: Option<TrustScopeWire>,
    diff: Option<String>,
    verify_command: Option<String>,
    #[serde(default)]
    warnings: Vec<Warning>,
    failure: Option<FailureView>,
}

/// `install.json`: written before a trust replaces `trusted/`, removed once
/// the daemon has recorded it or the old trust is back.
#[derive(Debug, Serialize, Deserialize)]
struct InstallMarker {
    had_old: bool,
}

/// The warnings to show: duplicates collapsed, sorted by file and line, and
/// cut to the daemon's limit. Advisory warnings must never block a trust, so
/// the surplus is counted, not sent.
fn display_warnings(warnings: &[Warning]) -> (Vec<WarningView>, u32) {
    let mut views: Vec<WarningView> = warnings.iter().map(Warning::view).collect();
    views.sort_by(|a, b| {
        (&a.file, a.line, &a.kind, &a.variable, &a.into).cmp(&(
            &b.file,
            b.line,
            &b.kind,
            &b.variable,
            &b.into,
        ))
    });
    views.dedup();
    let omitted = views.len().saturating_sub(MAX_WARNINGS);
    views.truncate(MAX_WARNINGS);
    (views, u32::try_from(omitted).unwrap_or(u32::MAX))
}

/// The poll loop's state. [`run`] drives it; the tests drive
/// [`Runner::step`] directly.
pub struct Runner {
    cfg: RunnerConfig,
    client: RunnerClient,
    pending: Option<Pending>,
    unreported: Vec<Unreported>,
}

impl fmt::Debug for Runner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runner")
            .field("name", &self.cfg.name)
            .field("pending", &self.pending.as_ref().map(|p| p.id))
            .field("unreported", &self.unreported.len())
            .finish_non_exhaustive()
    }
}

/// Reads a regular file without following a symlink, at most `limit`
/// bytes. For files a worker user could have replaced.
fn read_nofollow(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    f.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("file too large"));
    }
    Ok(bytes)
}

/// Removes a file or a whole directory tree, without following a symlink.
fn remove_path(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => {
            let _ = fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = fs::remove_file(path);
        }
        Err(_) => {}
    }
}

/// A fresh, empty 0700 directory at `path`, replacing whatever was there.
fn fresh_dir(path: &Path) -> io::Result<()> {
    remove_path(path);
    if let Some(parent) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    DirBuilder::new().mode(0o700).create(path)
}

/// `rel` (a validated relative path) under `base`.
fn under(base: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .fold(base.to_path_buf(), |p, c| p.join(c))
}

fn modes_of(tree: &Tree) -> Modes {
    tree.files
        .iter()
        .map(|(k, f)| (k.clone(), f.mode))
        .collect()
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| format!("{} is unreadable", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn save_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    write_atomic(path, &bytes)
}

/// True for a daemon answer that retrying will not change. A stale
/// signature is not: the retry is signed afresh.
fn is_permanent(e: &Error) -> bool {
    match e {
        Error::Daemon { http: 401, reply } if reply.code == "stale_signature" => false,
        Error::Daemon { http, .. } => *http < 500,
        _ => false,
    }
}

/// True when the root process's own review agrees with the worker's scope
/// in every signed field.
fn same_trust_scope(worker: &TrustScopeWire, root: &TrustScope) -> bool {
    worker.project == root.project
        && worker.baseline == root.baseline
        && worker.candidate == root.candidate
        && worker.diff == root.diff
        && worker.schema == root.schema
        && worker.policy_version == root.policy_version
        && worker.files_changed == root.files_changed
        && worker.lines_added == root.lines_added
        && worker.lines_removed == root.lines_removed
        && worker.schema_changed == root.schema_changed
}

fn same_scope(a: &JobScopeWire, b: &JobScopeWire) -> bool {
    match (serde_json::to_value(a), serde_json::to_value(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

// ---------------------------------------------------------------------
// The trust install marker

fn marker_path(paths: &ProjectPaths) -> PathBuf {
    paths.dir().join("install.json")
}

fn prev_dir(paths: &ProjectPaths) -> PathBuf {
    paths.dir().join("trusted.prev")
}

fn prev_json(paths: &ProjectPaths) -> PathBuf {
    paths.dir().join("trusted.prev.json")
}

/// Keep the installed trust: drop the previous one and the marker.
fn install_commit(paths: &ProjectPaths) {
    remove_path(&prev_dir(paths));
    remove_path(&prev_json(paths));
    remove_path(&marker_path(paths));
}

fn remove_dir_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Put the previous trust back (or none, for a first trust), if a marker
/// says an install is open. Only what the install had already moved is
/// moved back: with no `trusted.prev/` the swap never started and
/// `trusted/` is still the original; `trusted.json` is replaced only when
/// `trusted.prev.json` holds the original, or there was no old trust. A
/// failure is logged and the marker kept, so the next start tries again.
/// Returns whether the install is now closed.
fn install_undo(paths: &ProjectPaths) -> bool {
    let marker = match load_json::<InstallMarker>(&marker_path(paths)) {
        Ok(Some(m)) => m,
        Ok(None) => return true,
        Err(e) => {
            eprintln!("shoephone-runner: {e}; leaving the trust install for the next start");
            return false;
        }
    };
    let restored = (|| -> io::Result<()> {
        if marker.had_old {
            if prev_dir(paths).exists() {
                remove_dir_if_present(&paths.trusted_dir())?;
                fs::rename(prev_dir(paths), paths.trusted_dir())?;
            }
            if prev_json(paths).exists() {
                remove_file_if_present(&paths.trusted_json())?;
                fs::rename(prev_json(paths), paths.trusted_json())?;
            }
        } else {
            remove_dir_if_present(&paths.trusted_dir())?;
            remove_file_if_present(&paths.trusted_json())?;
        }
        remove_dir_if_present(&paths.dir().join("trusted.next"))?;
        remove_file_if_present(&marker_path(paths))
    })();
    if let Err(e) = restored {
        eprintln!(
            "shoephone-runner: restoring the previous trust in {}: {e}; the next start retries",
            paths.dir().display()
        );
        return false;
    }
    true
}

/// No install is open, but an older runner (or a commit that could not
/// finish) may have left `trusted.prev/`. If `trusted/` is missing, that
/// is the trust: put it back. Otherwise it is a leftover.
fn recover_unmarked(paths: &ProjectPaths) {
    let restore = |from: PathBuf, to: PathBuf| {
        if from.exists()
            && !to.exists()
            && let Err(e) = fs::rename(&from, &to)
        {
            eprintln!("shoephone-runner: restoring {}: {e}", to.display());
        }
    };
    restore(prev_dir(paths), paths.trusted_dir());
    restore(prev_json(paths), paths.trusted_json());
    if paths.trusted_dir().exists() {
        remove_path(&prev_dir(paths));
        remove_path(&prev_json(paths));
    }
}

impl Runner {
    /// Reads the runner's signing key and checks the daemon URL; nothing
    /// else is touched yet.
    pub fn new(cfg: RunnerConfig) -> Result<Runner, String> {
        let key = PrivateKey::read_openssh_file(&cfg.key)
            .map_err(|e| format!("cannot read the runner key {}: {e}", cfg.key.display()))?;
        if key.is_encrypted() {
            return Err(format!(
                "the runner key {} is encrypted; it must not be",
                cfg.key.display()
            ));
        }
        let client = RunnerClient::new(&cfg.daemon, &cfg.name, key)?;
        Ok(Runner {
            cfg,
            client,
            pending: None,
            unreported: Vec::new(),
        })
    }

    /// For integration tests only: make the next request to `path` fail.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn test_hooks_fault(&self, path: &str, fault: crate::runner::client::Fault) {
        self.client.test_hooks_fault(path, fault);
    }

    fn paths(&self, project: &str) -> Result<ProjectPaths, Failure> {
        ProjectPaths::new(&self.cfg.state_dir, project).map_err(|_| failure("unknown_project"))
    }

    fn jobs_dir(&self) -> PathBuf {
        self.cfg.state_dir.join("jobs")
    }

    fn job_dir(&self, id: u64) -> PathBuf {
        self.jobs_dir().join(id.to_string())
    }

    fn project(&self, name: &str) -> Result<&ProjectConfig, Failure> {
        self.cfg
            .projects
            .get(name)
            .ok_or_else(|| failure("unknown_project"))
    }

    fn journal(&self, project: &str) -> Option<Journal> {
        self.paths(project).ok().map(|p| Journal::new(&p))
    }

    /// A fresh job directory, 0700, under `state_dir/jobs` (0711, so a
    /// worker user can reach its own directory and list none).
    fn make_job_dir(&self, id: u64) -> Result<PathBuf, Failure> {
        let jobs = self.jobs_dir();
        let dir = self.job_dir(id);
        DirBuilder::new()
            .recursive(true)
            .mode(0o711)
            .create(&jobs)
            .and_then(|()| fs::set_permissions(&jobs, fs::Permissions::from_mode(0o711)))
            .and_then(|()| fresh_dir(&dir))
            .map_err(|_| failure("job_dir_unavailable"))?;
        Ok(dir)
    }

    /// Removes a job's directory and its root-only plan copy. Every way a
    /// job ends goes through here: the directory holds backend state
    /// (`.terraform/`) and the plan, which must not accumulate.
    fn cleanup(&self, project: &str, id: u64) {
        let dir = self.job_dir(id);
        exec::discard_plan(
            &self.cfg,
            &exec::Job {
                project,
                id,
                dir: &dir,
                module: ".",
            },
        );
        remove_path(&dir);
    }

    /// Runs `f` until it succeeds, fails for good, or [`RETRY_WINDOW`]
    /// runs out, backing off between tries.
    fn retrying<T>(&self, mut f: impl FnMut() -> Result<T, Error>) -> Result<T, Error> {
        let deadline = Instant::now() + RETRY_WINDOW;
        let mut delay = Duration::from_secs(1);
        loop {
            match f() {
                Ok(v) => return Ok(v),
                Err(e) if is_permanent(&e) || Instant::now() + delay > deadline => return Err(e),
                Err(_) => {
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Startup

    /// Checks the sandbox, prunes old logs, clears what an earlier run left
    /// behind, turns whatever the journals left open into results, and
    /// delivers them. Run it before the first [`Runner::step`]; it can be
    /// run again after a [`StartupError::Retry`].
    pub fn startup(&mut self) -> Result<(), StartupError> {
        exec::preflight(&self.cfg);
        if let Err(e) = exec::prune_logs(&self.cfg.log_dir, self.cfg.log_days) {
            eprintln!("shoephone-runner: pruning logs: {e}");
        }
        // Nothing survives a restart in memory, so no job directory or plan
        // copy from before it can still be used by this process.
        remove_path(&self.jobs_dir());
        self.pending = None;
        self.unreported.clear();
        let projects: Vec<String> = self.cfg.projects.keys().cloned().collect();
        for name in &projects {
            let paths = self
                .paths(name)
                .map_err(|_| StartupError::Fatal(format!("bad project name {name:?}")))?;
            remove_path(&paths.plans_dir());
            remove_path(&paths.dir().join("incoming"));
            remove_path(&paths.dir().join("trusted.next"));
            if let Some(u) = self.recover(name, &paths)? {
                self.unreported.push(u);
            }
        }
        self.deliver().map_err(StartupError::Retry)
    }

    /// What a project's journal left open, as a result to deliver.
    fn recover(
        &self,
        project: &str,
        paths: &ProjectPaths,
    ) -> Result<Option<Unreported>, StartupError> {
        let fatal = |what: &str, e: &dyn fmt::Display| {
            StartupError::Fatal(format!(
                "project {project}: {what} ({e}); check the project's state by hand"
            ))
        };
        let journal = Journal::new(paths);
        let open = journal
            .unfinished()
            .map_err(|e| fatal("the journal is unreadable", &e))?;
        let marker = marker_path(paths).exists();
        if !marker {
            recover_unmarked(paths);
        }
        let (job, result, f, install) = match open {
            None => {
                if marker {
                    install_undo(paths);
                }
                return Ok(None);
            }
            Some(Unfinished::Reporting {
                job,
                result,
                failure,
            }) => {
                let install = marker && result == "trusted";
                if marker && !install {
                    install_undo(paths);
                }
                (job, result, failure, install)
            }
            Some(open) => {
                if marker {
                    install_undo(paths);
                }
                let (job, result, f) = match open {
                    Unfinished::Claimed { job, kind } if kind == "trust" => {
                        (job, "apply_failed", Some(failure("runner_restarted")))
                    }
                    Unfinished::Claimed { job, .. } | Unfinished::Applying { job } => {
                        self.mark_uncertain(paths, None)
                            .map_err(|e| fatal("applied.json", &e))?;
                        (job, "outcome_unknown", None)
                    }
                    Unfinished::Reporting { .. } => unreachable!("handled above"),
                };
                eprintln!("shoephone-runner: job {job} of {project} was open at a restart");
                journal
                    .report(job, result, f.as_ref())
                    .map_err(|e| fatal("the journal is unwritable", &e))?;
                (job, result.to_string(), f, false)
            }
        };
        Ok(Some(Unreported {
            project: project.to_string(),
            body: FinishBody {
                id: job,
                result,
                failure: f.as_ref().map(view),
                project: Some(project.to_string()),
            },
            install,
            journaled: true,
        }))
    }

    // -----------------------------------------------------------------
    // Results

    /// Sends one `finish`. A permanent refusal of what may be a retry is
    /// checked against the job's status: if the daemon already has this
    /// very result, the earlier send arrived and only its reply was lost.
    fn send_finish(&self, body: &FinishBody) -> Sent {
        match self.client.finish(body) {
            Ok(()) => Sent::Delivered,
            Err(e) if is_permanent(&e) => match self.client.job(body.id) {
                Ok(Some(st)) if st.result.as_deref() == Some(body.result.as_str()) => {
                    Sent::Delivered
                }
                Ok(_) => {
                    eprintln!(
                        "shoephone-runner: finish {} of job {} refused: {e}",
                        body.result, body.id
                    );
                    Sent::Refused
                }
                Err(e) => Sent::Transient(format!("job status: {e}")),
            },
            Err(e) => Sent::Transient(format!("finish: {e}")),
        }
    }

    /// Delivers every unreported result, oldest first. Stops at the first
    /// transient failure; nothing new is polled until all are through.
    fn deliver(&mut self) -> Result<(), String> {
        while let Some(u) = self.unreported.first_mut() {
            if !u.journaled {
                // Journal first: a result sent but never written down would
                // be lost to a crash after the send.
                let f = u.body.failure.as_ref().map(|f| Failure {
                    category: f.category.clone(),
                    addresses: f.addresses.clone(),
                    detail: f.detail.clone(),
                });
                let journal = ProjectPaths::new(&self.cfg.state_dir, &u.project)
                    .map(|p| Journal::new(&p))
                    .map_err(|e| format!("journal for job {}: {e}", u.body.id))?;
                journal
                    .report(u.body.id, &u.body.result, f.as_ref())
                    .map_err(|e| format!("journal for job {}: {e}", u.body.id))?;
                u.journaled = true;
            }
            let u = &self.unreported[0];
            let delivered = match self.send_finish(&u.body) {
                Sent::Delivered => true,
                Sent::Refused => false,
                Sent::Transient(e) => return Err(e),
            };
            let u = self.unreported.remove(0);
            if let Ok(paths) = self.paths(&u.project) {
                if u.install {
                    if delivered {
                        install_commit(&paths);
                    } else {
                        // The daemon did not record the trust, so neither
                        // does the runner.
                        install_undo(&paths);
                    }
                }
                if let Err(e) = Journal::new(&paths).close(u.body.id) {
                    eprintln!("shoephone-runner: journal for job {}: {e}", u.body.id);
                }
            }
        }
        Ok(())
    }

    /// Queues a claimed job's result, then journals and delivers it. If
    /// the journal cannot be written nothing is sent and the error is
    /// returned; the next pass tries the journal again first.
    fn report(
        &mut self,
        project: &str,
        id: u64,
        result: &str,
        f: Option<Failure>,
        install: bool,
    ) -> Result<(), String> {
        self.unreported.push(Unreported {
            project: project.to_string(),
            body: FinishBody {
                id,
                result: result.to_string(),
                failure: f.as_ref().map(view),
                project: Some(project.to_string()),
            },
            install,
            journaled: false,
        });
        self.deliver()
    }

    // -----------------------------------------------------------------
    // The loop

    /// One pass: deliver any unreported result, then poll once and act on
    /// the answer. An error means the daemon could not be reached or
    /// refused the conversation, and [`run`] backs off. A job's own
    /// failure is reported to the daemon, not returned.
    pub fn step(&mut self) -> Result<(), String> {
        self.deliver()?;
        let job = self.client.poll().map_err(|e| format!("poll: {e}"))?;
        match job {
            Some(j) if j.state == "approved" => self.on_approved(j),
            Some(j) => {
                // A new job means the one we were waiting on is over.
                if let Some(p) = self.pending.take() {
                    self.cleanup(&p.project, p.id);
                }
                self.on_work(j)
            }
            None => self.check_pending(),
        }
    }

    /// Nothing to do: see whether the job we submitted has ended without
    /// coming back for a claim (declined, timed out, killed, refused).
    fn check_pending(&mut self) -> Result<(), String> {
        let Some(p) = self.pending.take() else {
            return Ok(());
        };
        let status = match self.client.job(p.id) {
            Ok(s) => s,
            Err(e) => {
                self.pending = Some(p);
                return Err(format!("job status: {e}"));
            }
        };
        match status.as_ref().map(|s| s.state.as_str()) {
            // Our claim reached the daemon but its answer did not reach us.
            Some("claimed") => self.execute(p, None),
            Some("queued" | "working" | "waiting" | "approved") => {
                self.pending = Some(p);
                Ok(())
            }
            _ => {
                if let Some(journal) = self.journal(&p.project) {
                    let _ = journal.close(p.id);
                }
                self.cleanup(&p.project, p.id);
                Ok(())
            }
        }
    }

    fn on_approved(&mut self, j: RunnerJob) -> Result<(), String> {
        let p = match self.pending.take() {
            Some(p) if p.id == j.id => p,
            other => {
                if let Some(p) = other {
                    self.cleanup(&p.project, p.id);
                }
                return self.orphan(&j);
            }
        };
        let journal = self.journal(&p.project);
        if let Some(journal) = &journal
            && let Err(e) = journal.claim(p.id, p.work.kind())
        {
            // Without the record a crash could not be reported; leave the
            // approval to expire rather than act on it unjournaled.
            eprintln!("shoephone-runner: journal for job {}: {e}", p.id);
            self.cleanup(&p.project, p.id);
            return Err(format!("journal: {e}"));
        }
        match self.client.claim(p.id) {
            Ok(scope) => self.execute(p, Some(scope)),
            Err(e) if is_permanent(&e) => {
                eprintln!("shoephone-runner: claim of job {} refused: {e}", p.id);
                if let Some(journal) = &journal {
                    let _ = journal.close(p.id);
                }
                self.cleanup(&p.project, p.id);
                Ok(())
            }
            Err(e) => {
                // It may have arrived; `check_pending` finds out.
                self.pending = Some(p);
                Err(format!("claim: {e}"))
            }
        }
    }

    /// An approval this process has no plan for (it restarted after the
    /// submit): claim it and fail it, so it ends now with nothing applied.
    fn orphan(&mut self, j: &RunnerJob) -> Result<(), String> {
        let journal = self.journal(&j.project);
        if let Some(journal) = &journal
            && let Err(e) = journal.claim(j.id, &j.kind)
        {
            return Err(format!("journal: {e}"));
        }
        match self.client.claim(j.id) {
            Ok(_) => self.report(
                &j.project,
                j.id,
                "apply_failed",
                Some(failure("plan_lost")),
                false,
            ),
            Err(e) if is_permanent(&e) => {
                if let Some(journal) = &journal {
                    let _ = journal.close(j.id);
                }
                Ok(())
            }
            Err(e) => Err(format!("claim: {e}")),
        }
    }

    fn on_work(&mut self, j: RunnerJob) -> Result<(), String> {
        let job_dir = match self.make_job_dir(j.id) {
            Ok(d) => d,
            Err(f) => return self.refuse(&j, "plan_failed", f),
        };
        let planned = match j.kind.as_str() {
            "trust" => self.plan_trust(&j, &job_dir),
            "apply" => self.plan_apply(&j, &job_dir),
            _ => Err(refused("unknown_kind")),
        };
        let (work, scope, display) = match planned {
            Ok(x) => x,
            Err(Stop::Refuse(result, f)) => {
                self.cleanup(&j.project, j.id);
                return self.refuse(&j, result, f);
            }
        };
        let body = SubmitBody {
            id: j.id,
            scope,
            display,
        };
        let pending = Pending {
            id: j.id,
            project: j.project.clone(),
            job_dir,
            scope: body.scope.clone(),
            work,
        };
        match self.client.submit(&body) {
            Ok(()) => {
                self.pending = Some(pending);
                Ok(())
            }
            Err(e) if is_permanent(&e) => {
                eprintln!("shoephone-runner: submit of job {} refused: {e}", j.id);
                self.cleanup(&j.project, j.id);
                self.refuse(&j, "plan_failed", failure("submit_refused"))
            }
            Err(e) => {
                // It may have arrived; `check_pending` finds out.
                self.pending = Some(pending);
                Err(format!("submit: {e}"))
            }
        }
    }

    fn refuse(&self, j: &RunnerJob, result: &str, f: Failure) -> Result<(), String> {
        let body = RefuseBody {
            id: j.id,
            result: result.to_string(),
            failure: view(&f),
        };
        match self.retrying(|| self.client.refuse(&body)) {
            Ok(()) => Ok(()),
            Err(e) if is_permanent(&e) => {
                eprintln!("shoephone-runner: refuse of job {} refused: {e}", j.id);
                Ok(())
            }
            Err(e) => Err(format!("refuse: {e}")),
        }
    }

    // -----------------------------------------------------------------
    // Trust

    /// The local trusted record, checked against the tree on disk: the
    /// tree's digest must still equal the one recorded.
    fn local_trust(&self, pcfg: &ProjectConfig, paths: &ProjectPaths) -> Option<(Trusted, Tree)> {
        let local: Trusted = load_json(&paths.trusted_json()).ok().flatten()?;
        let tree = tree::execution_input(&paths.trusted_dir(), &pcfg.path, &local.modes).ok()?;
        (tree::digest(&tree) == local.digest).then_some((local, tree))
    }

    /// Root's own review of `archive`, unpacked into the fresh directory
    /// `into`, against `baseline` (the trusted tree). Applies the worker's
    /// `no_changes` rule too.
    fn root_review(
        &self,
        project: &str,
        pcfg: &ProjectConfig,
        paths: &ProjectPaths,
        baseline: Option<&Trusted>,
        archive: &[u8],
        into: &Path,
    ) -> Result<(Review, Modes), Failure> {
        fresh_dir(into).map_err(|_| failure("job_dir_unavailable"))?;
        let modes = tree::unpack(archive, into, &Limits::default())?;
        let trusted = paths.trusted_dir();
        let r = review::review(
            baseline.map(|t| (trusted.as_path(), &t.modes)),
            (into, &modes),
            project,
            pcfg,
            POLICY_VERSION,
        )?;
        if r.scope.baseline.is_some() && r.scope.files_changed == 0 {
            return Err(failure("no_changes"));
        }
        Ok((r, modes))
    }

    fn plan_trust(
        &self,
        j: &RunnerJob,
        job_dir: &Path,
    ) -> Result<(Work, JobScopeWire, DisplayWire), Stop> {
        let pcfg = self.project(&j.project).map_err(refused_with)?;
        let paths = self.paths(&j.project).map_err(refused_with)?;
        // The baseline is what the daemon trusts, and the local tree must
        // be that same revision; otherwise the diff would be against
        // something the approver never signed.
        let baseline = match &j.trusted {
            None => None,
            Some(rec) => match self.local_trust(pcfg, &paths) {
                Some((local, tree)) if local.digest == rec.digest => Some((local, tree)),
                _ => return Err(refused("baseline_mismatch")),
            },
        };
        let archive = self
            .retrying(|| self.client.archive(j.id))
            .map_err(|_| plan_failed(failure("archive_unavailable")))?;
        let unavailable = |_: io::Error| plan_failed(failure("job_dir_unavailable"));
        let candidate = job_dir.join("candidate");
        fresh_dir(&candidate).map_err(unavailable)?;
        let candidate_modes =
            tree::unpack(&archive, &candidate, &Limits::default()).map_err(refused_with)?;
        let baseline_dir = job_dir.join("baseline");
        if let Some((_, tree)) = &baseline {
            fresh_dir(&baseline_dir).map_err(unavailable)?;
            tree::copy_execution_input(tree, &paths.trusted_dir(), &baseline_dir)
                .map_err(plan_failed)?;
        }
        let request = serde_json::json!({
            "baseline_dir": baseline.as_ref().map(|_| baseline_dir.display().to_string()),
            "candidate_dir": candidate.display().to_string(),
            "project": j.project,
            "policy_version": POLICY_VERSION,
            "project_path": pcfg.path,
            "schema_file": pcfg.schema_file,
            "variables": pcfg.variables.keys().collect::<Vec<_>>(),
            "baseline_modes": baseline.as_ref().map(|(local, _)| &local.modes),
            "candidate_modes": candidate_modes,
        });
        let bytes = serde_json::to_vec(&request).expect("a JSON value serializes");
        write_atomic(&job_dir.join("request.json"), &bytes).map_err(unavailable)?;
        let owner = exec::review_owner(&self.cfg).map_err(plan_failed)?;
        exec::hand_over(job_dir, owner).map_err(plan_failed)?;
        exec::run_review_worker(&self.cfg, job_dir).map_err(plan_failed)?;

        let review: ReviewFile = read_nofollow(&job_dir.join("review.json"), MAX_REVIEW_BYTES)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| plan_failed(failure("review_failed")))?;
        if let Some(f) = review.failure {
            return Err(refused_with(Failure {
                category: f.category,
                addresses: f.addresses,
                detail: f.detail,
            }));
        }
        let scope = review
            .scope
            .ok_or_else(|| plan_failed(failure("review_failed")))?;

        // The worker's word is not enough: root reviews its own unpack and
        // every signed field must agree, the shown diff included.
        let incoming = paths.dir().join("incoming");
        let root = self.root_review(
            &j.project,
            pcfg,
            &paths,
            baseline.as_ref().map(|(local, _)| local),
            &archive,
            &incoming,
        );
        remove_path(&incoming);
        let inconsistent = || refused("review_inconsistent");
        let (root, _) = root.map_err(|_| inconsistent())?;
        // The approver is shown root's own warnings. The worker's list is
        // only logged; a forged one changes nothing that is sent.
        let (warnings, warnings_omitted) = display_warnings(&root.warnings);
        let display_ok = match (&review.diff, &root.diff) {
            (Some(text), Some(_)) => sha256_hex(text) == root.scope.diff,
            (None, None) => review.verify_command.as_deref() == Some(root.verify_command.as_str()),
            _ => false,
        };
        if !same_trust_scope(&scope, &root.scope) || !display_ok {
            return Err(inconsistent());
        }
        if !review.warnings.is_empty() {
            eprintln!(
                "shoephone-runner: trust job {}: {} reviewer warning(s)",
                j.id,
                review.warnings.len()
            );
        }
        let display = match review.diff {
            Some(diff) => DisplayWire {
                diff: Some(diff),
                warnings,
                warnings_omitted,
                ..DisplayWire::default()
            },
            None => DisplayWire {
                external: true,
                verify_command: review.verify_command,
                warnings,
                warnings_omitted,
                ..DisplayWire::default()
            },
        };
        Ok((Work::Trust { archive }, JobScopeWire::Trust(scope), display))
    }

    /// Installs the approved candidate as `trusted/`, from root's own
    /// unpack and review of the archive against the trusted tree as it is
    /// now, never from the directory the review worker could write. Leaves
    /// `install.json` until the daemon has recorded it.
    fn install_trust(
        &self,
        project: &str,
        archive: &[u8],
        approved: &TrustScopeWire,
    ) -> Result<(), Failure> {
        let pcfg = self.project(project)?;
        let paths = self.paths(project)?;
        let baseline = match &approved.baseline {
            None => None,
            Some(digest) => match self.local_trust(pcfg, &paths) {
                Some((local, _)) if local.digest == *digest => Some(local),
                _ => return Err(failure("baseline_mismatch")),
            },
        };
        let incoming = paths.dir().join("incoming");
        let next = paths.dir().join("trusted.next");
        let unavailable = |_: io::Error| failure("trust_install_failed");
        let installed = (|| {
            let (root, modes) =
                self.root_review(project, pcfg, &paths, baseline.as_ref(), archive, &incoming)?;
            if !same_trust_scope(approved, &root.scope) {
                return Err(failure("review_inconsistent"));
            }
            let tree = tree::execution_input(&incoming, &pcfg.path, &modes)?;
            fresh_dir(&next).map_err(unavailable)?;
            tree::copy_execution_input(&tree, &incoming, &next)?;

            remove_path(&prev_dir(&paths));
            remove_path(&prev_json(&paths));
            let had_old = paths.trusted_dir().exists();
            save_json(&marker_path(&paths), &InstallMarker { had_old }).map_err(unavailable)?;
            let record = Trusted {
                digest: approved.candidate.clone(),
                schema: approved.schema.clone(),
                modes: modes_of(&tree),
            };
            let swapped = (|| {
                if had_old {
                    fs::rename(paths.trusted_dir(), prev_dir(&paths))?;
                    if paths.trusted_json().exists() {
                        fs::rename(paths.trusted_json(), prev_json(&paths))?;
                    }
                }
                fs::rename(&next, paths.trusted_dir())?;
                save_json(&paths.trusted_json(), &record)
            })();
            if swapped.is_err() {
                install_undo(&paths);
                return Err(failure("trust_install_failed"));
            }
            Ok(())
        })();
        remove_path(&incoming);
        remove_path(&next);
        installed
    }

    // -----------------------------------------------------------------
    // Apply

    fn plan_apply(
        &self,
        j: &RunnerJob,
        job_dir: &Path,
    ) -> Result<(Work, JobScopeWire, DisplayWire), Stop> {
        let pcfg = self.project(&j.project).map_err(refused_with)?;
        let paths = self.paths(&j.project).map_err(refused_with)?;
        // The daemon's record and the local tree must name one revision,
        // and the tree must still hash to it.
        let (local, tree) = match (&j.trusted, self.local_trust(pcfg, &paths)) {
            (Some(rec), Some((local, tree)))
                if rec.digest == local.digest && rec.schema == local.schema =>
            {
                (local, tree)
            }
            _ => return Err(refused("no_trusted_revision")),
        };
        let schema_path = under(&under(&paths.trusted_dir(), &pcfg.path), &pcfg.schema_file);
        let schema_text = fs::read(&schema_path)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|t| sha256_hex(t) == local.schema)
            .ok_or_else(|| refused("no_trusted_revision"))?;
        let parsed = schema::parse_schema(&schema_text).map_err(refused_with)?;
        let runner_vars = pcfg.variables.keys().cloned().collect();
        schema::disjoint(&parsed, &runner_vars).map_err(refused_with)?;
        let manifest = j
            .manifest
            .as_deref()
            .ok_or_else(|| refused("manifest_missing"))?;
        let canonical = schema::validate(&parsed, manifest).map_err(refused_with)?;

        let checkout = job_dir.join(exec::CHECKOUT);
        fresh_dir(&checkout).map_err(|_| plan_failed(failure("job_dir_unavailable")))?;
        tree::copy_execution_input(&tree, &paths.trusted_dir(), &checkout).map_err(plan_failed)?;
        let owner = exec::terraform_owner(&self.cfg).map_err(plan_failed)?;
        exec::hand_over(job_dir, owner).map_err(plan_failed)?;
        let context = exec::context_digest(&self.cfg, pcfg).map_err(plan_failed)?;
        let resolved = exec::resolve(&self.cfg, pcfg).map_err(plan_failed)?;
        let job = exec::Job {
            project: &j.project,
            id: j.id,
            dir: job_dir,
            module: &pcfg.path,
        };
        // Terraform reads the canonical text, written by `exec::plan`,
        // never the agent's manifest.
        let planned = exec::plan(&self.cfg, &job, &canonical, &resolved);
        drop(resolved);
        let (summary, plan, plan_sha) = planned.map_err(plan_failed)?;

        if summary.destructive && !j.allow_destroy {
            let addresses = summary
                .changes
                .iter()
                .filter(|(a, _)| matches!(a, Action::Delete | Action::Replace))
                .map(|(_, address)| address.clone())
                .collect();
            return Err(refused_with(Failure {
                category: "destroy_not_requested".into(),
                addresses,
                detail: None,
            }));
        }
        // Counts, the destructive flag and the address text all come from
        // this one summary, so the signed fields cannot drift apart.
        let address_text = summary
            .address_text()
            .ok_or_else(|| plan_failed(failure("plan_address_refused")))?;
        let applied: Option<Applied> = load_json(&paths.applied_json())
            .map_err(|_| plan_failed(failure("state_unreadable")))?;
        let baseline_status = match applied.as_ref().map(|a| a.status) {
            None => "none",
            Some(AppliedStatus::Applied) => "applied",
            Some(AppliedStatus::Uncertain) => "uncertain",
        };
        let baseline_text = applied.map(|a| a.manifest);
        let counts = summary.counts;
        let scope = ApplyScopeWire {
            project: j.project.clone(),
            revision: local.digest.clone(),
            schema: local.schema.clone(),
            manifest: sha256_hex(&canonical.0),
            baseline_manifest: baseline_text.as_deref().map(sha256_hex),
            baseline_status: baseline_status.to_string(),
            plan: plan_sha.clone(),
            destructive: summary.destructive,
            counts: CountsWire {
                create: counts.create,
                update: counts.update,
                replace: counts.replace,
                delete: counts.delete,
            },
            addresses: sha256_hex(&address_text),
        };
        let display = DisplayWire {
            manifest: Some(canonical.0.clone()),
            baseline_manifest: baseline_text,
            address_text: Some(address_text),
            ..DisplayWire::default()
        };
        let work = Work::Apply {
            plan,
            plan_sha,
            context,
            canonical: canonical.0,
        };
        Ok((work, JobScopeWire::Apply(scope), display))
    }

    /// Marks the baseline uncertain, keeping the last applied manifest, or
    /// `fallback` when nothing was applied before.
    fn mark_uncertain(&self, paths: &ProjectPaths, fallback: Option<&str>) -> Result<(), String> {
        let previous: Option<Applied> = load_json(&paths.applied_json())?;
        let manifest = match (previous, fallback) {
            (Some(p), _) => p.manifest,
            (None, Some(f)) => f.to_string(),
            (None, None) => return Ok(()),
        };
        save_json(
            &paths.applied_json(),
            &Applied {
                manifest,
                status: AppliedStatus::Uncertain,
            },
        )
        .map_err(|e| e.to_string())
    }

    // -----------------------------------------------------------------
    // After the claim

    /// Acts on a claimed job and reports how it ended. `claimed` is what
    /// the claim returned (absent when its reply was lost); it must be the
    /// whole scope this runner submitted.
    fn execute(&mut self, p: Pending, claimed: Option<JobScopeWire>) -> Result<(), String> {
        let same = claimed.as_ref().is_none_or(|c| same_scope(c, &p.scope));
        let (result, f, install) = if !same {
            ("apply_failed", Some(failure("scope_mismatch")), false)
        } else {
            match (&p.work, &p.scope) {
                (Work::Trust { archive }, JobScopeWire::Trust(approved)) => {
                    match self.install_trust(&p.project, archive, approved) {
                        Ok(()) => ("trusted", None, true),
                        Err(f) => ("apply_failed", Some(f), false),
                    }
                }
                (
                    Work::Apply {
                        plan,
                        plan_sha,
                        context,
                        canonical,
                    },
                    JobScopeWire::Apply(_),
                ) => {
                    let (r, f) = self.apply_claimed(&p, plan, plan_sha, context, canonical);
                    (r, f, false)
                }
                _ => ("apply_failed", Some(failure("scope_mismatch")), false),
            }
        };
        self.cleanup(&p.project, p.id);
        self.report(&p.project, p.id, result, f, install)
    }

    /// Re-checks the local trust and the pinned context, then applies under
    /// the journal.
    /// Returns the finish result and its failure.
    fn apply_claimed(
        &self,
        p: &Pending,
        plan: &Path,
        plan_sha: &str,
        context: &str,
        canonical: &str,
    ) -> (&'static str, Option<Failure>) {
        let (Ok(pcfg), Ok(paths)) = (self.project(&p.project), self.paths(&p.project)) else {
            return ("apply_failed", Some(failure("unknown_project")));
        };
        let job = exec::Job {
            project: &p.project,
            id: p.id,
            dir: &p.job_dir,
            module: &pcfg.path,
        };
        // Nothing has run yet: a changed context or trust ends the job as
        // `apply_failed` (the only failure `finish` takes from Claimed),
        // with the baseline untouched. The local trusted tree must still be
        // the revision and schema the approver signed.
        let JobScopeWire::Apply(approved) = &p.scope else {
            exec::discard_plan(&self.cfg, &job);
            return ("apply_failed", Some(failure("scope_mismatch")));
        };
        let still_trusted = self.local_trust(pcfg, &paths).is_some_and(|(local, _)| {
            local.digest == approved.revision && local.schema == approved.schema
        });
        if !still_trusted {
            exec::discard_plan(&self.cfg, &job);
            return ("apply_failed", Some(failure("untrusted")));
        }
        if let Err(f) = exec::check_context(&self.cfg, pcfg, context) {
            exec::discard_plan(&self.cfg, &job);
            return ("apply_failed", Some(f));
        }
        let resolved = match exec::resolve(&self.cfg, pcfg) {
            Ok(r) => r,
            Err(f) => {
                exec::discard_plan(&self.cfg, &job);
                return ("apply_failed", Some(f));
            }
        };
        // Before Terraform starts the baseline becomes uncertain; only a
        // clean apply makes it `applied` again, so a crash in between
        // leaves it uncertain.
        if self.mark_uncertain(&paths, Some(canonical)).is_err() {
            exec::discard_plan(&self.cfg, &job);
            return ("apply_failed", Some(failure("state_write_failed")));
        }
        let journal = Journal::new(&paths);
        let outcome = exec::apply(&self.cfg, &job, plan, plan_sha, &resolved, &journal);
        drop(resolved);
        if outcome.is_ok() {
            let applied = Applied {
                manifest: canonical.to_string(),
                status: AppliedStatus::Applied,
            };
            if let Err(e) = save_json(&paths.applied_json(), &applied) {
                eprintln!("shoephone-runner: applied.json for job {}: {e}", p.id);
            }
        }
        // The same mapping exec journaled, so a re-send says the same.
        exec::finish_result(&outcome)
    }
}

/// `shoephone-runner run`. Returns only when the runner cannot start.
pub fn run(cfg: RunnerConfig) -> ExitCode {
    let mut runner = match Runner::new(cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("shoephone-runner: {e}");
            return Status::Precondition.into();
        }
    };
    let mut delay = POLL_INTERVAL;
    loop {
        match runner.startup() {
            Ok(()) => break,
            Err(StartupError::Fatal(e)) => {
                eprintln!("shoephone-runner: {e}");
                return Status::Precondition.into();
            }
            Err(StartupError::Retry(e)) => {
                eprintln!("shoephone-runner: {e}; retrying in {}s", delay.as_secs());
                std::thread::sleep(delay);
                delay = (delay * 2).min(MAX_BACKOFF);
            }
        }
    }
    delay = POLL_INTERVAL;
    loop {
        match runner.step() {
            Ok(()) => delay = POLL_INTERVAL,
            Err(e) => {
                delay = (delay * 2).min(MAX_BACKOFF);
                eprintln!("shoephone-runner: {e}; next poll in {}s", delay.as_secs());
            }
        }
        std::thread::sleep(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provisioner(file: &str, line: u32) -> Warning {
        Warning::Provisioner {
            file: file.into(),
            line,
        }
    }

    #[test]
    fn display_warnings_cut_at_the_limit_and_count_the_rest() {
        let many: Vec<Warning> = (0..250).map(|i| provisioner("a.tf", i)).collect();
        let (sent, omitted) = display_warnings(&many);
        assert_eq!((sent.len(), omitted), (200, 50));
        assert_eq!(sent[0].line, 0);
        assert_eq!(sent[199].line, 199);
    }

    #[test]
    fn display_warnings_collapse_duplicates_and_sort() {
        let same: Vec<Warning> = (0..200).map(|_| provisioner("a.tf", 1)).collect();
        assert_eq!(
            display_warnings(&same),
            (vec![provisioner("a.tf", 1).view()], 0)
        );
        let mixed = [
            provisioner("b.tf", 1),
            provisioner("a.tf", 9),
            provisioner("a.tf", 2),
        ];
        let (sent, omitted) = display_warnings(&mixed);
        let order: Vec<_> = sent.iter().map(|w| (w.file.as_str(), w.line)).collect();
        assert_eq!(order, [("a.tf", 2), ("a.tf", 9), ("b.tf", 1)]);
        assert_eq!(omitted, 0);
    }

    #[test]
    fn under_joins_relative_components() {
        assert_eq!(
            under(Path::new("/s"), "infra/web"),
            PathBuf::from("/s/infra/web")
        );
        assert_eq!(under(Path::new("/s"), "./x"), PathBuf::from("/s/x"));
    }

    #[test]
    fn read_nofollow_refuses_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"secret").unwrap();
        let link = dir.path().join("review.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_nofollow(&link, 1024).is_err());
        assert_eq!(read_nofollow(&target, 1024).unwrap(), b"secret");
        assert!(read_nofollow(&target, 3).is_err(), "over the limit");
    }

    fn daemon(http: u16, code: &str) -> Error {
        Error::Daemon {
            http,
            reply: crate::api::ErrorReply {
                code: code.into(),
                error: String::new(),
                until: None,
            },
        }
    }

    #[test]
    fn only_client_errors_are_permanent() {
        assert!(is_permanent(&daemon(409, "busy")));
        assert!(is_permanent(&daemon(401, "wrong_runner")));
        assert!(
            !is_permanent(&daemon(401, "stale_signature")),
            "re-signed on retry"
        );
        assert!(!is_permanent(&daemon(500, "x")));
        assert!(!is_permanent(&Error::Unreachable("down".into())));
    }

    #[test]
    fn install_undo_restores_the_previous_trust() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProjectPaths::new(dir.path(), "web").unwrap();
        fs::create_dir_all(prev_dir(&paths)).unwrap();
        fs::write(prev_dir(&paths).join("old.tf"), b"old").unwrap();
        fs::write(prev_json(&paths), b"{\"old\":1}").unwrap();
        fs::create_dir_all(paths.trusted_dir()).unwrap();
        fs::write(paths.trusted_dir().join("new.tf"), b"new").unwrap();
        fs::write(paths.trusted_json(), b"{\"new\":1}").unwrap();
        save_json(&marker_path(&paths), &InstallMarker { had_old: true }).unwrap();
        install_undo(&paths);
        assert!(paths.trusted_dir().join("old.tf").exists());
        assert!(!paths.trusted_dir().join("new.tf").exists());
        assert_eq!(fs::read(paths.trusted_json()).unwrap(), b"{\"old\":1}");
        assert!(!marker_path(&paths).exists());
        assert!(!prev_dir(&paths).exists());

        // A first trust undone leaves nothing trusted.
        save_json(&marker_path(&paths), &InstallMarker { had_old: false }).unwrap();
        install_undo(&paths);
        assert!(!paths.trusted_dir().exists());
        assert!(!paths.trusted_json().exists());
    }

    /// A project with a live trust: `trusted/old.tf` and `trusted.json`.
    fn live_trust() -> (tempfile::TempDir, ProjectPaths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProjectPaths::new(dir.path(), "web").unwrap();
        fs::create_dir_all(paths.trusted_dir()).unwrap();
        fs::write(paths.trusted_dir().join("old.tf"), b"old").unwrap();
        fs::write(paths.trusted_json(), b"{\"old\":1}").unwrap();
        (dir, paths)
    }

    fn assert_original(paths: &ProjectPaths) {
        assert_eq!(
            fs::read(paths.trusted_dir().join("old.tf")).unwrap(),
            b"old"
        );
        assert_eq!(fs::read(paths.trusted_json()).unwrap(), b"{\"old\":1}");
    }

    #[test]
    fn undo_before_any_rename_keeps_the_original_trust() {
        let (_dir, paths) = live_trust();
        save_json(&marker_path(&paths), &InstallMarker { had_old: true }).unwrap();
        assert!(install_undo(&paths));
        assert_original(&paths);
        assert!(!marker_path(&paths).exists());
    }

    #[test]
    fn undo_after_a_failed_first_rename_keeps_the_original_trust() {
        let (_dir, paths) = live_trust();
        // The new tree was copied, the marker written, and renaming
        // trusted/ to trusted.prev/ failed.
        let next = paths.dir().join("trusted.next");
        fs::create_dir_all(&next).unwrap();
        fs::write(next.join("new.tf"), b"new").unwrap();
        save_json(&marker_path(&paths), &InstallMarker { had_old: true }).unwrap();
        assert!(install_undo(&paths));
        assert_original(&paths);
        assert!(!next.exists(), "the partial next tree goes");
        assert!(!marker_path(&paths).exists());
    }

    #[test]
    fn undo_after_a_failed_json_rename_restores_both() {
        let (_dir, paths) = live_trust();
        save_json(&marker_path(&paths), &InstallMarker { had_old: true }).unwrap();
        // trusted/ moved to trusted.prev/; moving trusted.json failed, so
        // it is still the original and trusted/ is absent.
        fs::rename(paths.trusted_dir(), prev_dir(&paths)).unwrap();
        assert!(install_undo(&paths));
        assert_original(&paths);
        assert!(!prev_dir(&paths).exists());
        assert!(!marker_path(&paths).exists());
    }

    #[test]
    fn a_failed_restore_keeps_the_marker_for_the_next_start() {
        let (_dir, paths) = live_trust();
        save_json(&marker_path(&paths), &InstallMarker { had_old: true }).unwrap();
        fs::rename(paths.trusted_dir(), prev_dir(&paths)).unwrap();
        // A read-only project directory makes the rename back fail.
        fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o500)).unwrap();
        let first = install_undo(&paths);
        fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o700)).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores the mode; nothing to observe
        }
        assert!(!first);
        assert!(marker_path(&paths).exists(), "kept for the next start");
        assert!(prev_dir(&paths).exists(), "the previous trust is not lost");
        assert!(install_undo(&paths), "the retry succeeds");
        assert_original(&paths);
    }

    #[test]
    fn an_unmarked_prev_with_no_trusted_tree_is_restored() {
        let (_dir, paths) = live_trust();
        fs::rename(paths.trusted_dir(), prev_dir(&paths)).unwrap();
        fs::rename(paths.trusted_json(), prev_json(&paths)).unwrap();
        recover_unmarked(&paths);
        assert_original(&paths);
        assert!(!prev_dir(&paths).exists());

        // With trusted/ present, an unmarked prev is a leftover.
        fs::create_dir_all(prev_dir(&paths)).unwrap();
        recover_unmarked(&paths);
        assert!(!prev_dir(&paths).exists());
        assert_original(&paths);
    }
}
