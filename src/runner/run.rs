// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephone-runner run`: the poll loop that ties the runner together.
//!
//! One job at a time. A **trust** job is unpacked into a fresh job
//! directory owned by `review_user`, reviewed there by the credential-free
//! review worker, and submitted; on approval the runner unpacks the archive
//! again itself, checks the approved candidate digest, and installs only
//! the execution input as `trusted/`. An **apply** job is checked against
//! the local trusted revision and the daemon's record of it, validated
//! against the trusted schema, planned in a copy of `trusted/` (never the
//! agent's tree), and submitted with the scope and display built from one
//! plan summary; on approval it is claimed, its pinned context re-checked,
//! and applied under the crash journal.
//!
//! Job directories live in `state_dir/jobs/<id>/` and are removed when the
//! job ends, whichever way it ends; the root-only plan copy goes with them.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde::Deserialize;
use ssh_key::PrivateKey;

use crate::api::{
    ApplyScopeWire, CountsWire, DisplayWire, FailureView, FinishBody, JobScopeWire, RefuseBody,
    RunnerJob, SubmitBody, TrustScopeWire,
};
use crate::client::Error;
use crate::exit::Status;
use crate::job::Failure;
use crate::runner::POLICY_VERSION;
use crate::runner::client::RunnerClient;
use crate::runner::config::{ProjectConfig, RunnerConfig};
use crate::runner::exec;
use crate::runner::journal::Journal;
use crate::runner::review::Warning;
use crate::runner::schema;
use crate::runner::state::{Applied, AppliedStatus, ProjectPaths, Trusted, write_atomic};
use crate::runner::tree::{self, Limits, Tree};
use crate::scope::Action;
use crate::store::sha256_hex;

/// How often the loop polls when all is well.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// The longest wait between polls after repeated errors.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Largest `review.json` the runner reads back from the worker.
const MAX_REVIEW_BYTES: u64 = 64 * 1024 * 1024;
/// How many times a `finish` is tried before the runner gives up on it.
const FINISH_ATTEMPTS: u32 = 5;

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
    /// The daemon could not be reached; try again later.
    Transport(String),
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
    /// The daemon could not be told about an unknown outcome yet.
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
        candidate: String,
        schema: String,
    },
    Apply {
        plan: PathBuf,
        plan_sha: String,
        context: String,
        canonical: String,
    },
}

/// The job this runner submitted and is waiting on.
#[derive(Debug)]
struct Pending {
    id: u64,
    project: String,
    job_dir: PathBuf,
    work: Work,
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

/// The poll loop's state. [`run`] drives it; the tests drive
/// [`Runner::step`] directly.
pub struct Runner {
    cfg: RunnerConfig,
    client: RunnerClient,
    pending: Option<Pending>,
}

impl fmt::Debug for Runner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runner")
            .field("name", &self.cfg.name)
            .field("pending", &self.pending.as_ref().map(|p| p.id))
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

fn modes_of(tree: &Tree) -> BTreeMap<String, u32> {
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

fn save_json<T: serde::Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    write_atomic(path, &bytes)
}

/// True for a daemon answer that retrying will not change.
fn is_permanent(e: &Error) -> bool {
    matches!(e, Error::Daemon { http, .. } if *http < 500)
}

/// How to undo a trust installed locally when the daemon will not record it.
#[derive(Debug)]
struct Restore {
    trusted_dir: PathBuf,
    trusted_json: PathBuf,
    prev: Option<PathBuf>,
    old_json: Option<Vec<u8>>,
}

impl Restore {
    fn commit(self) {
        if let Some(prev) = &self.prev {
            remove_path(prev);
        }
    }

    fn undo(&self) {
        remove_path(&self.trusted_dir);
        if let Some(prev) = &self.prev {
            let _ = fs::rename(prev, &self.trusted_dir);
        }
        let restored = match &self.old_json {
            Some(bytes) => write_atomic(&self.trusted_json, bytes),
            None => match fs::remove_file(&self.trusted_json) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        };
        if let Err(e) = restored {
            eprintln!("shoephone-runner: restoring trusted.json: {e}");
        }
    }
}

impl Runner {
    /// Reads the runner's signing key; nothing else is touched yet.
    pub fn new(cfg: RunnerConfig) -> Result<Runner, String> {
        let key = PrivateKey::read_openssh_file(&cfg.key)
            .map_err(|e| format!("cannot read the runner key {}: {e}", cfg.key.display()))?;
        if key.is_encrypted() {
            return Err(format!(
                "the runner key {} is encrypted; it must not be",
                cfg.key.display()
            ));
        }
        let client = RunnerClient::new(&cfg.daemon, &cfg.name, key);
        Ok(Runner {
            cfg,
            client,
            pending: None,
        })
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

    // -----------------------------------------------------------------
    // Startup

    /// Checks the sandbox, prunes old logs, clears what an earlier run left
    /// behind, and reports any apply the journal says was interrupted as
    /// `outcome_unknown`. Run it before the first [`Runner::step`].
    pub fn startup(&mut self) -> Result<(), StartupError> {
        exec::preflight(&self.cfg);
        if let Err(e) = exec::prune_logs(&self.cfg.log_dir, self.cfg.log_days) {
            eprintln!("shoephone-runner: pruning logs: {e}");
        }
        // Nothing survives a restart in memory, so no job directory or plan
        // copy from before it can still be used by this process.
        remove_path(&self.jobs_dir());
        self.pending = None;
        let projects: Vec<String> = self.cfg.projects.keys().cloned().collect();
        for name in &projects {
            let paths = self
                .paths(name)
                .map_err(|_| StartupError::Fatal(format!("bad project name {name:?}")))?;
            remove_path(&paths.plans_dir());
            remove_path(&paths.dir().join("incoming"));
            remove_path(&paths.dir().join("trusted.next"));
            let prev = paths.dir().join("trusted.prev");
            if prev.exists() && !paths.trusted_dir().exists() {
                let _ = fs::rename(&prev, paths.trusted_dir());
            }
            remove_path(&prev);
            self.report_unknown(name, &paths)?;
        }
        Ok(())
    }

    /// Reports a job the journal left `applying` as `outcome_unknown`, and
    /// only then closes the journal entry.
    fn report_unknown(&self, project: &str, paths: &ProjectPaths) -> Result<(), StartupError> {
        let journal = Journal::new(paths);
        let id = match journal.pending_unknown() {
            Ok(Some(id)) => id,
            Ok(None) => return Ok(()),
            Err(e) => {
                return Err(StartupError::Fatal(format!(
                    "project {project}: the apply journal is unreadable ({e}); \
                     check the project's state by hand, then remove journal.json"
                )));
            }
        };
        eprintln!("shoephone-runner: job {id} of {project} was applying at a restart");
        self.mark_uncertain(paths, None)
            .map_err(|e| StartupError::Fatal(format!("project {project}: applied.json: {e}")))?;
        let body = FinishBody {
            id,
            result: "outcome_unknown".into(),
            failure: None,
            project: Some(project.to_string()),
        };
        match self.client.finish(&body) {
            Ok(()) => {}
            Err(e) if is_permanent(&e) => {
                eprintln!("shoephone-runner: the daemon refused outcome_unknown for job {id}: {e}");
            }
            Err(e) => return Err(StartupError::Retry(format!("reporting job {id}: {e}"))),
        }
        journal
            .end(id, "outcome_unknown")
            .map_err(|e| StartupError::Fatal(format!("project {project}: journal: {e}")))
    }

    // -----------------------------------------------------------------
    // The loop

    /// One pass: poll once and act on the answer. An error means the
    /// daemon could not be reached or refused the conversation, and
    /// [`run`] backs off. A job's own failure is reported to the daemon,
    /// not returned.
    pub fn step(&mut self) -> Result<(), String> {
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
            Some("queued" | "working" | "waiting" | "approved") => self.pending = Some(p),
            _ => self.cleanup(&p.project, p.id),
        }
        Ok(())
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
        match self.client.claim(p.id) {
            Ok(scope) => {
                self.execute(p, Some(scope));
                Ok(())
            }
            Err(e) if is_permanent(&e) => {
                eprintln!("shoephone-runner: claim of job {} refused: {e}", p.id);
                self.cleanup(&p.project, p.id);
                Ok(())
            }
            Err(e) => {
                self.pending = Some(p);
                Err(format!("claim: {e}"))
            }
        }
    }

    /// An approval this process has no plan for (it restarted after the
    /// submit): claim it and fail it, so it ends now with nothing applied.
    fn orphan(&self, j: &RunnerJob) -> Result<(), String> {
        match self.client.claim(j.id) {
            Ok(_) => {
                self.finish(j.id, "apply_failed", Some(failure("plan_lost")));
                Ok(())
            }
            Err(e) if is_permanent(&e) => Ok(()),
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
            Err(Stop::Transport(e)) => {
                self.cleanup(&j.project, j.id);
                return Err(e);
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
        match self.client.refuse(&body) {
            Ok(()) => Ok(()),
            Err(e) if is_permanent(&e) => {
                eprintln!("shoephone-runner: refuse of job {} refused: {e}", j.id);
                Ok(())
            }
            Err(e) => Err(format!("refuse: {e}")),
        }
    }

    /// Reports how a claimed job ended.
    fn finish(&self, id: u64, result: &str, f: Option<Failure>) {
        let body = FinishBody {
            id,
            result: result.to_string(),
            failure: f.as_ref().map(view),
            project: None,
        };
        let _ = self.finish_body(&body);
    }

    /// [`RunnerClient::finish`], retried while the daemon is unreachable
    /// or answers 5xx.
    fn finish_body(&self, body: &FinishBody) -> Result<(), Error> {
        let mut delay = Duration::from_millis(500);
        let mut attempt = 1;
        loop {
            match self.client.finish(body) {
                Ok(()) => return Ok(()),
                Err(e) if is_permanent(&e) || attempt >= FINISH_ATTEMPTS => {
                    eprintln!(
                        "shoephone-runner: finish {} of job {} failed: {e}",
                        body.result, body.id
                    );
                    return Err(e);
                }
                Err(_) => {
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(MAX_BACKOFF);
                    attempt += 1;
                }
            }
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
        let archive = match self.client.archive(j.id) {
            Ok(a) => a,
            Err(e) if is_permanent(&e) => return Err(plan_failed(failure("archive_unavailable"))),
            Err(e) => return Err(Stop::Transport(format!("archive: {e}"))),
        };
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
        let expected_baseline = baseline.as_ref().map(|(local, _)| local.digest.clone());
        if scope.project != j.project
            || scope.baseline != expected_baseline
            || scope.policy_version != POLICY_VERSION
        {
            return Err(plan_failed(failure("review_inconsistent")));
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
                ..DisplayWire::default()
            },
            None => DisplayWire {
                external: true,
                verify_command: review.verify_command,
                ..DisplayWire::default()
            },
        };
        let work = Work::Trust {
            archive,
            candidate: scope.candidate.clone(),
            schema: scope.schema.clone(),
        };
        Ok((work, JobScopeWire::Trust(scope), display))
    }

    /// Installs the approved candidate as `trusted/`, from root's own
    /// unpack of the archive, never from the directory the review worker
    /// could write. Returns how to put the previous trust back.
    fn install_trust(
        &self,
        project: &str,
        archive: &[u8],
        candidate: &str,
        schema_digest: &str,
    ) -> Result<Restore, Failure> {
        let pcfg = self.project(project)?;
        let paths = self.paths(project)?;
        let dir = paths.dir();
        let incoming = dir.join("incoming");
        let next = dir.join("trusted.next");
        let prev = dir.join("trusted.prev");
        let unavailable = |_: io::Error| failure("trust_install_failed");
        let installed = (|| {
            fresh_dir(&incoming).map_err(unavailable)?;
            let modes = tree::unpack(archive, &incoming, &Limits::default())?;
            let tree = tree::execution_input(&incoming, &pcfg.path, &modes)?;
            if tree::digest(&tree) != candidate {
                return Err(failure("candidate_changed"));
            }
            let schema_path = under(&under(&incoming, &pcfg.path), &pcfg.schema_file);
            let schema_text = fs::read(&schema_path)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| failure("schema_missing"))?;
            if sha256_hex(&schema_text) != schema_digest {
                return Err(failure("schema_changed"));
            }
            fresh_dir(&next).map_err(unavailable)?;
            tree::copy_execution_input(&tree, &incoming, &next)?;
            let old_json = fs::read(paths.trusted_json()).ok();
            remove_path(&prev);
            let had_old = paths.trusted_dir().exists();
            if had_old {
                fs::rename(paths.trusted_dir(), &prev).map_err(unavailable)?;
            }
            let restore = Restore {
                trusted_dir: paths.trusted_dir(),
                trusted_json: paths.trusted_json(),
                prev: had_old.then(|| prev.clone()),
                old_json,
            };
            let record = Trusted {
                digest: candidate.to_string(),
                schema: schema_digest.to_string(),
                modes: modes_of(&tree),
            };
            let done = fs::rename(&next, paths.trusted_dir())
                .and_then(|()| save_json(&paths.trusted_json(), &record));
            if done.is_err() {
                restore.undo();
                return Err(failure("trust_install_failed"));
            }
            Ok(restore)
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

    /// Acts on a claimed job and reports how it ended. `scope` is what the
    /// claim returned (absent when the claim's reply was lost); it must be
    /// the scope this runner submitted.
    fn execute(&mut self, p: Pending, scope: Option<JobScopeWire>) {
        match &p.work {
            Work::Trust {
                archive,
                candidate,
                schema,
            } => {
                let same = match &scope {
                    None => true,
                    Some(JobScopeWire::Trust(t)) => t.candidate == *candidate,
                    Some(JobScopeWire::Apply(_)) => false,
                };
                if !same {
                    self.finish(p.id, "apply_failed", Some(failure("scope_mismatch")));
                } else {
                    match self.install_trust(&p.project, archive, candidate, schema) {
                        Ok(restore) => {
                            let body = FinishBody {
                                id: p.id,
                                result: "trusted".into(),
                                failure: None,
                                project: None,
                            };
                            match self.finish_body(&body) {
                                Ok(()) => restore.commit(),
                                // The daemon did not record it, so neither
                                // does the runner.
                                Err(_) => restore.undo(),
                            }
                        }
                        Err(f) => self.finish(p.id, "apply_failed", Some(f)),
                    }
                }
            }
            Work::Apply {
                plan,
                plan_sha,
                context,
                canonical,
            } => {
                let same = match &scope {
                    None => true,
                    Some(JobScopeWire::Apply(a)) => a.plan == *plan_sha,
                    Some(JobScopeWire::Trust(_)) => false,
                };
                let (result, f) = if same {
                    self.apply_claimed(&p, plan, plan_sha, context, canonical)
                } else {
                    ("apply_failed", Some(failure("scope_mismatch")))
                };
                self.finish(p.id, result, f);
            }
        }
        self.cleanup(&p.project, p.id);
    }

    /// Re-checks the pinned context, then applies under the journal.
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
        // Nothing has run yet: a changed context ends the job as
        // `apply_failed` (the only failure `finish` takes from Claimed),
        // with the baseline untouched.
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
        match outcome {
            Ok(()) => {
                let applied = Applied {
                    manifest: canonical.to_string(),
                    status: AppliedStatus::Applied,
                };
                if let Err(e) = save_json(&paths.applied_json(), &applied) {
                    eprintln!("shoephone-runner: applied.json for job {}: {e}", p.id);
                }
                ("applied", None)
            }
            // Terraform was stopped partway: nobody knows what it did.
            Err(f)
                if matches!(
                    f.category.as_str(),
                    "terraform_timeout" | "terraform_crashed"
                ) =>
            {
                if let Err(e) = journal.end(p.id, "outcome_unknown") {
                    eprintln!("shoephone-runner: journal for job {}: {e}", p.id);
                }
                ("outcome_unknown", None)
            }
            Err(f) => ("apply_failed", Some(f)),
        }
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

    #[test]
    fn only_client_errors_are_permanent() {
        let daemon = |http| Error::Daemon {
            http,
            reply: crate::api::ErrorReply {
                code: "x".into(),
                error: String::new(),
                until: None,
            },
        };
        assert!(is_permanent(&daemon(409)));
        assert!(!is_permanent(&daemon(500)));
        assert!(!is_permanent(&Error::Unreachable("down".into())));
    }
}
