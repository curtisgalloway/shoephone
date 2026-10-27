// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The executor. The root process resolves a project's secret references
//! with `secret_command` ([`resolve`]), then runs Terraform as
//! `terraform_user` inside a bubblewrap sandbox that sees only the job
//! directory, the Terraform binary, the plugin directory and the system
//! files TLS and DNS need. Full output goes to a root-only log; what comes
//! back is an exit code and the `-json` stream, which only [`categorize`]
//! and [`summarize`] read.
//!
//! A job directory looks like this (`job_dir` must be owned by
//! `terraform_user` and reachable by it):
//!
//! ```text
//! job_dir/
//!   checkout/<project path>/   the execution input, copied by the loop
//!   manifest.tfvars.json       the Canonical manifest
//!   cli.tfrc                   an empty Terraform CLI config
//!   backend.hcl                backend config, present only during init
//!   plan.tfplan                written by plan; show and apply read the
//!                              verified root-only copy mounted over it
//! ```
//!
//! The plan Terraform writes is copied at once to
//! `state_dir/projects/<p>/plans/<job>.tfplan` (root, 0600), and that copy
//! is what is hashed, shown and applied.

mod log;
mod sandbox;
mod secret;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use ssh_key::sha2::{Digest, Sha256};

use crate::job::Failure;
use crate::runner::POLICY_VERSION;
use crate::runner::config::{ProjectConfig, RunnerConfig, Source};
use crate::runner::journal::Journal;
use crate::runner::plan::{Phase, Summary, categorize, summarize};
use crate::runner::schema::Canonical;
use crate::runner::state::{ProjectPaths, write_atomic};

pub use log::prune_logs;
pub use sandbox::preflight;
#[cfg(any(test, feature = "test-hooks"))]
pub use sandbox::test_hooks_run_without_sandbox;
pub use secret::{Resolved, Secret, resolve};

use log::open_log;
use sandbox::{Launch, command, launch, run_streaming};
#[cfg(test)]
use sandbox::{TEST_LAUNCH, bwrap_args};
#[cfg(test)]
use secret::run_secret;
use secret::{env_name_allowed, identifier};

/// Where the execution input sits inside a job directory.
pub const CHECKOUT: &str = "checkout";
pub const MANIFEST_FILE: &str = "manifest.tfvars.json";
pub const BACKEND_FILE: &str = "backend.hcl";
pub const PLAN_FILE: &str = "plan.tfplan";
pub const CLI_CONFIG_FILE: &str = "cli.tfrc";

fn refuse(category: &str) -> Failure {
    Failure {
        category: category.to_string(),
        addresses: Vec::new(),
        detail: None,
    }
}

/// One job's run of Terraform.
#[derive(Debug, Clone, Copy)]
pub struct Job<'a> {
    /// The project name, which names the log and plan directories.
    pub project: &'a str,
    pub id: u64,
    /// The job directory, absolute.
    pub dir: &'a Path,
    /// The project's path inside `checkout/` (the root module).
    pub module: &'a str,
}

/// A Terraform step's result: its exit code and up to 16 MiB of stdout,
/// the `-json` stream (`truncated` when there was more). Stdout can hold
/// anything Terraform printed, so `Debug` shows only the code, and the
/// text goes only to [`categorize`] or [`summarize`].
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub truncated: bool,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("code", &self.code)
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------
// Running one Terraform command

/// An absolute path of only `[A-Za-z0-9/._+-]` with no `..`, so it can
/// sit unquoted in `TF_CLI_ARGS_init` and a `-chdir=` argument.
fn plain_path(p: &Path) -> bool {
    p.is_absolute()
        && p.components().all(|c| c != Component::ParentDir)
        && p.to_str().is_some_and(|s| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._+-".contains(&b))
        })
}

fn single_component(name: &str) -> bool {
    let mut c = Path::new(name).components();
    matches!((c.next(), c.next()), (Some(Component::Normal(n)), None) if n == name)
}

fn check_job(cfg: &RunnerConfig, job: &Job, resolved: &Resolved) -> Result<(), Failure> {
    let module_ok = !job.module.is_empty()
        && !job.module.starts_with('/')
        && plain_path(&Path::new("/").join(job.module));
    let paths_ok = plain_path(job.dir)
        && plain_path(&cfg.plugin_dir)
        && module_ok
        && single_component(job.project);
    if !paths_ok {
        return Err(refuse("path_refused"));
    }
    if !resolved.env.iter().all(|(k, _)| env_name_allowed(k))
        || !resolved.tf_vars.iter().all(|(k, _)| identifier(k, true))
    {
        return Err(refuse("env_name_refused"));
    }
    Ok(())
}

/// Terraform's whole environment.
fn terraform_env(cfg: &RunnerConfig, job: &Job, resolved: &Resolved) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = resolved
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.expose().to_string()))
        .collect();
    env.extend(
        resolved
            .tf_vars
            .iter()
            .map(|(k, v)| (format!("TF_VAR_{k}"), v.expose().to_string())),
    );
    let mut init = format!("-plugin-dir={}", cfg.plugin_dir.display());
    if !resolved.backend.is_empty() {
        init.push_str(&format!(
            " -backend-config={}",
            job.dir.join(BACKEND_FILE).display()
        ));
    }
    env.extend([
        ("TF_IN_AUTOMATION".to_string(), "1".to_string()),
        ("TF_INPUT".to_string(), "0".to_string()),
        ("HOME".to_string(), job.dir.display().to_string()),
        (
            "TF_CLI_CONFIG_FILE".to_string(),
            job.dir.join(CLI_CONFIG_FILE).display().to_string(),
        ),
        ("TF_CLI_ARGS_init".to_string(), init),
    ]);
    env
}

fn step_timeout(cfg: &RunnerConfig) -> Duration {
    Duration::from_secs(u64::from(cfg.terraform_timeout_minutes) * 60)
}

/// Runs `terraform -chdir=<job>/checkout/<module> <args>` in the sandbox,
/// with stdout and stderr streamed to the job's log. A non-zero exit is
/// returned in [`Output`], not as an error.
pub fn terraform(
    cfg: &RunnerConfig,
    job: &Job,
    args: &[&str],
    resolved: &Resolved,
) -> Result<Output, Failure> {
    let launch = launch(cfg)?;
    run(cfg, launch, job, args, resolved, None, step_timeout(cfg))
}

/// One Terraform command. `plan` is the verified plan, already rewound;
/// the sandbox sees it, read-only, at `job_dir/plan.tfplan`.
fn run(
    cfg: &RunnerConfig,
    launch: Launch,
    job: &Job,
    args: &[&str],
    resolved: &Resolved,
    plan: Option<&File>,
    timeout: Duration,
) -> Result<Output, Failure> {
    check_job(cfg, job, resolved)?;
    // A fresh, empty CLI config every time, so no .terraformrc applies.
    let rc = job.dir.join(CLI_CONFIG_FILE);
    remove_if_present(&rc)
        .and_then(|()| write_private(&rc, b"", launch.owner()))
        .map_err(|_| refuse("cli_config_write_failed"))?;
    #[cfg(any(test, feature = "test-hooks"))]
    if launch.is_direct()
        && let Some(verified) = plan
    {
        // No bwrap to mount the verified bytes: copy them into place.
        materialize(verified, &job.dir.join(PLAN_FILE)).map_err(|_| refuse("plan_unreadable"))?;
    }
    let module = job.dir.join(CHECKOUT).join(job.module);
    let mut argv = vec![OsString::from(format!("-chdir={}", module.display()))];
    argv.extend(args.iter().map(OsString::from));
    let mut log =
        open_log(&cfg.log_dir, job.project, job.id).map_err(|_| refuse("log_unavailable"))?;
    writeln!(log, "== terraform {}", args.join(" ")).map_err(|_| refuse("log_unavailable"))?;
    let plan_fd = plan
        .map(|f| fd_above_stdio(f).map_err(|_| refuse("plan_unreadable")))
        .transpose()?;
    let env = terraform_env(cfg, job, resolved);
    let cmd = command(
        cfg,
        launch,
        job.dir,
        &cfg.terraform,
        &argv,
        &env,
        plan_fd.as_ref().map(|f| f.as_raw_fd()),
    );
    drop(env);
    run_streaming(cmd, &mut log, timeout)
}

/// A close-on-exec duplicate of `f` numbered 3 or above. If the runner
/// started with one of fds 0-2 closed, the plan could otherwise sit on a
/// standard stream number, which the child's stdio setup would replace.
fn fd_above_stdio(f: &File) -> io::Result<OwnedFd> {
    // SAFETY: fcntl on a descriptor we hold open; the result is a new
    // descriptor that nothing else owns.
    let fd = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just created and is owned only here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(any(test, feature = "test-hooks"))]
fn materialize(verified: &File, dest: &Path) -> io::Result<()> {
    remove_if_present(dest)?;
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dest)?;
    io::copy(&mut &*verified, &mut out)?;
    Ok(())
}

// ---------------------------------------------------------------------
// Files

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Writes a new 0600 file for Terraform to read, owned by `owner`.
fn write_private(path: &Path, bytes: &[u8], owner: Option<(u32, u32)>) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
    }
    f.write_all(bytes)?;
    f.sync_all()
}

/// Opens a regular file for reading without following a symlink or
/// blocking on a FIFO, and checks the type on the open descriptor.
fn open_regular(path: &Path, follow: bool) -> io::Result<File> {
    let mut flags = libc::O_NONBLOCK;
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
    if f.metadata()?.is_file() {
        Ok(f)
    } else {
        Err(io::Error::other("not a regular file"))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The SHA-256 of everything readable from `f`.
fn hash_reader(mut f: impl Read) -> io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn hash_file(path: &Path, follow: bool) -> io::Result<String> {
    hash_reader(open_regular(path, follow)?)
}

/// An HCL quoted string: `\`, `"`, newline, return and tab escaped, other
/// control characters as `\uNNNN`, and `${` and `%{` doubled so no value
/// is read as a template.
fn hcl_string(s: &str) -> String {
    let mut out = String::from("\"");
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' | '%' if chars.peek() == Some(&'{') => {
                out.push(c);
                out.push(c);
            }
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `backend.hcl` for the length of `init`: removed on drop, so an early
/// return or a panic still removes it.
struct BackendFile(Option<PathBuf>);

impl BackendFile {
    fn write(
        job: &Job,
        backend: &[(String, Secret)],
        owner: Option<(u32, u32)>,
    ) -> Result<BackendFile, Failure> {
        if backend.is_empty() {
            return Ok(BackendFile(None));
        }
        let text: String = backend
            .iter()
            .map(|(k, v)| format!("{k} = {}\n", hcl_string(v.expose())))
            .collect();
        let path = job.dir.join(BACKEND_FILE);
        write_private(&path, text.as_bytes(), owner).map_err(|_| refuse("backend_write_failed"))?;
        Ok(BackendFile(Some(path)))
    }
}

impl Drop for BackendFile {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

// ---------------------------------------------------------------------
// Plan and apply

/// The root-only copy of a job's plan:
/// `state_dir/projects/<project>/plans/<job>.tfplan`.
pub fn plan_copy_path(cfg: &RunnerConfig, job: &Job) -> Result<PathBuf, Failure> {
    let paths =
        ProjectPaths::new(&cfg.state_dir, job.project).map_err(|_| refuse("path_refused"))?;
    Ok(paths.dir().join("plans").join(format!("{}.tfplan", job.id)))
}

/// Deletes the job's root-only plan copy. Call it when the job ends
/// without an apply; [`apply`] deletes it itself.
pub fn discard_plan(cfg: &RunnerConfig, job: &Job) {
    if let Ok(p) = plan_copy_path(cfg, job) {
        let _ = remove_if_present(&p);
    }
}

/// Opens the root-only copy once, hashes it from that descriptor, and
/// returns it rewound: the bytes checked are the bytes Terraform gets.
fn open_verified(path: &Path, expected_sha256: &str) -> Result<File, Failure> {
    let changed = |_| refuse("plan_changed");
    let mut f = open_regular(path, false).map_err(changed)?;
    if hash_reader(&mut f).map_err(changed)? != expected_sha256 {
        return Err(refuse("plan_changed"));
    }
    f.seek(SeekFrom::Start(0)).map_err(changed)?;
    Ok(f)
}

/// Plans a job: writes the canonical manifest to `job_dir`, outside the
/// checkout, runs `init` and `plan`, copies the plan to the root-only
/// store, and runs `show` on that copy. Returns the summary, the copy's
/// path and its SHA-256. Backend config reaches Terraform through
/// `backend.hcl`, which exists only while `init` runs.
pub fn plan(
    cfg: &RunnerConfig,
    job: &Job,
    manifest: &Canonical,
    resolved: &Resolved,
) -> Result<(Summary, PathBuf, String), Failure> {
    let launch = launch(cfg)?;
    check_job(cfg, job, resolved)?;
    let timeout = step_timeout(cfg);
    let owner = launch.owner();
    let manifest_path = job.dir.join(MANIFEST_FILE);
    write_private(&manifest_path, manifest.0.as_bytes(), owner)
        .map_err(|_| refuse("manifest_write_failed"))?;

    let init = {
        let _backend = BackendFile::write(job, &resolved.backend, owner)?;
        run(
            cfg,
            launch,
            job,
            &["init", "-input=false"],
            resolved,
            None,
            timeout,
        )?
    };
    if !init.success() {
        return Err(categorize(&init.stdout, Phase::Init));
    }

    let job_plan = job.dir.join(PLAN_FILE);
    let out_arg = format!("-out={}", job_plan.display());
    let var_arg = format!("-var-file={}", manifest_path.display());
    let args = [
        "plan",
        "-json",
        "-input=false",
        "-lock-timeout=60s",
        &out_arg,
        &var_arg,
    ];
    let planned = run(cfg, launch, job, &args, resolved, None, timeout)?;
    if !planned.success() {
        return Err(categorize(&planned.stdout, Phase::Plan));
    }

    let mut bytes = Vec::new();
    open_regular(&job_plan, false)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(|_| refuse("plan_unreadable"))?;
    let copy = plan_copy_path(cfg, job)?;
    let stored = copy
        .parent()
        .map_or(Ok(()), |d| {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(d)
        })
        .and_then(|()| write_atomic(&copy, &bytes));
    if stored.is_err() {
        let _ = remove_if_present(&copy);
        return Err(refuse("plan_store_failed"));
    }
    let sha = hex(&Sha256::digest(&bytes));
    let shown = (|| {
        let verified = open_verified(&copy, &sha)?;
        let plan_arg = job_plan.display().to_string();
        let shown = run(
            cfg,
            launch,
            job,
            &["show", "-json", &plan_arg],
            resolved,
            Some(&verified),
            timeout,
        )?;
        if !shown.success() {
            return Err(categorize(&shown.stdout, Phase::Plan));
        }
        if shown.truncated {
            return Err(refuse("plan_too_large"));
        }
        summarize(&shown.stdout)
    })();
    match shown {
        Ok(summary) => Ok((summary, copy, sha)),
        Err(e) => {
            let _ = remove_if_present(&copy);
            Err(e)
        }
    }
}

/// Applies the job's root-only plan copy, refusing `plan_changed` unless
/// it hashes to `expected_sha256`. The descriptor that was hashed is the
/// one mounted for Terraform. The journal says `applying` before Terraform
/// starts and `done` with the result after it returns, so a crash in
/// between leaves the outcome visibly unknown. The copy is deleted when
/// this returns. The caller must have run `check_context` at claim.
pub fn apply(
    cfg: &RunnerConfig,
    job: &Job,
    plan_file: &Path,
    expected_sha256: &str,
    resolved: &Resolved,
    journal: &Journal,
) -> Result<(), Failure> {
    let launch = launch(cfg)?;
    check_job(cfg, job, resolved)?;
    if plan_file != plan_copy_path(cfg, job)? {
        return Err(refuse("path_refused"));
    }
    let result = (|| {
        let verified = open_verified(plan_file, expected_sha256)?;
        journal
            .begin(job.id)
            .map_err(|_| refuse("journal_write_failed"))?;
        let plan_arg = job.dir.join(PLAN_FILE).display().to_string();
        let args = [
            "apply",
            "-json",
            "-input=false",
            "-lock-timeout=60s",
            &plan_arg,
        ];
        let result = run(
            cfg,
            launch,
            job,
            &args,
            resolved,
            Some(&verified),
            step_timeout(cfg),
        )
        .and_then(|out| {
            if out.success() {
                Ok(())
            } else if out.code.is_none() {
                // Killed by a signal: how far it got is unknown.
                Err(refuse("terraform_crashed"))
            } else {
                Err(categorize(&out.stdout, Phase::Apply))
            }
        });
        let recorded = match &result {
            Ok(()) => "applied",
            Err(f) => f.category.as_str(),
        };
        // If this write fails the journal still says `applying`, and the
        // next start reports the outcome as unknown: wrong in the safe
        // direction.
        if journal.end(job.id, recorded).is_err() {
            eprintln!("shoephone-runner: journal_write_failed for job {}", job.id);
        }
        result
    })();
    let _ = remove_if_present(plan_file);
    result
}

// ---------------------------------------------------------------------
// Workers and their files

/// How long the review worker may run before its process group is killed.
const REVIEW_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Who must own a Terraform job directory: `terraform_user`, or `None`
/// when the tests run without the sandbox.
pub fn terraform_owner(cfg: &RunnerConfig) -> Result<Option<(u32, u32)>, Failure> {
    Ok(launch(cfg)?.owner())
}

/// Who the review worker runs as and who owns its job directory:
/// `review_user`, or `None` when the tests run without the sandbox.
pub fn review_owner(cfg: &RunnerConfig) -> Result<Option<(u32, u32)>, Failure> {
    sandbox::worker_ids(&cfg.review_user)
}

/// Gives `dir` and everything under it to `owner`, without following a
/// symlink. Nothing to do when `owner` is `None`.
pub fn hand_over(dir: &Path, owner: Option<(u32, u32)>) -> Result<(), Failure> {
    fn walk(p: &Path, uid: u32, gid: u32) -> io::Result<()> {
        std::os::unix::fs::lchown(p, Some(uid), Some(gid))?;
        if fs::symlink_metadata(p)?.is_dir() {
            for entry in fs::read_dir(p)? {
                walk(&entry?.path(), uid, gid)?;
            }
        }
        Ok(())
    }
    match owner {
        None => Ok(()),
        Some((uid, gid)) => walk(dir, uid, gid).map_err(|_| refuse("job_dir_unavailable")),
    }
}

/// Test-only stand-ins for a compromised review worker, by job directory
/// prefix.
#[cfg(any(test, feature = "test-hooks"))]
#[allow(clippy::type_complexity)]
static REVIEW_TAMPER: std::sync::Mutex<Vec<(PathBuf, fn(&Path))>> =
    std::sync::Mutex::new(Vec::new());

/// For integration tests only: after the in-process review worker runs in
/// a job directory under `under`, call `tamper` on that directory, as a
/// worker that lies about its review would. Exists only with `test-hooks`.
#[cfg(any(test, feature = "test-hooks"))]
pub fn test_hooks_tamper_review(under: &Path, tamper: fn(&Path)) {
    REVIEW_TAMPER
        .lock()
        .expect("tamper list")
        .push((under.to_path_buf(), tamper));
}

/// Runs `shoephone-runner review-worker <job_dir>` as `review_user`, with
/// no credentials and a cleared environment, and waits up to ten minutes.
/// The worker's verdict is in `job_dir/review.json`; this returns an error
/// only when the worker could not be run or ran out of time. When the
/// tests run without the sandbox, the worker runs in this process.
pub fn run_review_worker(cfg: &RunnerConfig, job_dir: &Path) -> Result<(), Failure> {
    let Some((uid, gid)) = review_owner(cfg)? else {
        // A refusal is recorded in review.json, which the caller reads.
        let _ = crate::runner::review::review_worker(job_dir);
        #[cfg(any(test, feature = "test-hooks"))]
        for (under, tamper) in REVIEW_TAMPER.lock().expect("tamper list").iter() {
            if job_dir.starts_with(under) {
                tamper(job_dir);
            }
        }
        return Ok(());
    };
    let program = std::env::current_exe().map_err(|_| refuse("review_unavailable"))?;
    let mut child = sandbox::review_command(&program, job_dir, uid, gid)
        .spawn()
        .map_err(|_| refuse("review_unavailable"))?;
    let deadline = std::time::Instant::now() + REVIEW_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                secret::kill_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse("review_timeout"));
            }
        }
    }
}

// ---------------------------------------------------------------------
// Pinned context

/// Every entry under `dir`, by relative path, without following symlinks:
/// a file's hash, a symlink's target text, or a directory marker.
fn plugin_entries(dir: &Path, rel: &str, out: &mut BTreeMap<String, String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("non-UTF-8 name"))?;
        let path = format!("{rel}{name}");
        let t = entry.file_type()?;
        if t.is_dir() {
            out.insert(path.clone(), "dir".into());
            plugin_entries(&entry.path(), &format!("{path}/"), out)?;
        } else if t.is_symlink() {
            let target = fs::read_link(entry.path())?;
            out.insert(path, format!("symlink {}", target.display()));
        } else if t.is_file() {
            out.insert(path, format!("file {}", hash_file(&entry.path(), false)?));
        } else {
            out.insert(path, "other".into());
        }
    }
    Ok(())
}

fn sources_toml(map: &BTreeMap<String, Source>) -> toml::Value {
    let mut t = toml::Table::new();
    for (k, s) in map {
        let mut one = toml::Table::new();
        match s {
            Source::Value(v) => one.insert("value".into(), v.clone().into()),
            Source::Secret(r) => one.insert("secret".into(), r.clone().into()),
        };
        t.insert(k.clone(), one.into());
    }
    t.into()
}

/// The project's config as TOML with every key in sorted order.
fn project_toml(p: &ProjectConfig) -> String {
    let mut t = toml::Table::new();
    t.insert("backend_config".into(), sources_toml(&p.backend_config));
    t.insert("env".into(), sources_toml(&p.env));
    t.insert("path".into(), p.path.clone().into());
    t.insert("schema_file".into(), p.schema_file.clone().into());
    t.insert(
        "terraform_version".into(),
        p.terraform_version.clone().into(),
    );
    t.insert("variables".into(), sources_toml(&p.variables));
    toml::to_string(&t).expect("a table of strings serializes")
}

/// The SHA-256 over what a plan was made with: the runner's policy
/// version, the Terraform binary, every entry in `plugin_dir`, and the
/// project's config (secret references, never values). Recorded with the
/// plan and recomputed at claim.
pub fn context_digest(cfg: &RunnerConfig, project: &ProjectConfig) -> Result<String, Failure> {
    let unavailable = |_| refuse("context_unavailable");
    let terraform = hash_file(&cfg.terraform, true).map_err(unavailable)?;
    let mut plugins = BTreeMap::new();
    plugin_entries(&cfg.plugin_dir, "", &mut plugins).map_err(unavailable)?;
    let mut h = Sha256::new();
    let mut field = |label: &str, value: &str| {
        h.update(format!("{label} {}\n", value.len()));
        h.update(value);
        h.update("\n");
    };
    field("context", "shoephone-runner-context-v1");
    field("policy_version", &POLICY_VERSION.to_string());
    field("terraform", &terraform);
    for (path, what) in &plugins {
        field("plugin", &format!("{path}\n{what}"));
    }
    field("project", &project_toml(project));
    Ok(hex(&h.finalize()))
}

/// Refuses `context_changed` when the context differs from the digest
/// recorded with the plan. Run it at claim, before [`apply`].
pub fn check_context(
    cfg: &RunnerConfig,
    project: &ProjectConfig,
    recorded: &str,
) -> Result<(), Failure> {
    if context_digest(cfg, project)? == recorded {
        Ok(())
    } else {
        Err(refuse("context_changed"))
    }
}

#[cfg(test)]
mod tests;
