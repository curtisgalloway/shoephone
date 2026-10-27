// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The executor. The root process resolves a project's secret references
//! with `secret_command`, then runs Terraform as `terraform_user` inside a
//! bubblewrap sandbox that sees only the job directory, the Terraform
//! binary, the plugin directory and the system files TLS and DNS need.
//! Full output goes to a root-only log; what comes back is an exit code and
//! the `-json` stream, which only [`categorize`] and [`summarize`] read.
//!
//! A job directory looks like this (`job_dir` must be owned by
//! `terraform_user` and reachable by it):
//!
//! ```text
//! job_dir/
//!   checkout/<project path>/   the execution input, copied by the loop
//!   manifest.tfvars.json       the Canonical manifest, written here
//!   backend.hcl                backend config, present only during init
//!   plan.tfplan                the saved plan
//! ```

use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use ssh_key::sha2::{Digest, Sha256};

use crate::job::Failure;
use crate::runner::POLICY_VERSION;
use crate::runner::config::{ProjectConfig, RunnerConfig, Source};
use crate::runner::journal::Journal;
use crate::runner::plan::{Phase, Summary, categorize, summarize};
use crate::runner::schema::Canonical;

/// Where the execution input sits inside a job directory.
pub const CHECKOUT: &str = "checkout";
pub const MANIFEST_FILE: &str = "manifest.tfvars.json";
pub const BACKEND_FILE: &str = "backend.hcl";
pub const PLAN_FILE: &str = "plan.tfplan";

const SECRET_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SECRET_BYTES: usize = 64 * 1024;
const SECRET_PATH: &str = "/usr/bin:/bin";

/// Names a project's `env` may not set, because the executor sets them.
const RESERVED_ENV: [&str; 5] = [
    "HOME",
    "TF_IN_AUTOMATION",
    "TF_INPUT",
    "TF_PLUGIN_CACHE_DIR",
    "TF_DATA_DIR",
];
const RESERVED_ENV_PREFIXES: [&str; 2] = ["TF_CLI_ARGS", "TF_VAR_"];

fn refuse(category: &str) -> Failure {
    Failure {
        category: category.to_string(),
        addresses: Vec::new(),
        detail: None,
    }
}

// ---------------------------------------------------------------------
// Resolved values

/// A resolved value. `Debug` prints `[redacted]`; there is no `Display`
/// and no `Serialize`, so a value leaves only through [`Secret::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A project's values, resolved in the root process. Every value is held
/// as a [`Secret`], including plain config values, so none prints.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub env: Vec<(String, Secret)>,
    pub tf_vars: Vec<(String, Secret)>,
    pub backend: Vec<(String, Secret)>,
    /// The values that came from `secret_command`, for masking any text
    /// that might leave the runner.
    pub masks: Vec<Secret>,
}

/// `^[A-Za-z_][A-Za-z0-9_]*$`, with `-` allowed after the first byte when
/// `dash`.
fn identifier(name: &str, dash: bool) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || (dash && b == b'-'))
}

fn env_name_allowed(name: &str) -> bool {
    identifier(name, false)
        && !RESERVED_ENV.contains(&name)
        && !RESERVED_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Resolves every value the project supplies. Each distinct secret
/// reference runs `secret_command` once. Run it in the root process only;
/// it is the one place secrets enter the runner.
pub fn resolve(cfg: &RunnerConfig, project: &ProjectConfig) -> Result<Resolved, Failure> {
    if !project.env.keys().all(|n| env_name_allowed(n)) {
        return Err(refuse("env_name_refused"));
    }
    if !project.variables.keys().all(|n| identifier(n, true)) {
        return Err(refuse("variable_name_refused"));
    }
    if !project.backend_config.keys().all(|n| identifier(n, true)) {
        return Err(refuse("backend_config_refused"));
    }
    let extra: Vec<(String, OsString)> = cfg
        .secret_env
        .iter()
        .filter_map(|n| std::env::var_os(n).map(|v| (n.clone(), v)))
        .collect();
    let mut cache: BTreeMap<String, Secret> = BTreeMap::new();
    let mut all = |map: &BTreeMap<String, Source>| -> Result<Vec<(String, Secret)>, Failure> {
        let mut out = Vec::new();
        for (name, source) in map {
            let value = match source {
                Source::Value(v) => Secret(v.clone()),
                Source::Secret(reference) => match cache.get(reference.as_str()) {
                    Some(s) => s.clone(),
                    None => {
                        let s = run_secret(&cfg.secret_command, reference, &extra, SECRET_TIMEOUT)?;
                        cache.insert(reference.clone(), s.clone());
                        s
                    }
                },
            };
            out.push((name.clone(), value));
        }
        Ok(out)
    };
    let env = all(&project.env)?;
    let tf_vars = all(&project.variables)?;
    let backend = all(&project.backend_config)?;
    let masks = cache.into_values().collect();
    Ok(Resolved {
        env,
        tf_vars,
        backend,
        masks,
    })
}

/// Kills the child's whole process group, then reaps the child.
fn kill_group(child: &mut std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: kill has no memory preconditions; the child leads its
        // own process group (process_group(0)), so -pid names only it.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Runs `argv` with `reference` appended, in an environment of only
/// `PATH=/usr/bin:/bin` and `extra_env`, stdin and stderr closed. The
/// value is stdout with one trailing newline removed. Any failure is
/// `secret_unavailable` with nothing else: no reference, no stderr.
fn run_secret(
    argv: &[String],
    reference: &str,
    extra_env: &[(String, OsString)],
    timeout: Duration,
) -> Result<Secret, Failure> {
    let unavailable = || refuse("secret_unavailable");
    let (program, args) = argv.split_first().ok_or_else(unavailable)?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .arg(reference)
        .env_clear()
        .env("PATH", SECRET_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|_| unavailable())?;
    let Some(mut stdout) = child.stdout.take() else {
        kill_group(&mut child);
        return Err(unavailable());
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let read = (&mut stdout)
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut buf);
        let _ = tx.send(read.map(|_| buf));
    });
    let deadline = Instant::now() + timeout;
    // The reader ends at EOF or at the cap. A grandchild holding stdout
    // open keeps it waiting until the deadline, then the group is killed.
    let bytes = match rx.recv_timeout(timeout) {
        Ok(Ok(b)) if b.len() <= MAX_SECRET_BYTES => b,
        _ => {
            kill_group(&mut child);
            return Err(unavailable());
        }
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                kill_group(&mut child);
                return Err(unavailable());
            }
        }
    };
    if !status.success() {
        return Err(unavailable());
    }
    let mut text = String::from_utf8(bytes).map_err(|_| unavailable())?;
    if text.ends_with('\n') {
        text.pop();
    }
    if text.is_empty() || text.contains('\0') {
        return Err(unavailable());
    }
    Ok(Secret(text))
}

// ---------------------------------------------------------------------
// Launching Terraform

/// One job's run of Terraform.
#[derive(Debug, Clone, Copy)]
pub struct Job<'a> {
    /// The project name, which names the log directory.
    pub project: &'a str,
    pub id: u64,
    /// The job directory, absolute.
    pub dir: &'a Path,
    /// The project's path inside `checkout/` (the root module).
    pub module: &'a str,
}

/// A Terraform step's result: its exit code and stdout, the `-json`
/// stream. Stdout can hold anything Terraform printed, so `Debug` shows
/// only the code, and the text goes only to [`categorize`] or
/// [`summarize`].
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
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
            .finish_non_exhaustive()
    }
}

/// How Terraform is started. Release builds have only `Sandboxed`: the
/// other variants, and the switch that selects them, exist under
/// `cfg(test)` alone, so a deployed binary contains no way to run
/// Terraform outside bubblewrap or as root.
#[derive(Debug, Clone, Copy)]
enum Launch {
    /// bwrap as `terraform_user`. The only variant outside `cfg(test)`.
    Sandboxed { uid: u32, gid: u32 },
    /// Terraform run directly as the test user, without bwrap.
    #[cfg(test)]
    Direct,
    /// bwrap as the test user, for the Linux-only sandbox check.
    #[cfg(test)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    BwrapAsSelf,
}

impl Launch {
    /// Who must own the files the root process writes for Terraform, and
    /// who Terraform runs as.
    fn owner(self) -> Option<(u32, u32)> {
        match self {
            Launch::Sandboxed { uid, gid } => Some((uid, gid)),
            #[cfg(test)]
            _ => None,
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Set by a test on its own thread. There is no environment variable
    /// and no release-build equivalent.
    static TEST_LAUNCH: std::cell::Cell<Option<Launch>> = const { std::cell::Cell::new(None) };
}

/// The uid and gid of `name`, from the password database.
fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let cname = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: passwd is plain data; getpwnam_r fills it, pointing into buf.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and buf.len() is its size.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    (rc == 0 && !result.is_null()).then_some((pwd.pw_uid, pwd.pw_gid))
}

fn launch(cfg: &RunnerConfig) -> Result<Launch, Failure> {
    // The only bypass. `cfg(test)` code is absent from release builds.
    #[cfg(test)]
    if let Some(l) = TEST_LAUNCH.with(|c| c.get()) {
        return Ok(l);
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(refuse("sandbox_unavailable"));
    }
    match lookup_user(&cfg.terraform_user) {
        Some((uid, gid)) if uid != 0 && gid != 0 => Ok(Launch::Sandboxed { uid, gid }),
        _ => Err(refuse("sandbox_unavailable")),
    }
}

/// Runs in the child after std has called setgid, setgroups(0) and setuid
/// (std ignores EPERM from setgroups, so this check is what makes the drop
/// certain): refuse to exec unless every id is the target and no
/// supplementary group is left.
fn verify_dropped(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: these only read the process credentials, and are
    // async-signal-safe, as a pre_exec closure requires.
    let dropped = unsafe {
        libc::getuid() == uid
            && libc::geteuid() == uid
            && libc::getgid() == gid
            && libc::getegid() == gid
            && libc::getgroups(0, std::ptr::null_mut()) == 0
    };
    if dropped {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }
}

/// The bwrap arguments before `--`. Nothing from the state dir, the
/// config, the key or the log dir is bound. Environment values are not
/// here: a bwrap argument is readable in /proc by every local user, so the
/// environment is set on the bwrap process itself (cleared first) and
/// bwrap passes it through. That is why there is no `--clearenv`.
fn bwrap_args(cfg: &RunnerConfig, job_dir: &Path) -> Vec<OsString> {
    let mut a: Vec<OsString> = [
        "--die-with-parent",
        "--unshare-all",
        "--share-net",
        "--new-session",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        "/usr",
        "/usr",
    ]
    .map(OsString::from)
    .into();
    for lib in ["/lib", "/lib64"] {
        match fs::symlink_metadata(lib) {
            Ok(m) if m.file_type().is_symlink() => {
                if let Ok(target) = fs::read_link(lib) {
                    a.extend(["--symlink".into(), target.into(), lib.into()]);
                }
            }
            Ok(_) => a.extend(["--ro-bind", lib, lib].map(OsString::from)),
            Err(_) => {}
        }
    }
    for etc in ["/etc/ssl", "/etc/resolv.conf"] {
        a.extend(["--ro-bind", etc, etc].map(OsString::from));
    }
    for ro in [&cfg.terraform, &cfg.plugin_dir] {
        a.extend(["--ro-bind".into(), ro.into(), ro.into()]);
    }
    a.extend(["--bind".into(), job_dir.into(), job_dir.into()]);
    a.extend(["--chdir".into(), job_dir.into()]);
    a
}

/// The command that runs `program args` for a job: under bwrap as
/// `terraform_user` in release builds. The environment is exactly `env`.
fn command(
    cfg: &RunnerConfig,
    launch: Launch,
    job_dir: &Path,
    program: &Path,
    args: &[OsString],
    env: &[(String, String)],
) -> Command {
    let bwrap = || {
        let mut c = Command::new(&cfg.bwrap);
        c.args(bwrap_args(cfg, job_dir))
            .arg("--")
            .arg(program)
            .args(args);
        c
    };
    let mut cmd = match launch {
        Launch::Sandboxed { .. } => bwrap(),
        #[cfg(test)]
        Launch::BwrapAsSelf => bwrap(),
        #[cfg(test)]
        Launch::Direct => {
            let mut c = Command::new(program);
            c.args(args).current_dir(job_dir);
            c
        }
    };
    cmd.env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((uid, gid)) = launch.owner() {
        cmd.uid(uid).gid(gid);
        // SAFETY: verify_dropped calls only async-signal-safe functions.
        unsafe {
            cmd.pre_exec(move || verify_dropped(uid, gid));
        }
    }
    cmd
}

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
        ("TF_CLI_ARGS_init".to_string(), init),
    ]);
    env
}

/// Runs `terraform -chdir=<job>/checkout/<module> <args>` in the sandbox,
/// with full stdout and stderr appended to the job's log. A non-zero exit
/// is returned in [`Output`], not as an error.
pub fn terraform(
    cfg: &RunnerConfig,
    job: &Job,
    args: &[&str],
    resolved: &Resolved,
) -> Result<Output, Failure> {
    let launch = launch(cfg)?;
    run(cfg, launch, job, args, resolved)
}

fn run(
    cfg: &RunnerConfig,
    launch: Launch,
    job: &Job,
    args: &[&str],
    resolved: &Resolved,
) -> Result<Output, Failure> {
    check_job(cfg, job, resolved)?;
    let module = job.dir.join(CHECKOUT).join(job.module);
    let mut argv = vec![OsString::from(format!("-chdir={}", module.display()))];
    argv.extend(args.iter().map(OsString::from));
    let mut log =
        open_log(&cfg.log_dir, job.project, job.id).map_err(|_| refuse("log_unavailable"))?;
    let env = terraform_env(cfg, job, resolved);
    let out = command(cfg, launch, job.dir, &cfg.terraform, &argv, &env)
        .output()
        .map_err(|_| refuse("terraform_unavailable"))?;
    drop(env);
    // Terraform has already run, so a log failure must not change the
    // result. It is reported without any of the text.
    if write_log(&mut log, args, &out).is_err() {
        eprintln!("shoephone-runner: log_write_failed for job {}", job.id);
    }
    Ok(Output {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    })
}

// ---------------------------------------------------------------------
// Logs

/// A directory that is not a symlink; created 0700 when missing.
fn private_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::other("not a directory")),
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
fn open_log(log_dir: &Path, project: &str, job: u64) -> io::Result<File> {
    if !single_component(project) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    private_dir(log_dir)?;
    let dir = log_dir.join(project);
    private_dir(&dir)?;
    let path = dir.join(format!("{job}.log"));
    let mut opts = OpenOptions::new();
    opts.append(true).custom_flags(libc::O_NOFOLLOW);
    match opts.clone().create_new(true).mode(0o600).open(&path) {
        Ok(f) => {
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            Ok(f)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let f = opts.open(&path)?;
            let m = f.metadata()?;
            // SAFETY: geteuid has no preconditions.
            let ours = m.uid() == unsafe { libc::geteuid() };
            if m.is_file() && ours && m.mode() & 0o077 == 0 {
                Ok(f)
            } else {
                Err(io::Error::other("unexpected log file"))
            }
        }
        Err(e) => Err(e),
    }
}

fn write_log(log: &mut File, args: &[&str], out: &std::process::Output) -> io::Result<()> {
    let code = out
        .status
        .code()
        .map_or("signal".to_string(), |c| c.to_string());
    writeln!(log, "== terraform {} (exit {code})", args.join(" "))?;
    log.write_all(b"-- stdout\n")?;
    log.write_all(&out.stdout)?;
    log.write_all(b"\n-- stderr\n")?;
    log.write_all(&out.stderr)?;
    log.write_all(b"\n")?;
    log.sync_all()
}

/// Deletes regular files older than `days` in each project directory
/// under `log_dir`. Symlinks are never followed or removed. Returns how
/// many files went. Call it at startup.
pub fn prune_logs(log_dir: &Path, days: u32) -> io::Result<usize> {
    let cutoff = SystemTime::now() - Duration::from_secs(u64::from(days) * 86_400);
    let projects = match fs::read_dir(log_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0;
    for project in projects {
        let project = project?;
        if !project.file_type()?.is_dir() {
            continue;
        }
        for entry in fs::read_dir(project.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            if fs::symlink_metadata(entry.path())?.modified()? < cutoff {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------
// Plan and apply

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

/// The SHA-256 of a regular file. A symlink is refused unless `follow`.
fn hash_file(path: &Path, follow: bool) -> io::Result<String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    if !follow {
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

fn backend_hcl(backend: &[(String, Secret)]) -> String {
    backend
        .iter()
        .map(|(k, v)| format!("{k} = {}\n", hcl_string(v.expose())))
        .collect()
}

/// Plans a job: writes the canonical manifest to `job_dir`, outside the
/// checkout, runs `init`, `plan` and `show`, and returns the summary, the
/// plan file and its SHA-256. Backend config reaches Terraform through
/// `backend.hcl`, which exists only while `init` runs.
pub fn plan(
    cfg: &RunnerConfig,
    job: &Job,
    manifest: &Canonical,
    resolved: &Resolved,
) -> Result<(Summary, PathBuf, String), Failure> {
    let launch = launch(cfg)?;
    check_job(cfg, job, resolved)?;
    let owner = launch.owner();
    let manifest_path = job.dir.join(MANIFEST_FILE);
    write_private(&manifest_path, manifest.0.as_bytes(), owner)
        .map_err(|_| refuse("manifest_write_failed"))?;

    let backend_path = job.dir.join(BACKEND_FILE);
    if !resolved.backend.is_empty() {
        write_private(
            &backend_path,
            backend_hcl(&resolved.backend).as_bytes(),
            owner,
        )
        .map_err(|_| refuse("backend_write_failed"))?;
    }
    let init = run(cfg, launch, job, &["init", "-input=false"], resolved);
    if !resolved.backend.is_empty() {
        let _ = fs::remove_file(&backend_path);
    }
    let init = init?;
    if !init.success() {
        return Err(categorize(&init.stdout, Phase::Init));
    }

    let plan_path = job.dir.join(PLAN_FILE);
    let out_arg = format!("-out={}", plan_path.display());
    let var_arg = format!("-var-file={}", manifest_path.display());
    let planned = run(
        cfg,
        launch,
        job,
        &[
            "plan",
            "-json",
            "-input=false",
            "-lock-timeout=60s",
            &out_arg,
            &var_arg,
        ],
        resolved,
    )?;
    if !planned.success() {
        return Err(categorize(&planned.stdout, Phase::Plan));
    }
    let plan_hash = || hash_file(&plan_path, false).map_err(|_| refuse("plan_unreadable"));
    let sha = plan_hash()?;
    let plan_arg = plan_path.display().to_string();
    let shown = run(cfg, launch, job, &["show", "-json", &plan_arg], resolved)?;
    if !shown.success() {
        return Err(categorize(&shown.stdout, Phase::Plan));
    }
    // The summary must describe the file that was hashed.
    if plan_hash()? != sha {
        return Err(refuse("plan_changed"));
    }
    let summary = summarize(&shown.stdout)?;
    Ok((summary, plan_path, sha))
}

/// Applies a saved plan, refusing `plan_changed` unless the file still
/// hashes to `expected_sha256`. The journal says `applying` before
/// Terraform starts and `done` with the result after it returns, so a
/// crash in between leaves the outcome visibly unknown.
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
    if !plain_path(plan_file) {
        return Err(refuse("path_refused"));
    }
    match hash_file(plan_file, false) {
        Ok(sha) if sha == expected_sha256 => {}
        _ => return Err(refuse("plan_changed")),
    }
    journal
        .begin(job.id)
        .map_err(|_| refuse("journal_write_failed"))?;
    let plan_arg = plan_file.display().to_string();
    let result = run(
        cfg,
        launch,
        job,
        &[
            "apply",
            "-json",
            "-input=false",
            "-lock-timeout=60s",
            &plan_arg,
        ],
        resolved,
    )
    .and_then(|out| {
        if out.success() {
            Ok(())
        } else {
            Err(categorize(&out.stdout, Phase::Apply))
        }
    });
    let recorded = match &result {
        Ok(()) => "applied",
        Err(f) => f.category.as_str(),
    };
    // If this write fails the journal still says `applying`, and the next
    // start reports the outcome as unknown: wrong in the safe direction.
    if journal.end(job.id, recorded).is_err() {
        eprintln!("shoephone-runner: journal_write_failed for job {}", job.id);
    }
    result
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
