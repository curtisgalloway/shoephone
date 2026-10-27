// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! Starting Terraform: bubblewrap as `terraform_user`, with output
//! streamed to the log and a timeout that kills the whole tree.

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use super::secret::kill_group;
use super::{Output, PLAN_FILE, refuse};
use crate::job::Failure;
use crate::runner::config::RunnerConfig;

/// How much of Terraform's stdout (the `-json` stream) is kept in memory.
/// The log keeps all of it.
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;

/// System paths bound read-only when present: CA bundles (Debian, and
/// Fedora/RHEL) and the resolver config.
const ETC_BINDS: [&str; 3] = ["/etc/ssl", "/etc/pki", "/etc/resolv.conf"];
/// The ones whose absence is worth a startup warning.
const ETC_EXPECTED: [&str; 2] = ["/etc/ssl", "/etc/resolv.conf"];

/// How Terraform is started. A deployed build has only `Sandboxed`. The
/// other variants and the switches that select them exist only under
/// `cfg(test)` or the `test-hooks` feature, and `shoephone-runner` refuses
/// to start when built with `test-hooks` (see RUNNER.md).
#[derive(Debug, Clone, Copy)]
pub(super) enum Launch {
    /// bwrap as `terraform_user`.
    Sandboxed { uid: u32, gid: u32 },
    /// Terraform run directly as the current user, without bwrap.
    #[cfg(any(test, feature = "test-hooks"))]
    Direct,
    /// bwrap as the current user, for the Linux-only sandbox check.
    #[cfg(any(test, feature = "test-hooks"))]
    #[allow(dead_code)]
    BwrapAsSelf,
}

impl Launch {
    /// Who must own the files the root process writes for Terraform, and
    /// who Terraform runs as.
    pub(super) fn owner(self) -> Option<(u32, u32)> {
        match self {
            Launch::Sandboxed { uid, gid } => Some((uid, gid)),
            #[cfg(any(test, feature = "test-hooks"))]
            _ => None,
        }
    }

    fn uses_bwrap(self) -> bool {
        match self {
            Launch::Sandboxed { .. } => true,
            #[cfg(any(test, feature = "test-hooks"))]
            Launch::BwrapAsSelf => true,
            #[cfg(any(test, feature = "test-hooks"))]
            Launch::Direct => false,
        }
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn is_direct(self) -> bool {
        matches!(self, Launch::Direct)
    }
}

#[cfg(test)]
thread_local! {
    /// Set by a unit test on its own thread.
    pub(super) static TEST_LAUNCH: std::cell::Cell<Option<Launch>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(any(test, feature = "test-hooks"))]
static TEST_HOOKS_NO_SANDBOX: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// For integration tests only: run Terraform directly, without bwrap or a
/// uid drop, for the rest of this process. Exists only with `test-hooks`.
#[cfg(any(test, feature = "test-hooks"))]
pub fn test_hooks_run_without_sandbox() {
    TEST_HOOKS_NO_SANDBOX.store(true, std::sync::atomic::Ordering::SeqCst);
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

pub(super) fn launch(cfg: &RunnerConfig) -> Result<Launch, Failure> {
    // The only bypasses, both absent from a deployed build.
    #[cfg(test)]
    if let Some(l) = TEST_LAUNCH.with(|c| c.get()) {
        return Ok(l);
    }
    #[cfg(any(test, feature = "test-hooks"))]
    if TEST_HOOKS_NO_SANDBOX.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(Launch::Direct);
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

/// The uid and gid a worker runs as and owns its job directory as: `user`
/// from the password database, never root. `None` when the tests run
/// without the sandbox, where every worker is the current user.
pub(super) fn worker_ids(user: &str) -> Result<Option<(u32, u32)>, Failure> {
    #[cfg(test)]
    if let Some(l) = TEST_LAUNCH.with(|c| c.get()) {
        return Ok(l.owner());
    }
    #[cfg(any(test, feature = "test-hooks"))]
    if TEST_HOOKS_NO_SANDBOX.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(None);
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(refuse("sandbox_unavailable"));
    }
    match lookup_user(user) {
        Some((uid, gid)) if uid != 0 && gid != 0 => Ok(Some((uid, gid))),
        _ => Err(refuse("sandbox_unavailable")),
    }
}

/// `program review-worker <job_dir>` as `uid`/`gid`, with an environment
/// of only `PATH=/usr/bin:/bin`, no stdin and no stdout, in its own
/// process group. The child refuses to exec unless the drop took.
pub(super) fn review_command(program: &Path, job_dir: &Path, uid: u32, gid: u32) -> Command {
    let mut cmd = Command::new(program);
    cmd.arg("review-worker")
        .arg(job_dir)
        .current_dir(job_dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .uid(uid)
        .gid(gid);
    // SAFETY: the closure calls only async-signal-safe functions and does
    // not allocate.
    unsafe {
        cmd.pre_exec(move || verify_dropped(uid, gid));
    }
    cmd
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

/// True for `bubblewrap X.Y...` at 0.8 or later, which has
/// `--disable-userns`.
pub(super) fn version_has_disable_userns(version: &str) -> bool {
    let Some(v) = version.split_whitespace().nth(1) else {
        return false;
    };
    let mut parts = v.split('.').map(|p| p.parse::<u32>().ok());
    match (parts.next().flatten(), parts.next().flatten()) {
        (Some(major), Some(minor)) => (major, minor) >= (0, 8),
        _ => false,
    }
}

static DISABLE_USERNS: OnceLock<bool> = OnceLock::new();

/// Whether this bwrap has `--disable-userns`, probed once per process.
fn disable_userns(bwrap: &Path) -> bool {
    *DISABLE_USERNS.get_or_init(|| {
        Command::new(bwrap)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some_and(|o| version_has_disable_userns(&String::from_utf8_lossy(&o.stdout)))
    })
}

/// The startup check: probes bwrap and warns on stderr about missing
/// system files Terraform needs for TLS and DNS. Returns the warnings.
pub fn preflight(cfg: &RunnerConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    if !disable_userns(&cfg.bwrap) {
        warnings.push(
            "bwrap lacks --disable-userns (needs 0.8 or later); the sandbox can create user namespaces"
                .to_string(),
        );
    }
    for p in ETC_EXPECTED {
        if !Path::new(p).exists() {
            warnings.push(format!(
                "{p} is missing; Terraform in the sandbox will lack it"
            ));
        }
    }
    for w in &warnings {
        eprintln!("shoephone-runner: warning: {w}");
    }
    warnings
}

/// The bwrap arguments before `--`. Nothing from the state dir, the
/// config, the key or the log dir is bound. `plan_fd` is the verified
/// plan, mounted read-only over `job_dir/plan.tfplan`. Environment values
/// are not here: a bwrap argument is readable in /proc by every local
/// user, so the environment is set on the bwrap process itself (cleared
/// first) and bwrap passes it through. That is why there is no
/// `--clearenv`.
pub(super) fn bwrap_args(
    cfg: &RunnerConfig,
    job_dir: &Path,
    plan_fd: Option<RawFd>,
) -> Vec<OsString> {
    let mut a: Vec<OsString> = [
        "--die-with-parent",
        "--unshare-all",
        "--share-net",
        "--new-session",
        "--cap-drop",
        "ALL",
    ]
    .map(OsString::from)
    .into();
    if disable_userns(&cfg.bwrap) {
        a.extend(["--unshare-user", "--disable-userns"].map(OsString::from));
    }
    a.extend(
        [
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
        .map(OsString::from),
    );
    for lib in ["/lib", "/lib64"] {
        match std::fs::symlink_metadata(lib) {
            Ok(m) if m.file_type().is_symlink() => {
                if let Ok(target) = std::fs::read_link(lib) {
                    a.extend(["--symlink".into(), target.into(), lib.into()]);
                }
            }
            Ok(_) => a.extend(["--ro-bind", lib, lib].map(OsString::from)),
            Err(_) => {}
        }
    }
    for etc in ETC_BINDS {
        if Path::new(etc).exists() {
            a.extend(["--ro-bind", etc, etc].map(OsString::from));
        }
    }
    for ro in [&cfg.terraform, &cfg.plugin_dir] {
        a.extend(["--ro-bind".into(), ro.into(), ro.into()]);
    }
    a.extend(["--bind".into(), job_dir.into(), job_dir.into()]);
    if let Some(fd) = plan_fd {
        a.extend([
            "--ro-bind-data".into(),
            fd.to_string().into(),
            job_dir.join(PLAN_FILE).into(),
        ]);
    }
    a.extend(["--chdir".into(), job_dir.into()]);
    a
}

/// The command that runs `program args` for a job: under bwrap as
/// `terraform_user` in a deployed build. The environment is exactly `env`.
/// Only `plan_fd` is inherited, by clearing its FD_CLOEXEC in the child.
pub(super) fn command(
    cfg: &RunnerConfig,
    launch: Launch,
    job_dir: &Path,
    program: &Path,
    args: &[OsString],
    env: &[(String, String)],
    plan_fd: Option<RawFd>,
) -> Command {
    let bwrap_fd = plan_fd.filter(|_| launch.uses_bwrap());
    let mut cmd = if launch.uses_bwrap() {
        let mut c = Command::new(&cfg.bwrap);
        c.args(bwrap_args(cfg, job_dir, bwrap_fd))
            .arg("--")
            .arg(program)
            .args(args);
        c
    } else {
        let mut c = Command::new(program);
        c.args(args).current_dir(job_dir);
        c
    };
    cmd.env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let owner = launch.owner();
    if let Some((uid, gid)) = owner {
        cmd.uid(uid).gid(gid);
    }
    if owner.is_some() || bwrap_fd.is_some() {
        // SAFETY: the closure calls only async-signal-safe functions
        // (getuid and friends, fcntl) and does not allocate.
        unsafe {
            cmd.pre_exec(move || {
                if let Some((uid, gid)) = owner {
                    verify_dropped(uid, gid)?;
                }
                if let Some(fd) = bwrap_fd
                    && libc::fcntl(fd, libc::F_SETFD, 0) == -1
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd
}

/// Runs `cmd`, writing stdout and stderr to `log` as they arrive and
/// keeping at most 16 MiB of stdout. Past `timeout` the whole process
/// group is killed (bwrap's `--die-with-parent` takes the sandbox with it)
/// and the result is `terraform_timeout`.
pub(super) fn run_streaming(
    mut cmd: Command,
    log: &mut File,
    timeout: Duration,
) -> Result<Output, Failure> {
    let mut child = cmd.spawn().map_err(|_| refuse("terraform_unavailable"))?;
    let pid = child.id();
    let deadline = Instant::now() + timeout;
    let kill = |child: &mut std::process::Child, log: &mut File| {
        kill_group(pid);
        let _ = child.kill();
        let _ = child.wait();
        let _ = writeln!(log, "\n== killed: timeout");
        refuse("terraform_timeout")
    };
    let (tx, rx) = mpsc::channel::<(bool, Option<Vec<u8>>)>();
    let pipes: [(bool, Option<Box<dyn Read + Send>>); 2] = [
        (true, child.stdout.take().map(|p| Box::new(p) as _)),
        (false, child.stderr.take().map(|p| Box::new(p) as _)),
    ];
    let mut open = 0;
    for (is_stdout, pipe) in pipes {
        let Some(mut pipe) = pipe else { continue };
        open += 1;
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send((is_stdout, Some(buf[..n].to_vec()))).is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = tx.send((is_stdout, None));
        });
    }
    drop(tx);
    let mut stdout = Vec::new();
    let mut truncated = false;
    let mut log_ok = true;
    while open > 0 {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok((is_stdout, Some(chunk))) => {
                log_ok = log_ok && log.write_all(&chunk).is_ok();
                // Once one chunk is dropped, keep none after it, so the
                // kept text is a prefix of the stream with no gap.
                if is_stdout && !truncated {
                    if stdout.len() + chunk.len() <= MAX_STDOUT_BYTES {
                        stdout.extend_from_slice(&chunk);
                    } else {
                        truncated = true;
                    }
                }
            }
            Ok((_, None)) => open -= 1,
            Err(RecvTimeoutError::Timeout) => return Err(kill(&mut child, log)),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => return Err(kill(&mut child, log)),
        }
    };
    let code = status.code();
    let shown = code.map_or("signal".to_string(), |c| c.to_string());
    log_ok = log_ok && writeln!(log, "\n== exit {shown}").is_ok() && log.sync_all().is_ok();
    // Terraform has already run, so a log failure must not change the
    // result. It is reported without any of the text.
    if !log_ok {
        eprintln!("shoephone-runner: log_write_failed");
    }
    Ok(Output {
        code,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        truncated,
    })
}
