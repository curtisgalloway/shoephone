// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The resolver: the one place secrets enter the runner. It runs in the
//! root process only.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::refuse;
use crate::job::Failure;
use crate::runner::config::{ProjectConfig, RunnerConfig, Source};

pub(super) const SECRET_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SECRET_BYTES: usize = 64 * 1024;
const SECRET_PATH: &str = "/usr/bin:/bin";

/// Names a project's `env` may not set: the executor sets them, or they
/// would change where Terraform reads config or writes logs.
const RESERVED_ENV: [&str; 10] = [
    "HOME",
    "TF_IN_AUTOMATION",
    "TF_INPUT",
    "TF_CLI_CONFIG_FILE",
    "TF_LOG",
    "TF_LOG_PATH",
    "TF_LOG_CORE",
    "TF_LOG_PROVIDER",
    "TF_PLUGIN_CACHE_DIR",
    "TF_DATA_DIR",
];
const RESERVED_ENV_PREFIXES: [&str; 2] = ["TF_CLI_ARGS", "TF_VAR_"];

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
pub(super) fn identifier(name: &str, dash: bool) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || (dash && b == b'-'))
}

pub(super) fn env_name_allowed(name: &str) -> bool {
    identifier(name, false)
        && !RESERVED_ENV.contains(&name)
        && !RESERVED_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Resolves every value the project supplies. Each distinct secret
/// reference runs `secret_command` once. Run it in the root process only.
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

/// SIGKILL to the process group led by `pid`.
pub(super) fn kill_group(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: kill has no memory preconditions; the child leads its
        // own process group (process_group(0)), so -pid names only it.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

#[cfg(target_os = "linux")]
fn info_pid(info: &libc::siginfo_t) -> libc::pid_t {
    // SAFETY: waitid filled the struct; si_pid reads its pid field.
    unsafe { info.si_pid() }
}

#[cfg(not(target_os = "linux"))]
fn info_pid(info: &libc::siginfo_t) -> libc::pid_t {
    info.si_pid
}

/// True once `pid` has exited. The child is left unreaped, so its pid and
/// process group id cannot be reused while the group is killed.
fn exited_unreaped(pid: u32) -> bool {
    // SAFETY: siginfo_t is plain data; zeroed means "nothing reported".
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: info is valid for writing; WNOWAIT leaves the child waitable.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    rc == 0 && info_pid(&info) != 0
}

/// Runs `argv` with `reference` appended, in an environment of only
/// `PATH=/usr/bin:/bin` and `extra_env`, stdin and stderr closed. The
/// value is stdout with one trailing newline removed. Any failure is
/// `secret_unavailable` with nothing else: no reference, no stderr.
pub(super) fn run_secret(
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
    let pid = child.id();
    let finish = |child: &mut std::process::Child| {
        kill_group(pid);
        child.wait()
    };
    let Some(mut stdout) = child.stdout.take() else {
        let _ = finish(&mut child);
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
    // The reader ends at EOF or at the cap, and is waited for only until
    // the deadline. A leftover process holding stdout open is killed with
    // the group.
    let bytes = match rx.recv_timeout(timeout) {
        Ok(Ok(b)) if b.len() <= MAX_SECRET_BYTES => b,
        _ => {
            let _ = finish(&mut child);
            return Err(unavailable());
        }
    };
    let mut exited = exited_unreaped(pid);
    while !exited && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
        exited = exited_unreaped(pid);
    }
    // Always: kill whatever the command left in its group, then reap.
    let status = finish(&mut child);
    match status {
        Ok(s) if exited && s.success() => {}
        _ => return Err(unavailable()),
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
