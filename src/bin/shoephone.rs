// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephone` — the grant CLI an agent session runs.
//!
//! Every path returns a [`Status`] rather than calling `process::exit`, so
//! the exit contract stays visible in the signatures. `--json` puts one
//! document on stdout and everything else on stderr.

use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::json;
use shoephone::api::{
    ApplyBody, JobReply, JobStatus, MAX_ARCHIVE_BYTES, MAX_MANIFEST_BYTES, RequestBody,
    RequestState, TrustBody,
};
use shoephone::client::{Client, Error};
use shoephone::exit::{SKILL, Status, VERSION};
use shoephone::session::Session;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--skill") {
        print!("{}", SKILL.replace("{{VERSION}}", VERSION));
        return Status::Ok.into();
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        if args.iter().any(|a| a == "--json") {
            println!("{}", json!({ "version": VERSION }));
        } else {
            println!("shoephone {VERSION}");
        }
        return Status::Ok.into();
    }
    run(&args).into()
}

struct Opts {
    json: bool,
    daemon: Option<String>,
    window: Option<u64>,
    reason: Option<String>,
    context: Option<String>,
    manifest: Option<String>,
    allow_destroy: bool,
    positional: Vec<String>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut opts = Opts {
        json: false,
        daemon: None,
        window: None,
        reason: None,
        context: None,
        manifest: None,
        allow_destroy: false,
        positional: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => opts.json = true,
            "--daemon" => opts.daemon = Some(it.next().ok_or("--daemon needs a URL")?.clone()),
            "--context" => {
                let v = it.next().ok_or("--context needs a URL")?;
                opts.context = Some(v.clone());
            }
            "--allow-destroy" => opts.allow_destroy = true,
            "--manifest" => {
                let v = it.next().ok_or("--manifest needs a file")?;
                opts.manifest = Some(v.clone());
            }
            "--reason" => {
                let v = it.next().ok_or("--reason needs text")?;
                opts.reason = Some(v.clone());
            }
            "--window" => {
                let v = it.next().ok_or("--window needs minutes")?;
                opts.window = Some(
                    v.parse()
                        .map_err(|_| format!("--window {v:?}: not a number"))?,
                );
            }
            s if s.starts_with("--") => return Err(format!("unknown flag {s}")),
            _ => opts.positional.push(a.clone()),
        }
    }
    Ok(opts)
}

/// `$XDG_CONFIG_HOME/shoephone/config.toml` (default `~/.config`), parsed;
/// `None` when it is absent or unreadable.
fn config_file() -> Option<toml::Table> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
        })?;
    let text = std::fs::read_to_string(base.join("shoephone/config.toml")).ok()?;
    text.parse().ok()
}

/// `--daemon`, else `$SHOEPHONE_DAEMON`, else `daemon = "..."` in the
/// config file.
fn daemon_url(opts: &Opts) -> Option<String> {
    if let Some(d) = &opts.daemon {
        return Some(d.clone());
    }
    if let Ok(d) = std::env::var("SHOEPHONE_DAEMON")
        && !d.is_empty()
    {
        return Some(d);
    }
    config_file()?.get("daemon")?.as_str().map(str::to_owned)
}

/// `agent = false` in the config file turns off ssh-agent entirely: the
/// certificate is only written beside the session key, where ssh finds it
/// through an `IdentityFile` line. For machines whose agent refuses keys
/// it did not create (the 1Password agent does). Default true.
fn use_agent() -> bool {
    config_file()
        .and_then(|t| t.get("agent")?.as_bool())
        .unwrap_or(true)
}

fn run(args: &[String]) -> Status {
    let opts = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("shoephone: {e}; try --skill");
            return Status::Usage;
        }
    };
    let verb = opts.positional.first().map(String::as_str);
    let host = opts.positional.get(1).map(String::as_str);
    match (verb, host) {
        (Some("doctor"), _) => doctor(&opts),
        (Some("status"), _) => status(&opts),
        (Some("request"), Some(h)) => request(&opts, h),
        (Some("renew"), Some(h)) => renew(&opts, h),
        (Some("disavow"), Some(h)) => disavow(&opts, h),
        (Some("trust"), Some(p)) => trust(&opts, p),
        (Some("apply"), Some(p)) => apply(&opts, p),
        (Some("request" | "renew" | "disavow"), None) => {
            eprintln!(
                "shoephone: {} needs a host; try --skill",
                verb.unwrap_or_default()
            );
            Status::Usage
        }
        (Some("trust" | "apply"), None) => {
            eprintln!(
                "shoephone: {} needs a project; try --skill",
                verb.unwrap_or_default()
            );
            Status::Usage
        }
        (Some(v), _) => {
            eprintln!("shoephone: unknown command `{v}`; try --skill");
            Status::Usage
        }
        (None, _) => {
            eprintln!("shoephone: a command is required; try --skill");
            Status::Usage
        }
    }
}

fn need_client(opts: &Opts) -> Result<Client, Status> {
    match daemon_url(opts) {
        Some(url) => Ok(Client::new(&url)),
        None => {
            eprintln!(
                "shoephone: no daemon configured; pass --daemon, set SHOEPHONE_DAEMON, or write daemon = \"https://...\" in ~/.config/shoephone/config.toml"
            );
            Err(Status::Precondition)
        }
    }
}

/// The session for one host: its own keypair and certificate, so approving
/// or disavowing this host never touches another host's.
fn need_session(host: &str) -> Result<Session, Status> {
    let dir = match Session::default_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("shoephone: {e}");
            return Err(Status::Precondition);
        }
    };
    match Session::for_host(dir, host) {
        Ok(s) => Ok(s),
        Err(e) => {
            eprintln!("shoephone: {e}");
            Err(Status::Usage)
        }
    }
}

fn fail(e: &Error) -> Status {
    eprintln!("shoephone: {e}");
    if let Error::Daemon { reply, .. } = e
        && let Some(until) = reply.until
    {
        eprintln!("shoephone: try again in {}", in_minutes(until));
    }
    e.status()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn in_minutes(unix: u64) -> String {
    let secs = unix.saturating_sub(now_unix());
    if secs < 90 {
        format!("{secs} s")
    } else {
        format!("{} min", secs.div_ceil(60))
    }
}

/// The link the phone shows for "open the session": `--context`, else the
/// Claude Code session this process runs in, which the harness names in
/// `CLAUDE_CODE_BRIDGE_SESSION_ID` and serves at claude.ai/code/<id>.
fn session_link() -> Option<String> {
    let id = std::env::var("CLAUDE_CODE_BRIDGE_SESSION_ID").ok()?;
    let id = id.trim();
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some(format!("https://claude.ai/code/{id}"))
}

fn requester() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        })
        .unwrap_or_default()
}

fn hostname_ok(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

fn doctor(opts: &Opts) -> Status {
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    let daemon = daemon_url(opts);
    match &daemon {
        Some(url) => notes.push(format!("daemon: {url}")),
        None => problems.push(
            "no daemon configured (--daemon, SHOEPHONE_DAEMON, or ~/.config/shoephone/config.toml)"
                .to_owned(),
        ),
    }
    let mut hosts = Vec::new();
    if let Some(url) = &daemon {
        match Client::new(url).status() {
            Ok(s) => {
                notes.push(format!(
                    "daemon reachable: shoephoned {}, CA {}",
                    s.version, s.ca_fingerprint
                ));
                if s.devices.is_empty() {
                    problems.push("no approver device is enrolled; nothing can be approved".into());
                } else {
                    notes.push(format!("approver devices: {}", s.devices.join(", ")));
                }
                if s.hosts.is_empty() {
                    problems.push("daemon signs for no hosts".into());
                } else {
                    notes.push(format!("hosts: {}", s.hosts.join(", ")));
                }
                for w in &s.windows {
                    notes.push(format!(
                        "open window: admin on {} for {}",
                        w.host,
                        in_minutes(w.ends_at)
                    ));
                }
                hosts = s.hosts;
            }
            Err(e) => problems.push(e.to_string()),
        }
    }
    if use_agent() {
        match Session::agent_reachable() {
            Ok(()) => notes.push("ssh-agent reachable".into()),
            Err(e) => problems.push(e),
        }
    } else {
        notes.push(
            "ssh-agent not used (agent = false); ssh reads the certificate beside the session key"
                .into(),
        );
    }
    match Session::default_dir() {
        Ok(dir) => {
            let hosts_dir = dir.join("hosts");
            if let Ok(entries) = std::fs::read_dir(&hosts_dir) {
                let mut names: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().is_dir())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect();
                names.sort();
                for name in names {
                    let key_path = hosts_dir.join(&name).join("session_ed25519");
                    if key_path.exists() {
                        notes.push(format!("session key for {name}: {}", key_path.display()));
                    }
                }
            }
            let legacy = dir.join("session_ed25519");
            if legacy.exists() {
                notes.push(format!(
                    "legacy shared session key at {} is no longer used; delete it when no host still relies on it",
                    legacy.display()
                ));
            }
        }
        Err(e) => problems.push(e),
    }
    let ok = problems.is_empty();
    if opts.json {
        println!(
            "{}",
            json!({ "ok": ok, "problems": problems, "notes": notes, "hosts": hosts })
        );
    } else {
        for n in &notes {
            eprintln!("ok: {n}");
        }
        for p in &problems {
            eprintln!("problem: {p}");
        }
        println!(
            "shoephone {VERSION}: {}",
            if ok {
                "ready"
            } else {
                "not ready; see problems above"
            }
        );
    }
    if ok { Status::Ok } else { Status::Precondition }
}

fn status(opts: &Opts) -> Status {
    let client = match need_client(opts) {
        Ok(c) => c,
        Err(s) => return s,
    };
    match client.status() {
        Ok(s) => {
            if opts.json {
                println!("{}", serde_json::to_string(&s).unwrap_or_default());
            } else {
                if s.windows.is_empty() && s.job.is_none() {
                    println!("no open windows");
                }
                for w in &s.windows {
                    println!(
                        "admin on {} for {} (key {})",
                        w.host,
                        in_minutes(w.ends_at),
                        w.fingerprint
                    );
                }
                if let Some(j) = &s.job {
                    println!(
                        "active job #{}: {} {} ({})",
                        j.id, j.kind, j.project, j.state
                    );
                }
            }
            Status::Ok
        }
        Err(e) => fail(&e),
    }
}

fn request(opts: &Opts, host: &str) -> Status {
    if !hostname_ok(host) {
        eprintln!("shoephone: {host:?} is not a hostname");
        return Status::Usage;
    }
    let Some(reason) = opts
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    else {
        eprintln!(
            "shoephone: --reason is required: say what the task is and why it needs admin; the person reads it before approving"
        );
        return Status::Usage;
    };
    let client = match need_client(opts) {
        Ok(c) => c,
        Err(s) => return s,
    };
    let session = match need_session(host) {
        Ok(s) => s,
        Err(s) => return s,
    };
    let public_key = match session.public_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("shoephone: {e}");
            return Status::Precondition;
        }
    };
    let reply = match client.request(&RequestBody {
        host: host.to_owned(),
        public_key: public_key.clone(),
        requester: requester(),
        reason: reason.to_owned(),
        context: opts.context.clone().or_else(session_link),
        window_minutes: opts.window,
    }) {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    eprintln!(
        "shoephone: requested admin on {} as {} for {}",
        reply.host,
        reply.principal,
        in_minutes(reply.ends_at)
    );
    eprintln!(
        "shoephone: match code {}  <- the person compares this with their phone",
        reply.match_code
    );
    if !opts.json {
        println!("match code: {}", reply.match_code);
    }
    eprintln!(
        "shoephone: waiting for a verdict (up to {} min)",
        reply.pending_ttl.div_ceil(60)
    );

    let deadline = Instant::now() + Duration::from_secs(reply.pending_ttl + 30);
    let ends_at = loop {
        std::thread::sleep(Duration::from_secs(2));
        match client.poll(reply.id) {
            Ok(RequestState::Pending) => {}
            Ok(RequestState::Approved { ends_at }) => break ends_at,
            Ok(RequestState::Gone) => {
                eprintln!("shoephone: not approved (declined or timed out); do not retry");
                if opts.json {
                    println!(
                        "{}",
                        json!({ "result": null, "empty": true, "reason": "not approved" })
                    );
                }
                return Status::AuthDenied;
            }
            Err(e) => return fail(&e),
        }
        if Instant::now() > deadline {
            eprintln!("shoephone: no verdict before the request expired; do not retry");
            if opts.json {
                println!(
                    "{}",
                    json!({ "result": null, "empty": true, "reason": "timed out" })
                );
            }
            return Status::AuthDenied;
        }
    };
    let _ = ends_at;
    load(opts, &client, &session, host, &public_key, "approved")
}

fn renew(opts: &Opts, host: &str) -> Status {
    if !hostname_ok(host) {
        eprintln!("shoephone: {host:?} is not a hostname");
        return Status::Usage;
    }
    let client = match need_client(opts) {
        Ok(c) => c,
        Err(s) => return s,
    };
    let session = match need_session(host) {
        Ok(s) => s,
        Err(s) => return s,
    };
    let public_key = match session.public_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("shoephone: {e}");
            return Status::Precondition;
        }
    };
    load(opts, &client, &session, host, &public_key, "renewed")
}

/// Issue a certificate inside an open window and load it into the agent.
fn load(
    opts: &Opts,
    client: &Client,
    session: &Session,
    host: &str,
    public_key: &str,
    what: &str,
) -> Status {
    let issued = match client.issue(host, public_key) {
        Ok(i) => i,
        Err(e) => {
            if let Error::Daemon { reply, .. } = &e
                && reply.code == "no_window"
            {
                eprintln!("shoephone: no open window for {host}; run `shoephone request {host}`");
            }
            return fail(&e);
        }
    };
    // Unload the previous certificate first; a second ssh-add would leave it
    // in the agent as a separate identity until it expired.
    let agent_wanted = use_agent();
    if agent_wanted {
        session.remove_from_agent();
    }
    if let Err(e) = session.write_certificate(&issued.certificate) {
        eprintln!("shoephone: {e}");
        return Status::Precondition;
    }
    let lifetime = issued.valid_before.saturating_sub(now_unix());
    let loaded = if agent_wanted {
        session.add_to_agent(lifetime)
    } else {
        Ok(())
    };
    if let Err(e) = &loaded {
        eprintln!("shoephone: {e}");
        eprintln!(
            "shoephone: certificate is at {} for `ssh -i {}`",
            session.cert_path().display(),
            session.key_path().display()
        );
    }
    if !agent_wanted {
        eprintln!(
            "shoephone: certificate is at {}; ssh finds it beside the session key (agent = false)",
            session.cert_path().display()
        );
    }
    eprintln!(
        "shoephone: {what}: admin on {host}, certificate #{} good for {}, window closes in {}",
        issued.serial,
        in_minutes(issued.valid_before),
        in_minutes(issued.ends_at)
    );
    if opts.json {
        println!(
            "{}",
            json!({
                "result": {
                    "host": host,
                    "serial": issued.serial,
                    "valid_before": issued.valid_before,
                    "ends_at": issued.ends_at,
                    "certificate": session.cert_path(),
                    "key": session.key_path(),
                    "in_agent": agent_wanted && loaded.is_ok(),
                },
                "empty": false,
            })
        );
    } else {
        println!(
            "{what}: admin on {host} until the certificate expires in {}; renew with `shoephone renew {host}`",
            in_minutes(issued.valid_before)
        );
    }
    if loaded.is_ok() {
        Status::Ok
    } else {
        Status::AuthRemediable
    }
}

fn disavow(opts: &Opts, host: &str) -> Status {
    if !hostname_ok(host) {
        eprintln!("shoephone: {host:?} is not a hostname");
        return Status::Usage;
    }
    let client = match need_client(opts) {
        Ok(c) => c,
        Err(s) => return s,
    };
    if let Ok(session) = need_session(host) {
        if use_agent() {
            session.remove_from_agent();
        }
        session.remove_certificate();
    }
    match client.kill(host) {
        Ok(()) => {
            if use_agent() {
                eprintln!(
                    "shoephone: window on {host} closed; the loaded certificate expires within one TTL"
                );
            } else {
                eprintln!("shoephone: window on {host} closed; the certificate file is removed");
            }
            if opts.json {
                println!(
                    "{}",
                    json!({ "result": { "host": host, "killed": true }, "empty": false })
                );
            } else {
                println!("disavowed: {host}");
            }
            Status::Ok
        }
        Err(Error::Daemon { reply, .. }) if reply.code == "no_window" => {
            eprintln!("shoephone: no open window for {host}; nothing to close");
            if opts.json {
                println!(
                    "{}",
                    json!({ "result": null, "empty": true, "reason": "no open window" })
                );
            }
            Status::Empty
        }
        Err(e) => fail(&e),
    }
}

fn project_ok(project: &str) -> bool {
    !project.is_empty()
        && project
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// The `--reason` text, or the usage error the caller returns.
fn need_reason(opts: &Opts) -> Result<String, Status> {
    match opts
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        Some(r) => Ok(r.to_owned()),
        None => {
            eprintln!(
                "shoephone: --reason is required: say what the change is and why; the person reads it before approving"
            );
            Err(Status::Usage)
        }
    }
}

/// A git command with a cleared environment (plus `PATH` and `HOME`), run
/// directly and never through a shell.
fn git_command(args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    cmd.args(args)
        .env_clear()
        .stdin(std::process::Stdio::null());
    for var in ["PATH", "HOME"] {
        if let Some(v) = std::env::var_os(var) {
            cmd.env(var, v);
        }
    }
    cmd
}

/// Run git and return its stdout, or the reason it failed.
fn git(args: &[&str]) -> Result<Vec<u8>, String> {
    let out = git_command(args)
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// The whole repository at `HEAD`, from the repo root, as a gzip tar.
/// `git archive` is streamed through the encoder, and the run stops as soon
/// as the compressed output passes the upload limit.
fn repo_archive() -> Result<Vec<u8>, (Status, String)> {
    let top = git(&["rev-parse", "--show-toplevel"]).map_err(|e| {
        (
            Status::Precondition,
            format!("run this inside the Terraform repository's git checkout: {e}"),
        )
    })?;
    let top = String::from_utf8_lossy(&top).trim().to_owned();
    let dirty = git(&["-C", &top, "status", "--porcelain", "--untracked-files=no"])
        .map_err(|e| (Status::Precondition, format!("git status failed: {e}")))?;
    if !dirty.is_empty() {
        return Err((
            Status::Precondition,
            "tracked files have uncommitted changes (see `git status`); commit or stash them, because only HEAD is trusted".to_owned(),
        ));
    }
    let broken =
        |what: &str, e: &dyn std::fmt::Display| (Status::Precondition, format!("{what}: {e}"));
    let mut child = git_command(&["-C", &top, "archive", "--format=tar", "HEAD"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| broken("cannot run git", &e))?;
    let mut tar = child
        .stdout
        .take()
        .ok_or_else(|| broken("git archive", &"no stdout"))?;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut tar, &mut buf)
            .map_err(|e| broken("cannot read git archive", &e))?;
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut gz, &buf[..n])
            .map_err(|e| broken("cannot compress the archive", &e))?;
        if gz.get_ref().len() > MAX_ARCHIVE_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err((
                Status::Permanent,
                format!(
                    "archive_too_large: the compressed repository is over {} MiB, the limit",
                    MAX_ARCHIVE_BYTES >> 20
                ),
            ));
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| broken("git archive", &e))?;
    if !out.status.success() {
        return Err(broken(
            "git archive failed",
            &String::from_utf8_lossy(&out.stderr).trim(),
        ));
    }
    let gz = gz
        .finish()
        .map_err(|e| broken("cannot compress the archive", &e))?;
    if gz.len() > MAX_ARCHIVE_BYTES {
        return Err((
            Status::Permanent,
            format!(
                "archive_too_large: the compressed repository is over {} MiB, the limit",
                MAX_ARCHIVE_BYTES >> 20
            ),
        ));
    }
    Ok(gz)
}

fn trust(opts: &Opts, project: &str) -> Status {
    if !project_ok(project) {
        eprintln!("shoephone: {project:?} is not a project name");
        return Status::Usage;
    }
    let reason = match need_reason(opts) {
        Ok(r) => r,
        Err(s) => return s,
    };
    let client = match need_client(opts) {
        Ok(c) => c,
        Err(s) => return s,
    };
    let archive = match repo_archive() {
        Ok(a) => a,
        Err((status, msg)) => {
            eprintln!("shoephone: {msg}");
            return status;
        }
    };
    let reply = match client.trust(&TrustBody {
        project: project.to_owned(),
        archive: base64::engine::general_purpose::STANDARD.encode(&archive),
        reason,
        requester: requester(),
        context: opts.context.clone().or_else(session_link),
    }) {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    wait_for_job(opts, &client, &reply, "trust")
}

fn apply(opts: &Opts, project: &str) -> Status {
    if !project_ok(project) {
        eprintln!("shoephone: {project:?} is not a project name");
        return Status::Usage;
    }
    let reason = match need_reason(opts) {
        Ok(r) => r,
        Err(s) => return s,
    };
    let Some(path) = opts.manifest.as_deref() else {
        eprintln!("shoephone: --manifest FILE is required: the JSON file of variable values");
        return Status::Usage;
    };
    let manifest = match std::fs::read(path) {
        Ok(b) if b.len() > MAX_MANIFEST_BYTES => {
            eprintln!(
                "shoephone: {path}: manifest_too_large: {} bytes; the limit is {MAX_MANIFEST_BYTES}",
                b.len()
            );
            return Status::Permanent;
        }
        Ok(b) => match String::from_utf8(b) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("shoephone: {path}: not UTF-8 text");
                return Status::Permanent;
            }
        },
        Err(e) => {
            eprintln!("shoephone: cannot read manifest {path}: {e}");
            return Status::Precondition;
        }
    };
    let client = match need_client(opts) {
        Ok(c) => c,
        Err(s) => return s,
    };
    let reply = match client.apply(&ApplyBody {
        project: project.to_owned(),
        manifest,
        allow_destroy: opts.allow_destroy,
        reason,
        requester: requester(),
        context: opts.context.clone().or_else(session_link),
    }) {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    wait_for_job(opts, &client, &reply, "apply")
}

/// Poll a filed job until it is done, then report and map the outcome.
fn wait_for_job(opts: &Opts, client: &Client, reply: &JobReply, kind: &str) -> Status {
    eprintln!(
        "shoephone: match code {}  <- the person compares this with their phone",
        reply.match_code
    );
    if !opts.json {
        println!("match code: {}", reply.match_code);
    }
    eprintln!(
        "shoephone: waiting for the {kind} (the runner plans first, then the person decides)"
    );
    // The daemon settles every state on its own clock, so this is only a
    // backstop against a poll loop that never ends.
    let deadline = Instant::now() + Duration::from_secs(8 * 3600);
    let mut hinted = false;
    let mut failures = 0;
    // Whether the job got far enough that something may have run: an
    // approval the runner may have claimed, or a claim.
    let mut may_have_run = false;
    let done = loop {
        match client.job(reply.id) {
            Ok(job) => {
                failures = 0;
                if job.state == "done" {
                    break job;
                }
                if matches!(job.state.as_str(), "approved" | "claimed") {
                    may_have_run = true;
                }
                if job.state == "waiting" && !hinted {
                    hinted = true;
                    if kind == "trust" {
                        eprintln!("shoephone: approve on your phone: trust this code");
                    } else {
                        eprintln!("shoephone: approve this apply on your phone");
                    }
                }
            }
            Err(Error::Daemon {
                http: 404,
                reply: r,
            }) if r.code == "no_such_job" => {
                if !may_have_run {
                    // Never approved here, so nothing ran on its strength.
                    eprintln!(
                        "shoephone: the daemon no longer knows job {} (it restarted before the job was approved); nothing ran. Check `shoephone status`, then file it again",
                        reply.id
                    );
                    return Status::RetryUnknown;
                }
                eprintln!(
                    "shoephone: the daemon no longer knows job {}; its outcome is unknown. Check the real state before anything else",
                    reply.id
                );
                return Status::OutcomeUnknown;
            }
            // A poll only reads, so a few failed ones are not the end.
            Err(Error::Unreachable(_) | Error::Ambiguous(_)) if failures < 5 => failures += 1,
            Err(e) => return fail(&e),
        }
        if Instant::now() > deadline {
            eprintln!(
                "shoephone: no result after 8 hours; check `shoephone status` before retrying"
            );
            return Status::RetryUnknown;
        }
        std::thread::sleep(Duration::from_secs(2));
    };
    report_job(opts, &done)
}

fn report_job(opts: &Opts, job: &JobStatus) -> Status {
    let outcome = job.result.as_deref().unwrap_or("unknown");
    let (category, addresses) = match &job.failure {
        Some(f) => (Some(f.category.as_str()), f.addresses.as_slice()),
        None => (None, &[][..]),
    };
    if let Some(f) = &job.failure {
        eprintln!(
            "shoephone: {outcome}: {}{}",
            f.category,
            f.detail
                .as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default()
        );
        for a in &f.addresses {
            eprintln!("shoephone:   {a}");
        }
    }
    let status = match outcome {
        "trusted" | "applied" => Status::Ok,
        "declined" | "timed_out" => {
            eprintln!("shoephone: {outcome}; do not retry");
            Status::AuthDenied
        }
        "killed" => {
            eprintln!("shoephone: the job was killed; do not retry");
            Status::AuthDenied
        }
        "refused" => Status::Permanent,
        "plan_failed" => Status::PlanFailed,
        "apply_failed" if job.kind == "trust" => {
            eprintln!(
                "shoephone: the code change was not trusted: the runner could not install it. The previous trust stands"
            );
            Status::ApplyFailed
        }
        "apply_failed" => {
            eprintln!("shoephone: the apply failed part way; check the real state before retrying");
            Status::ApplyFailed
        }
        "outcome_unknown" if job.kind == "trust" => {
            eprintln!(
                "shoephone: the daemon cannot say whether the code change was trusted. Check `shoephone status` before anything else; do not retry"
            );
            Status::OutcomeUnknown
        }
        "outcome_unknown" => {
            eprintln!(
                "shoephone: the runner cannot say whether the apply took effect. Check the real state before anything else; do not retry"
            );
            Status::OutcomeUnknown
        }
        other => {
            eprintln!("shoephone: unexpected result {other:?}; check `shoephone status`");
            Status::RetryUnknown
        }
    };
    if opts.json {
        let counts = job.summary.as_ref().map(|s| {
            json!({
                "create": s.create,
                "update": s.update,
                "replace": s.replace,
                "delete": s.delete,
            })
        });
        println!(
            "{}",
            json!({
                "result": {
                    "id": job.id,
                    "project": job.project,
                    "kind": job.kind,
                    "outcome": outcome,
                    "category": category,
                    "addresses": addresses,
                    "counts": counts,
                    "changed_variables": job.summary.as_ref().map(|s| &s.variables),
                },
                "empty": false,
            })
        );
    } else if status == Status::Ok {
        println!("{outcome}: {}", job.project);
    }
    status
}
