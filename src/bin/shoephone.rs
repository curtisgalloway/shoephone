// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephone` — the grant CLI an agent session runs.
//!
//! Every path returns a [`Status`] rather than calling `process::exit`, so
//! the exit contract stays visible in the signatures. `--json` puts one
//! document on stdout and everything else on stderr.

use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use shoephone::api::{RequestBody, RequestState};
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
    positional: Vec<String>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut opts = Opts {
        json: false,
        daemon: None,
        window: None,
        reason: None,
        context: None,
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
        (Some("request" | "renew" | "disavow"), None) => {
            eprintln!(
                "shoephone: {} needs a host; try --skill",
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

fn need_session() -> Result<Session, Status> {
    match Session::default_dir() {
        Ok(dir) => Ok(Session::new(dir)),
        Err(e) => {
            eprintln!("shoephone: {e}");
            Err(Status::Precondition)
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
        Ok(dir) => match Session::new(dir.clone()).public_key() {
            Ok(_) => notes.push(format!(
                "session key: {}",
                dir.join("session_ed25519").display()
            )),
            Err(e) => problems.push(e),
        },
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
            } else if s.windows.is_empty() {
                println!("no open windows");
            } else {
                for w in &s.windows {
                    println!(
                        "admin on {} for {} (key {})",
                        w.host,
                        in_minutes(w.ends_at),
                        w.fingerprint
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
    let session = match need_session() {
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
    let session = match need_session() {
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
    if let Ok(session) = need_session() {
        if use_agent() {
            session.remove_from_agent();
        }
        session.remove_certificate();
    }
    match client.kill(host) {
        Ok(()) => {
            eprintln!(
                "shoephone: window on {host} closed; the loaded certificate expires within one TTL"
            );
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
