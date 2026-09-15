// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephoned` — the grant daemon on the failsafe host.
//!
//! Three verbs, all reading `--config <file>` (default
//! `/etc/shoephone/shoephoned.toml`):
//!
//! - `serve`: hold the user CA and answer the CLI and the approve page.
//! - `init-ca`: create the CA key file named in the config and print the
//!   public line for every host's `TrustedUserCAKeys`.
//! - `enroll --name <device>`: mint a one-time code for the approve page's
//!   enrollment form. Human-only: it runs at this host's console.
//! - `devices`: list the enrolled approvers.
//! - `forget --name <device>` or `--id <handle>`: remove one. Human-only and
//!   console-only for the same reason as `enroll`, and it refuses to run
//!   while the daemon holds the device list in memory. Names are not
//!   unique, so an ambiguous one is refused rather than resolved.

use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use shoephone::ca::{OsEntropy, UserCa};
use shoephone::config::Config;
use shoephone::exit::{Status, VERSION};
use shoephone::grant::Entropy;
use shoephone::server::Daemon;
use shoephone::store::{self, EnrollCode, Store};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("shoephoned {VERSION}");
        return Status::Ok.into();
    }
    run(&args).into()
}

/// Where the deployed daemon keeps its config; `--config` overrides it.
const DEFAULT_CONFIG: &str = "/etc/shoephone/shoephoned.toml";

fn usage() -> Status {
    eprintln!(
        "usage: shoephoned [--config <file>] (serve | init-ca | enroll --name <device>\n                                          | devices | forget (--name <device> | --id <handle>))\n       shoephoned --version\n\n--config defaults to /etc/shoephone/shoephoned.toml"
    );
    Status::Usage
}

/// The parsed command line. Flags take the next token as their value only
/// when it is not itself a flag, so `--name --config x` is a usage error
/// rather than a device named `--config`.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    config: Option<String>,
    name: Option<String>,
    id: Option<String>,
    verb: Option<String>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" | "--name" | "--id" => {
                let value = it
                    .next()
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| format!("{a} needs a value"))?;
                let slot = match a.as_str() {
                    "--config" => &mut out.config,
                    "--name" => &mut out.name,
                    _ => &mut out.id,
                };
                if slot.is_some() {
                    return Err(format!("{a} given twice"));
                }
                *slot = Some(value.clone());
            }
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}")),
            verb if out.verb.is_none() => out.verb = Some(verb.to_owned()),
            extra => return Err(format!("unexpected argument {extra:?}")),
        }
    }
    Ok(out)
}

fn run(args: &[String]) -> Status {
    let parsed = match parse(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return usage();
        }
    };
    // A missing verb is a usage error before anything else: the default
    // config path must not turn `shoephoned` alone into "config not found".
    if parsed.verb.is_none() {
        return usage();
    }
    let config_path = parsed.config.unwrap_or_else(|| DEFAULT_CONFIG.to_owned());
    let config = match Config::from_file(&PathBuf::from(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Precondition;
        }
    };
    match (parsed.verb.as_deref(), parsed.name, parsed.id) {
        (Some("serve"), None, None) => serve(config),
        (Some("init-ca"), None, None) => init_ca(&config.ca_key),
        (Some("enroll"), Some(name), None) => enroll(&config, &name),
        (Some("devices"), None, None) => devices(&config),
        (Some("forget"), Some(target), None) | (Some("forget"), None, Some(target)) => {
            forget(&config, &target)
        }
        _ => usage(),
    }
}

fn init_ca(path: &Path) -> Status {
    // No exists() check: write_openssh_file creates the file with
    // create_new, so an existing file or a planted symlink fails the open
    // instead of being truncated.
    let ca = match UserCa::generate("shoephone user CA") {
        Ok(ca) => ca,
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Permanent;
        }
    };
    if let Err(e) = ca.write_openssh_file(path) {
        eprintln!("shoephoned: {e}; refusing to overwrite an existing CA");
        return Status::Precondition;
    }
    match ca.public_key_line() {
        Ok(line) => {
            eprintln!(
                "shoephoned: wrote {} (mode 0600); it must be owned by root",
                path.display()
            );
            eprintln!("shoephoned: TrustedUserCAKeys line for every host follows on stdout");
            println!("{line}");
            Status::Ok
        }
        Err(e) => {
            eprintln!("shoephoned: {e}");
            Status::Permanent
        }
    }
}

/// Whether something is already listening where the daemon would.
///
/// `serve` loads `devices.json` once at startup and keeps the list in
/// memory, writing the whole list back whenever it changes. So a removal
/// made on disk underneath a running daemon is not merely late — it is
/// undone by the daemon's next save, which knows nothing about it. The next
/// `push/register` would resurrect the device we just removed, and nothing
/// would report it. Refusing to run is the only honest option.
fn daemon_is_listening(listen: &str) -> bool {
    let Ok(addrs) = listen.to_socket_addrs() else {
        return false;
    };
    addrs
        .into_iter()
        .any(|a| TcpStream::connect_timeout(&a, Duration::from_millis(500)).is_ok())
}

fn devices(config: &Config) -> Status {
    let store = Store::new(&config.state_dir);
    let devices = match store.load_devices() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Precondition;
        }
    };
    if devices.is_empty() {
        eprintln!("shoephoned: no enrolled devices; `shoephoned enroll --name <device>`");
        return Status::Empty;
    }
    for d in &devices {
        // Say which devices cannot be pushed to, because that is the
        // difference an operator is usually looking for: a device enrolled
        // before per-device push secrets existed is refused at
        // push/register and silently receives nothing.
        let push = match (&d.push_token, &d.push_secret_sha256) {
            (Some(_), Some(_)) => "push ok",
            (Some(_), None) => "push token but no secret: re-enroll for notifications",
            (None, _) => "no push token registered",
        };
        // Epoch seconds, as the daemon stores them, plus an age: which
        // enrollment is the stale one is the question this list answers.
        let age = store::unix(SystemTime::now()).saturating_sub(d.enrolled_at) / 86_400;
        // The handle first: it is the only field guaranteed to identify one
        // device, and it is what `forget --id` takes.
        println!(
            "{}\t{}\t{}\t{age}d ago\t{}",
            d.handle(),
            d.name,
            d.enrolled_at,
            push
        );
    }
    Status::Ok
}

/// Remove an enrolled approver.
///
/// There is no remote form of this and there should not be: the approver is
/// the root of the whole model, so the ability to remove one must not be
/// reachable by anything the approver authorizes. Same custody as `enroll`.
fn forget(config: &Config, target: &str) -> Status {
    if daemon_is_listening(&config.listen) {
        eprintln!(
            "shoephoned: something is listening on {}, so shoephoned is probably running.",
            config.listen
        );
        eprintln!(
            "shoephoned: it holds the device list in memory and would write this removal back out. Stop it first:"
        );
        eprintln!("shoephoned:     systemctl stop shoephoned");
        return Status::Precondition;
    }
    let store = Store::new(&config.state_dir);
    let matches = match store.match_devices(target) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Precondition;
        }
    };
    // Names are not unique and the ambiguous case is the common one: a
    // replacement enrolled under the name it replaces. Resolving it by
    // picking one, or by removing both, would take the working device at the
    // moment this tool is reached for. So it refuses and shows the handles.
    if matches.len() > 1 {
        eprintln!(
            "shoephoned: {target:?} matches {} devices; name it by handle instead:",
            matches.len()
        );
        for d in &matches {
            let age = (store::unix(SystemTime::now()).saturating_sub(d.enrolled_at)) / 86_400;
            eprintln!(
                "shoephoned:     --id {}   ({}, enrolled {age}d ago)",
                d.handle(),
                d.name
            );
        }
        return Status::Usage;
    }
    let Some(found) = matches.first() else {
        eprintln!("shoephoned: no enrolled device matching {target:?}");
        if let Ok(d) = store.load_devices() {
            for x in &d {
                eprintln!("shoephoned:     {} {}", x.handle(), x.name);
            }
        }
        return Status::Usage;
    };
    let name = found.name.clone();
    let remaining = match store.forget_device(&found.handle()) {
        Ok(Some(n)) => n,
        Ok(None) => {
            eprintln!("shoephoned: {target:?} vanished between the lookup and the removal");
            return Status::Precondition;
        }
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Precondition;
        }
    };
    eprintln!(
        "shoephoned: removed {name:?}; {remaining} device(s) remain. Its key can no longer approve anything."
    );
    if remaining == 0 {
        // Recoverable, but only from this console, so say so plainly rather
        // than refusing: an operator removing a lost phone may have no other
        // device to keep.
        eprintln!(
            "shoephoned: NO APPROVERS REMAIN. Nothing can be approved until you run `shoephoned enroll --name <device>` here."
        );
    }
    eprintln!("shoephoned: start the daemon again: systemctl start shoephoned");
    Status::Ok
}

fn enroll(config: &Config, name: &str) -> Status {
    let store = Store::new(&config.state_dir);
    // Fail here rather than after someone has walked to their phone, scanned
    // the code and passed Face ID. The daemon refuses the same name again at
    // enroll_finish, which is the check that counts -- this one only saves
    // the trip.
    match store.load_devices() {
        Ok(devices) => {
            if let Some(taken) = devices.iter().find(|d| d.name == name) {
                eprintln!("shoephoned: a device named {name:?} is already enrolled");
                eprintln!(
                    "shoephoned: remove it with `shoephoned forget --id {}`, or choose another name",
                    taken.handle()
                );
                return Status::Usage;
            }
        }
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Precondition;
        }
    }
    let mut buf = [0u8; 8];
    OsEntropy.fill(&mut buf);
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let raw: String = buf
        .iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect();
    let code = EnrollCode {
        sha256: store::sha256_hex(&raw),
        device_name: name.to_owned(),
        expires_at: store::unix(SystemTime::now()) + EnrollCode::TTL_SECS,
        failures: 0,
    };
    if let Err(e) = store.save_enroll_code(&code) {
        eprintln!("shoephoned: {e}");
        return Status::Precondition;
    }
    let pretty = format!("{}-{}", &raw[..4], &raw[4..]);
    eprintln!(
        "shoephoned: enrollment for {name:?} is open for {} minutes; scan this with the Shoephone app, or enter the code",
        EnrollCode::TTL_SECS / 60
    );
    // The QR carries the daemon's origin too, so a fresh app configures
    // itself from the scan. It goes to stderr with the chatter; stdout
    // stays the bare code for anything that captures it.
    let mut payload = format!(
        "shoephone://enroll?daemon={}&code={}",
        config.rp_origin, pretty
    );
    if let Some(access) = &config.access {
        match access.secret() {
            Ok(secret) => payload.push_str(&format!("&id={}&secret={secret}", access.client_id)),
            Err(e) => {
                eprintln!("shoephoned: {e}");
                return Status::Precondition;
            }
        }
    }
    match qr_text(&payload) {
        Some(qr) => eprintln!("\n{qr}"),
        None => eprintln!("shoephoned: (QR code too large to render)"),
    }
    println!("{pretty}");
    Status::Ok
}

/// A QR code as terminal text, two modules per character row using half
/// blocks, with a two-module quiet zone. Low error correction: a terminal
/// renders every module perfectly, and the smaller code scans faster. Light modules are drawn, dark
/// ones are left to the background, which is the right way round on the
/// dark terminals a console usually has; phone scanners read either.
fn qr_text(payload: &str) -> Option<String> {
    let qr = qrcodegen::QrCode::encode_text(payload, qrcodegen::QrCodeEcc::Low).ok()?;
    let size = qr.size();
    const QUIET: i32 = 2;
    let light = |x: i32, y: i32| !qr.get_module(x, y);
    let mut out = String::new();
    let mut y = -QUIET;
    while y < size + QUIET {
        for x in -QUIET..size + QUIET {
            let top = light(x, y);
            let bottom = light(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Some(out)
}

fn serve(config: Config) -> Status {
    let daemon = match Daemon::new(config) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Precondition;
        }
    };
    let listen = daemon.config().listen.clone();
    let devices = daemon.device_names();
    let hosts: Vec<&String> = daemon.config().principals.keys().collect();
    eprintln!(
        "shoephoned {VERSION}: {} host(s), {} enrolled device(s), listening on {listen}",
        hosts.len(),
        devices.len()
    );
    if devices.is_empty() {
        eprintln!("shoephoned: nothing can be approved until a device is enrolled");
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("shoephoned: runtime: {e}");
            return Status::Permanent;
        }
    };
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("shoephoned: bind {listen}: {e}");
                return Status::Precondition;
            }
        };
        let app = daemon.router();
        let shutdown = async {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                match signal(SignalKind::terminate()) {
                    Ok(mut term) => tokio::select! {
                        _ = ctrl_c => {}
                        _ = term.recv() => {}
                    },
                    Err(_) => {
                        let _ = ctrl_c.await;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = ctrl_c.await;
            }
            eprintln!("shoephoned: shutting down; open windows are closed");
        };
        match axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
        {
            Ok(()) => Status::Ok,
            Err(e) => {
                eprintln!("shoephoned: serve: {e}");
                Status::RetryUnknown
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn qr_text_has_a_quiet_zone_and_the_finder_pattern() {
        let text =
            qr_text("shoephone://enroll?daemon=https://approve.example&code=ABCD-EFGH").unwrap();
        let rows: Vec<&str> = text.lines().collect();
        // Quiet zone: the first row is two module rows of light, i.e. all full blocks.
        assert!(rows[0].chars().all(|c| c == '\u{2588}'), "{:?}", rows[0]);
        // Row 1 starts with quiet zone, then the finder pattern's top edge: a
        // dark 7-wide bar whose top half is dark and bottom half is dark too,
        // except the row pairs straddle it; just check the first module column
        // after the quiet zone is not light in both halves.
        let second: Vec<char> = rows[1].chars().collect();
        assert_eq!(second[0], '\u{2588}');
        assert_ne!(second[2], '\u{2588}');
        assert!(rows.len() > 10);
    }

    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn flags_take_values_that_are_not_flags() {
        let p = parse(&argv("--config /etc/x.toml enroll --name phone")).unwrap();
        assert_eq!(p.config.as_deref(), Some("/etc/x.toml"));
        assert_eq!(p.verb.as_deref(), Some("enroll"));
        assert_eq!(p.name.as_deref(), Some("phone"));

        let p = parse(&argv("--config x --name laptop enroll")).unwrap();
        assert_eq!(
            p.verb.as_deref(),
            Some("enroll"),
            "a flag value is not the verb"
        );

        let p = parse(&argv("--config enroll enroll")).unwrap();
        assert_eq!(p.config.as_deref(), Some("enroll"));
        assert_eq!(p.verb.as_deref(), Some("enroll"));

        assert!(
            parse(&argv("enroll --name --config x")).is_err(),
            "a flag is not a value"
        );
        assert!(parse(&argv("--config x serve extra")).is_err());
        assert!(parse(&argv("--config x --bogus serve")).is_err());
        assert!(parse(&argv("--config x --config y serve")).is_err());
    }
}
