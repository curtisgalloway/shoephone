// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephoned` — the grant daemon on the failsafe host.
//!
//! Three verbs, all needing `--config <file>`:
//!
//! - `serve`: hold the user CA and answer the CLI and the approve page.
//! - `init-ca`: create the CA key file named in the config and print the
//!   public line for every host's `TrustedUserCAKeys`.
//! - `enroll --name <device>`: mint a one-time code for the approve page's
//!   enrollment form. Human-only: it runs at this host's console.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;

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

fn usage() -> Status {
    eprintln!(
        "usage: shoephoned --config <file> (serve | init-ca | enroll --name <device>)\n       shoephoned --version"
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
    verb: Option<String>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" | "--name" => {
                let value = it
                    .next()
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| format!("{a} needs a value"))?;
                let slot = if a == "--config" {
                    &mut out.config
                } else {
                    &mut out.name
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
    let Some(config_path) = parsed.config else {
        return usage();
    };
    let config = match Config::from_file(&PathBuf::from(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Precondition;
        }
    };
    match (parsed.verb.as_deref(), parsed.name) {
        (Some("serve"), None) => serve(config),
        (Some("init-ca"), None) => init_ca(&config.ca_key),
        (Some("enroll"), Some(name)) => enroll(&config, &name),
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

fn enroll(config: &Config, name: &str) -> Status {
    let store = Store::new(&config.state_dir);
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
    eprintln!(
        "shoephoned: enrollment for {name:?} is open for {} minutes; enter this code on the approve page",
        EnrollCode::TTL_SECS / 60
    );
    println!("{}-{}", &raw[..4], &raw[4..]);
    Status::Ok
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
