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

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn run(args: &[String]) -> Status {
    let Some(config_path) = flag(args, "--config") else {
        return usage();
    };
    let verb = args
        .iter()
        .find(|a| !a.starts_with("--") && Some(a.as_str()) != Some(config_path.as_str()))
        .map(String::as_str);
    let config_path = PathBuf::from(config_path);
    let config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Precondition;
        }
    };
    match verb {
        Some("serve") => serve(config),
        Some("init-ca") => init_ca(&config.ca_key),
        Some("enroll") => match flag(args, "--name") {
            Some(name) => enroll(&config, &name),
            None => usage(),
        },
        _ => usage(),
    }
}

fn init_ca(path: &Path) -> Status {
    if path.exists() {
        eprintln!(
            "shoephoned: {} already exists; refusing to overwrite a CA",
            path.display()
        );
        return Status::Precondition;
    }
    let ca = match UserCa::generate("shoephone user CA") {
        Ok(ca) => ca,
        Err(e) => {
            eprintln!("shoephoned: {e}");
            return Status::Permanent;
        }
    };
    if let Err(e) = ca.write_openssh_file(path) {
        eprintln!("shoephoned: {e}");
        return Status::Precondition;
    }
    match ca.public_key_line() {
        Ok(line) => {
            eprintln!(
                "shoephoned: wrote {}; make it mode 0600, owner root",
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
