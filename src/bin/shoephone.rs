// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephone` — the grant CLI an agent session runs.
//!
//! Scaffold. Verbs land one at a time; every path returns a [`Status`] rather
//! than calling `process::exit`, so the exit contract stays visible in the
//! signatures.

use std::process::ExitCode;

use shoephone::exit::{SKILL, Status, VERSION};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--skill") {
        print!("{}", SKILL.replace("{{VERSION}}", VERSION));
        return Status::Ok.into();
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("shoephone {VERSION}");
        return Status::Ok.into();
    }
    run(&args).into()
}

fn run(args: &[String]) -> Status {
    match args.first().map(String::as_str) {
        Some("doctor") => doctor(),
        Some(verb) => {
            eprintln!("shoephone: unknown command `{verb}`; try --skill");
            Status::Usage
        }
        None => {
            eprintln!("shoephone: a command is required; try --skill");
            Status::Usage
        }
    }
}

/// Check preconditions before guessing. Nothing to check yet: the daemon,
/// its address, and the session ssh-agent all arrive with the first real verb.
fn doctor() -> Status {
    println!("shoephone {VERSION}: nothing to check yet");
    Status::Ok
}
