// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephoned` — the grant daemon on the failsafe host.
//!
//! Scaffold. The daemon will hold the SSH user CA, accept grant requests from
//! the CLI, present the enforced scope to the approver, verify the approver's
//! signature over scope + nonce, and sign short-lived host-scoped
//! certificates inside a phone-approved window. None of that exists yet.

use std::process::ExitCode;

use shoephone::exit::{Status, VERSION};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("shoephoned {VERSION}");
        return Status::Ok.into();
    }
    eprintln!("shoephoned {VERSION}: not implemented yet");
    Status::Precondition.into()
}
