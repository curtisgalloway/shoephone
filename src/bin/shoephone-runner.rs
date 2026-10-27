// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephone-runner`: the host that holds Terraform credentials and polls
//! the daemon.
//!
//! Verbs: `run` (the poll loop), `review-worker <job-dir>` (the
//! credential-free review step) and `--skill`. `run` and `review-worker` are
//! not implemented yet and exit with status 3.

use std::process::ExitCode;

use shoephone::exit::{Status, VERSION};
use shoephone::runner::config::RunnerConfig;

/// The runner's own agent-facing document, compiled in so it cannot drift.
const RUNNER_DOC: &str = include_str!("../../RUNNER.md");

/// Where the deployed runner keeps its config; `--config` overrides it.
const DEFAULT_CONFIG: &str = "/etc/shoephone-runner/shoephone-runner.toml";

fn usage() -> Status {
    eprintln!(
        "usage: shoephone-runner [--config <file>] run\n       shoephone-runner review-worker <job-dir>\n       shoephone-runner --skill | --version\n\n--config defaults to {DEFAULT_CONFIG}"
    );
    Status::Usage
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args).into()
}

fn run(args: &[String]) -> Status {
    if args.iter().any(|a| a == "--skill") {
        print!("{}", RUNNER_DOC.replace("{{VERSION}}", VERSION));
        return Status::Ok;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("shoephone-runner {VERSION}");
        return Status::Ok;
    }
    let mut config = DEFAULT_CONFIG.to_string();
    let mut rest: Vec<&str> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--config" {
            match it.next().filter(|v| !v.starts_with("--")) {
                Some(v) => config = v.clone(),
                None => {
                    eprintln!("--config needs a value");
                    return usage();
                }
            }
        } else {
            rest.push(a);
        }
    }
    match rest.as_slice() {
        ["run"] => {
            if let Err(e) = RunnerConfig::from_file(std::path::Path::new(&config)) {
                eprintln!("shoephone-runner: {e}");
                return Status::Precondition;
            }
            eprintln!("shoephone-runner: run is not yet implemented");
            Status::Precondition
        }
        ["review-worker", _job_dir] => {
            eprintln!("shoephone-runner: review-worker is not yet implemented");
            Status::Precondition
        }
        _ => usage(),
    }
}
