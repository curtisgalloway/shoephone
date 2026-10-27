// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephone-runner`: the host that holds Terraform credentials and polls
//! the daemon.
//!
//! Verbs: `run` (the poll loop), `review-worker <job-dir>` (the
//! credential-free review step), `diff-digest` (the operator's check of a
//! trust review) and `--skill`. `run` is not implemented yet and exits with
//! status 3.

use std::path::Path;
use std::process::ExitCode;

use shoephone::exit::{Status, VERSION};
use shoephone::runner::config::RunnerConfig;
use shoephone::runner::review::{WorkerError, diff_digest, review_worker};

/// The runner's own agent-facing document, compiled in so it cannot drift.
const RUNNER_DOC: &str = include_str!("../../RUNNER.md");

/// Where the deployed runner keeps its config; `--config` overrides it.
const DEFAULT_CONFIG: &str = "/etc/shoephone-runner/shoephone-runner.toml";

fn usage() -> Status {
    eprintln!(
        "usage: shoephone-runner [--config <file>] run\n       shoephone-runner review-worker <job-dir>\n       shoephone-runner [--json] diff-digest <baseline-digest|none> <baseline-checkout|-> <candidate-checkout> <project-path>\n       shoephone-runner --skill | --version\n\n--config defaults to {DEFAULT_CONFIG}"
    );
    Status::Usage
}

/// `diff-digest <baseline-digest|none> <baseline-checkout|-> <candidate-checkout>
/// <project-path>`: the operator's check of a trust review's digests.
fn diff_digest_verb(
    baseline_digest: &str,
    baseline: &str,
    candidate: &str,
    project_path: &str,
    json: bool,
) -> Status {
    let digest = (baseline_digest != "none").then_some(baseline_digest);
    let dir = (baseline != "-").then(|| Path::new(baseline));
    match diff_digest(digest, dir, Path::new(candidate), project_path) {
        Ok((cand, diff)) => {
            if json {
                println!("{}", serde_json::json!({"candidate": cand, "diff": diff}));
            } else {
                println!("candidate {cand}");
                println!("diff {diff}");
            }
            Status::Ok
        }
        Err(f) => {
            eprintln!(
                "shoephone-runner: {}{}",
                f.category,
                f.detail.map(|d| format!(": {d}")).unwrap_or_default()
            );
            Status::Permanent
        }
    }
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
    let json = args.iter().any(|a| a == "--json");
    let args: Vec<String> = args.iter().filter(|a| *a != "--json").cloned().collect();
    let args = args.as_slice();
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
        ["review-worker", job_dir] => match review_worker(Path::new(job_dir)) {
            Ok(()) => Status::Ok,
            Err(WorkerError::Refused(f)) => {
                eprintln!("shoephone-runner: review refused: {}", f.category);
                Status::Permanent
            }
            Err(WorkerError::Request(e)) => {
                eprintln!("shoephone-runner: {e}");
                Status::Precondition
            }
        },
        [
            "diff-digest",
            baseline_digest,
            baseline,
            candidate,
            project_path,
        ] => diff_digest_verb(baseline_digest, baseline, candidate, project_path, json),
        _ => usage(),
    }
}
