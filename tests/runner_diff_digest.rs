// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The `diff-digest` verb, run as the operator would run it.

use std::process::Command;

fn runner(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_shoephone-runner"))
        .env("SHOEPHONE_RUNNER_ALLOW_TEST_HOOKS", "1")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn diff_digest_prints_both_digests_and_refuses_a_wrong_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let infra = dir.path().join("infra");
    std::fs::create_dir_all(&infra).unwrap();
    std::fs::write(infra.join("main.tf"), "x = 1\n").unwrap();
    let cand = dir.path().to_str().unwrap();

    let out = runner(&["diff-digest", "none", "-", cand, "infra"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(lines[0].starts_with("candidate ") && lines[0].len() == 10 + 64);
    assert!(lines[1].starts_with("diff ") && lines[1].len() == 5 + 64);

    let out = runner(&["--json", "diff-digest", "none", "-", cand, "infra"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["candidate"].as_str().unwrap().len(), 64);

    let wrong = "0".repeat(64);
    let out = runner(&["diff-digest", &wrong, cand, cand, "infra"]);
    assert_eq!(out.status.code(), Some(30));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("baseline_mismatch"));
}
