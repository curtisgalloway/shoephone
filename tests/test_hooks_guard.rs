// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `cargo test` builds both service binaries with the `test-hooks` feature
//! (through the crate's dev-dependency on itself). Such a build must
//! refuse to start unless its allow variable is exactly `1`.

use std::process::Command;

fn version(bin: &str, var: &str, value: Option<&str>) -> std::process::Output {
    let mut c = Command::new(bin);
    c.arg("--version").env_remove(var);
    if let Some(v) = value {
        c.env(var, v);
    }
    c.output().unwrap()
}

fn check(bin: &str, var: &str, name: &str) {
    let out = version(bin, var, None);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert!(out.stdout.is_empty());
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("test-hooks"), "{err}");

    let out = version(bin, var, Some("yes"));
    assert_eq!(
        out.status.code(),
        Some(3),
        "only the exact value 1 allows it"
    );

    let out = version(bin, var, Some("1"));
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .starts_with(&format!("{name} "))
    );
}

#[test]
fn test_hooks_runner_refuses_to_start() {
    check(
        env!("CARGO_BIN_EXE_shoephone-runner"),
        "SHOEPHONE_RUNNER_ALLOW_TEST_HOOKS",
        "shoephone-runner",
    );
}

#[test]
fn test_hooks_daemon_refuses_to_start() {
    check(
        env!("CARGO_BIN_EXE_shoephoned"),
        "SHOEPHONED_ALLOW_TEST_HOOKS",
        "shoephoned",
    );
}
