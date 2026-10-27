// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `cargo test` builds `shoephone-runner` with the `test-hooks` feature
//! (through the crate's dev-dependency on itself), and such a build must
//! refuse to start unless SHOEPHONE_RUNNER_ALLOW_TEST_HOOKS=1.

use std::process::Command;

fn runner() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_shoephone-runner"));
    c.arg("--version")
        .env_remove("SHOEPHONE_RUNNER_ALLOW_TEST_HOOKS");
    c
}

#[test]
fn test_hooks_build_refuses_to_start() {
    let out = runner().output().unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert!(out.stdout.is_empty());
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("test-hooks"), "{err}");

    let out = runner()
        .env("SHOEPHONE_RUNNER_ALLOW_TEST_HOOKS", "yes")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "only the exact value 1 allows it"
    );

    let out = runner()
        .env("SHOEPHONE_RUNNER_ALLOW_TEST_HOOKS", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .starts_with("shoephone-runner ")
    );
}
