// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The shared trust and apply scope vectors, checked against this daemon's
//! own derivation.
//!
//! Same contract as `tests/vectors.rs`: the approver app derives the same
//! challenges in Swift from a vendored copy of
//! `tests/fixtures/job-scope-vectors.json`, so a format change made on one
//! side only fails a suite.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use shoephone::scope::{
    Action, ApplyScope, BaselineStatus, Counts, TrustScope, address_text, challenge_of,
};

#[derive(serde::Deserialize)]
struct Doc {
    address_texts: std::collections::BTreeMap<String, String>,
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    kind: String,
    scope: serde_json::Value,
    nonce: String,
    bytes_to_sign: String,
    challenge_sha256_hex: String,
    challenge_base64url: String,
}

fn doc() -> Doc {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/job-scope-vectors.json"
    );
    let text = std::fs::read_to_string(path).expect("vector file");
    let doc: Doc = serde_json::from_str(&text).expect("vector json");
    assert!(doc.vectors.len() >= 4, "expected at least four vectors");
    doc
}

fn s(v: &serde_json::Value, key: &str) -> String {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key}"))
        .to_string()
}

fn opt(v: &serde_json::Value, key: &str) -> Option<String> {
    v[key].as_str().map(str::to_string)
}

fn n(v: &serde_json::Value, key: &str) -> u32 {
    v[key].as_u64().unwrap_or_else(|| panic!("{key}")) as u32
}

fn b(v: &serde_json::Value, key: &str) -> bool {
    v[key].as_bool().unwrap_or_else(|| panic!("{key}"))
}

fn bytes_of(v: &Vector) -> Vec<u8> {
    let sc = &v.scope;
    match v.kind.as_str() {
        "trust" => TrustScope {
            project: s(sc, "project"),
            baseline: opt(sc, "baseline"),
            candidate: s(sc, "candidate"),
            diff: s(sc, "diff"),
            schema: s(sc, "schema"),
            policy_version: n(sc, "policy_version"),
            files_changed: n(sc, "files_changed"),
            lines_added: n(sc, "lines_added"),
            lines_removed: n(sc, "lines_removed"),
            schema_changed: b(sc, "schema_changed"),
        }
        .bytes_to_sign(&v.nonce),
        "apply" => ApplyScope {
            project: s(sc, "project"),
            revision: s(sc, "revision"),
            schema: s(sc, "schema"),
            manifest: s(sc, "manifest"),
            baseline_manifest: opt(sc, "baseline_manifest"),
            baseline_status: match s(sc, "baseline_status").as_str() {
                "none" => BaselineStatus::None,
                "applied" => BaselineStatus::Applied,
                "uncertain" => BaselineStatus::Uncertain,
                other => panic!("unknown baseline_status {other}"),
            },
            plan: s(sc, "plan"),
            destructive: b(sc, "destructive"),
            counts: Counts {
                create: n(&sc["counts"], "create"),
                update: n(&sc["counts"], "update"),
                replace: n(&sc["counts"], "replace"),
                delete: n(&sc["counts"], "delete"),
            },
            addresses: s(sc, "addresses"),
        }
        .bytes_to_sign(&v.nonce),
        other => panic!("unknown kind {other}"),
    }
}

#[test]
fn every_job_vector_matches_this_daemons_derivation() {
    for v in doc().vectors {
        let bytes = bytes_of(&v);
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            v.bytes_to_sign,
            "bytes_to_sign disagree for {}",
            v.name
        );
        let challenge = challenge_of(&bytes);
        let hex: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, v.challenge_sha256_hex, "digest for {}", v.name);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(challenge),
            v.challenge_base64url,
            "base64url challenge for {}",
            v.name
        );
    }
}

#[test]
fn job_vectors_are_distinct() {
    let d = doc();
    let mut seen: Vec<&str> = d
        .vectors
        .iter()
        .map(|v| v.challenge_base64url.as_str())
        .collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "two vectors share a challenge");
}

#[test]
fn recorded_address_digests_match_the_recorded_address_texts() {
    let d = doc();
    let first = address_text(&[
        (Action::Create, "aws_instance.web".into()),
        (Action::Update, "aws_security_group.web".into()),
    ]);
    assert_eq!(first, d.address_texts["apply with baseline_status none"]);
    let second = address_text(&[
        (Action::Delete, "aws_instance.old".into()),
        (Action::Replace, "aws_db_instance.main".into()),
        (Action::Create, "aws_eip.web".into()),
    ]);
    assert_eq!(second, d.address_texts["apply, uncertain and destructive"]);
    for (text, name) in [
        (first, "apply with baseline_status none"),
        (second, "apply, uncertain and destructive"),
    ] {
        let hex: String = challenge_of(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let v = d.vectors.iter().find(|v| v.name == name).unwrap();
        assert_eq!(hex, v.scope["addresses"].as_str().unwrap());
    }
}
