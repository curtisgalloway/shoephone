// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The shared bound-challenge vectors, checked against this daemon's own
//! derivation.
//!
//! The approver app implements the same derivation in Swift and has a test
//! that reads a vendored copy of this file. Neither implementation can
//! drift without one of the two suites failing, which is the only way to
//! catch a format change that both sides would otherwise make consistently
//! wrong in their own repository.
//!
//! `tests/fixtures/bound-challenge-vectors.json` is the source of truth;
//! the app's copy is compared against it by that repository's
//! `scripts/e2e.sh`.

use std::time::{Duration, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use shoephone::grant::{Scope, bound_challenge};

#[derive(serde::Deserialize)]
struct Doc {
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    host: String,
    principal: String,
    public_key: String,
    ends_at: u64,
    nonce: String,
    bytes_to_sign: String,
    challenge_sha256_hex: String,
    challenge_base64url: String,
}

fn vectors() -> Vec<Vector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/bound-challenge-vectors.json"
    );
    let text = std::fs::read_to_string(path).expect("vector file");
    let doc: Doc = serde_json::from_str(&text).expect("vector json");
    assert!(!doc.vectors.is_empty(), "the vector file must not be empty");
    doc.vectors
}

#[test]
fn every_vector_matches_this_daemons_derivation() {
    for v in vectors() {
        let scope = Scope {
            host: v.host.clone(),
            principal: v.principal.clone(),
            public_key: v.public_key.clone(),
            ends_at: UNIX_EPOCH + Duration::from_secs(v.ends_at),
        };

        let bytes = scope.bytes_to_sign(&v.nonce);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            v.bytes_to_sign,
            "bytes_to_sign disagree for {}",
            v.name
        );

        let challenge = bound_challenge(&scope, &v.nonce);
        let hex: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, v.challenge_sha256_hex,
            "digest disagrees for {}",
            v.name
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(challenge),
            v.challenge_base64url,
            "base64url challenge disagrees for {}",
            v.name
        );
    }
}

#[test]
fn the_vectors_are_distinct() {
    let all = vectors();
    let mut seen: Vec<&str> = all.iter().map(|v| v.challenge_base64url.as_str()).collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(
        before,
        seen.len(),
        "two vectors share a challenge, so one of them proves nothing"
    );
}
