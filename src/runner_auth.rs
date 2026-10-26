// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! Runner identity: every request a Terraform runner makes is signed with
//! that runner's ed25519 key and cannot be replayed.
//!
//! The runner signs a canonical rendering of the request (method, path,
//! body hash, job, timestamp, nonce) as an SSHSIG in the `shoephone-runner`
//! namespace, so a signature made for any other purpose, such as a login
//! challenge, never verifies here. The daemon checks, in this order: the
//! runner is known, the timestamp is within 60 s of its clock, the
//! signature verifies, and only then that the nonce is new. A nonce is
//! recorded only after the signature verifies, so a caller without a key
//! cannot fill the cache.

use std::collections::{BTreeMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use ssh_key::sha2::{Digest, Sha256};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

use crate::grant::Refusal;

/// Header carrying the base64url SSHSIG.
pub const SIGNATURE_HEADER: &str = "shoephone-runner-signature";
/// Header carrying the runner's configured name.
pub const RUNNER_HEADER: &str = "shoephone-runner";

/// SSHSIG namespace for runner requests.
const NAMESPACE: &str = "shoephone-runner";
/// How far a request's timestamp may be from the daemon's clock.
const MAX_SKEW_SECS: u64 = 60;
/// How long a nonce is remembered. Longer than twice the skew window, so a
/// nonce cannot outlive its timestamp's validity and be replayed.
const NONCE_TTL_SECS: u64 = 120;
/// Most nonces held at once; past it the cache refuses rather than grows.
const MAX_NONCES: usize = 10_000;

/// The exact bytes a runner signs and the daemon verifies.
pub fn canonical(
    method: &str,
    path: &str,
    body: &[u8],
    job: Option<u64>,
    timestamp: u64,
    nonce: &str,
) -> Vec<u8> {
    let digest: String = Sha256::digest(body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let job = job.map_or_else(|| "-".to_owned(), |j| j.to_string());
    format!("shoephone-runner-v1\n{method}\n{path}\n{digest}\n{job}\n{timestamp}\n{nonce}\n")
        .into_bytes()
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = ALPHABET.iter().position(|a| a == c)? as u32;
            n |= v << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

/// Signs `message`, returning the SSHSIG as PEM then base64url, which is
/// one line and header-safe.
pub fn sign(key: &PrivateKey, message: &[u8]) -> Result<String, String> {
    let sig = key
        .sign(NAMESPACE, HashAlg::Sha512, message)
        .map_err(|e| format!("signing: {e}"))?;
    let pem = sig
        .to_pem(LineEnding::LF)
        .map_err(|e| format!("encoding signature: {e}"))?;
    Ok(b64url_encode(pem.as_bytes()))
}

/// The pieces of a request that [`canonical`] covers, in its argument order.
pub type MessageParts<'a> = (&'a str, &'a str, &'a [u8], Option<u64>, u64, &'a str);

/// Checks runner signatures and remembers recent nonces.
#[derive(Debug, Default)]
pub struct Verifier {
    keys: BTreeMap<String, PublicKey>,
    /// (when recorded in Unix seconds, "runner\nnonce"), oldest first.
    seen: VecDeque<(u64, String)>,
}

impl Verifier {
    pub fn new(keys: BTreeMap<String, PublicKey>) -> Self {
        Self {
            keys,
            seen: VecDeque::new(),
        }
    }

    /// Verifies one request. `WrongRunner` for an unknown runner, a
    /// malformed or invalid signature; `StaleSignature` for a timestamp
    /// outside the window, a replayed nonce, or a full nonce cache.
    pub fn verify(
        &mut self,
        now: SystemTime,
        runner: &str,
        signature: &str,
        parts: MessageParts<'_>,
    ) -> Result<(), Refusal> {
        let (method, path, body, job, timestamp, nonce) = parts;
        let now_secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        while self
            .seen
            .front()
            .is_some_and(|(at, _)| now_secs.saturating_sub(*at) > NONCE_TTL_SECS)
        {
            self.seen.pop_front();
        }

        let key = self.keys.get(runner).ok_or(Refusal::WrongRunner)?;
        if now_secs.abs_diff(timestamp) > MAX_SKEW_SECS {
            return Err(Refusal::StaleSignature);
        }
        // The nonce is one line of the canonical text; a newline in it
        // would let one request's bytes read as another's.
        if nonce.is_empty() || nonce.contains('\n') {
            return Err(Refusal::WrongRunner);
        }
        let pem = b64url_decode(signature).ok_or(Refusal::WrongRunner)?;
        let sig = SshSig::from_pem(pem).map_err(|_| Refusal::WrongRunner)?;
        let message = canonical(method, path, body, job, timestamp, nonce);
        key.verify(NAMESPACE, &message, &sig)
            .map_err(|_| Refusal::WrongRunner)?;

        let tag = format!("{runner}\n{nonce}");
        if self.seen.iter().any(|(_, t)| *t == tag) || self.seen.len() >= MAX_NONCES {
            return Err(Refusal::StaleSignature);
        }
        self.seen.push_back((now_secs, tag));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ssh_key::Algorithm;
    use ssh_key::rand_core::OsRng;

    use super::*;

    fn key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    const NOW: u64 = 1_800_000_000;

    fn verifier(runners: &[(&str, &PrivateKey)]) -> Verifier {
        Verifier::new(
            runners
                .iter()
                .map(|(n, k)| ((*n).to_owned(), k.public_key().clone()))
                .collect(),
        )
    }

    fn signed(k: &PrivateKey, body: &[u8], ts: u64, nonce: &str) -> String {
        sign(
            k,
            &canonical("POST", "/api/runner/jobs", body, Some(7), ts, nonce),
        )
        .unwrap()
    }

    fn parts<'a>(body: &'a [u8], ts: u64, nonce: &'a str) -> MessageParts<'a> {
        ("POST", "/api/runner/jobs", body, Some(7), ts, nonce)
    }

    #[test]
    fn canonical_format_is_exact() {
        let got = canonical("GET", "/x", b"", None, 5, "n1");
        let want = "shoephone-runner-v1\nGET\n/x\n\
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n-\n5\nn1\n";
        assert_eq!(String::from_utf8(got).unwrap(), want);
    }

    #[test]
    fn base64url_round_trips() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 250) as u8).collect();
            let text = b64url_encode(&data);
            assert!(!text.contains(['+', '/', '=']));
            assert_eq!(b64url_decode(&text).unwrap(), data);
        }
        assert!(b64url_decode("a").is_none());
        assert!(b64url_decode("ab+/").is_none());
    }

    #[test]
    fn signed_request_verifies() {
        let k = key();
        let mut v = verifier(&[("r1", &k)]);
        let sig = signed(&k, b"{}", NOW, "n1");
        assert!(!sig.contains(['\n', ' ']));
        assert_eq!(
            v.verify(at(NOW), "r1", &sig, parts(b"{}", NOW, "n1")),
            Ok(())
        );
    }

    #[test]
    fn tampered_body_is_refused() {
        let k = key();
        let mut v = verifier(&[("r1", &k)]);
        let sig = signed(&k, b"{}", NOW, "n1");
        assert_eq!(
            v.verify(at(NOW), "r1", &sig, parts(b"{\"x\":1}", NOW, "n1")),
            Err(Refusal::WrongRunner)
        );
    }

    #[test]
    fn replayed_nonce_is_refused() {
        let k = key();
        let mut v = verifier(&[("r1", &k)]);
        let sig = signed(&k, b"{}", NOW, "n1");
        assert_eq!(
            v.verify(at(NOW), "r1", &sig, parts(b"{}", NOW, "n1")),
            Ok(())
        );
        assert_eq!(
            v.verify(at(NOW + 5), "r1", &sig, parts(b"{}", NOW, "n1")),
            Err(Refusal::StaleSignature)
        );
    }

    #[test]
    fn old_timestamp_is_refused() {
        let k = key();
        let mut v = verifier(&[("r1", &k)]);
        let old = signed(&k, b"{}", NOW - 61, "n1");
        assert_eq!(
            v.verify(at(NOW), "r1", &old, parts(b"{}", NOW - 61, "n1")),
            Err(Refusal::StaleSignature)
        );
        let future = signed(&k, b"{}", NOW + 61, "n2");
        assert_eq!(
            v.verify(at(NOW), "r1", &future, parts(b"{}", NOW + 61, "n2")),
            Err(Refusal::StaleSignature)
        );
        let edge = signed(&k, b"{}", NOW - 60, "n3");
        assert_eq!(
            v.verify(at(NOW), "r1", &edge, parts(b"{}", NOW - 60, "n3")),
            Ok(())
        );
    }

    #[test]
    fn other_runners_key_is_refused() {
        let (k1, k2) = (key(), key());
        let mut v = verifier(&[("r1", &k1), ("r2", &k2)]);
        let sig = signed(&k2, b"{}", NOW, "n1");
        assert_eq!(
            v.verify(at(NOW), "r1", &sig, parts(b"{}", NOW, "n1")),
            Err(Refusal::WrongRunner)
        );
        assert_eq!(
            v.verify(at(NOW), "nobody", &sig, parts(b"{}", NOW, "n1")),
            Err(Refusal::WrongRunner)
        );
    }

    #[test]
    fn signature_from_another_namespace_is_refused() {
        let k = key();
        let mut v = verifier(&[("r1", &k)]);
        let msg = canonical("POST", "/api/runner/jobs", b"{}", Some(7), NOW, "n1");
        let pem = k
            .sign("file", HashAlg::Sha512, &msg)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        let sig = b64url_encode(pem.as_bytes());
        assert_eq!(
            v.verify(at(NOW), "r1", &sig, parts(b"{}", NOW, "n1")),
            Err(Refusal::WrongRunner)
        );
    }

    #[test]
    fn bad_signature_does_not_burn_the_nonce() {
        let k = key();
        let mut v = verifier(&[("r1", &k)]);
        assert_eq!(
            v.verify(at(NOW), "r1", "bogus", parts(b"{}", NOW, "n1")),
            Err(Refusal::WrongRunner)
        );
        assert!(v.seen.is_empty());
        let sig = signed(&k, b"{}", NOW, "n1");
        assert_eq!(
            v.verify(at(NOW), "r1", &sig, parts(b"{}", NOW, "n1")),
            Ok(())
        );
    }

    #[test]
    fn nonces_expire_and_the_cache_is_bounded() {
        let k = key();
        let mut v = verifier(&[("r1", &k)]);
        let sig = signed(&k, b"{}", NOW, "n1");
        assert_eq!(
            v.verify(at(NOW), "r1", &sig, parts(b"{}", NOW, "n1")),
            Ok(())
        );
        let later = signed(&k, b"{}", NOW + 200, "n2");
        assert_eq!(
            v.verify(at(NOW + 200), "r1", &later, parts(b"{}", NOW + 200, "n2")),
            Ok(())
        );
        assert_eq!(v.seen.len(), 1, "the old nonce is dropped on verify");

        for i in v.seen.len()..MAX_NONCES {
            v.seen.push_back((NOW + 200, format!("r1\nfill{i}")));
        }
        let full = signed(&k, b"{}", NOW + 200, "n3");
        assert_eq!(
            v.verify(at(NOW + 200), "r1", &full, parts(b"{}", NOW + 200, "n3")),
            Err(Refusal::StaleSignature)
        );
        assert_eq!(v.seen.len(), MAX_NONCES);
    }
}
