// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! Drives the daemon's real WebAuthn enrollment and approval endpoints with a
//! software authenticator: `ring` generates the ES256 keypair and signs, and
//! a small hand-rolled CBOR encoder builds the attestation object and COSE
//! key that the daemon's `webauthn-rs` verifier parses.
//!
//! Enrollment has no HTTP endpoint that mints a code (the console does), so
//! each test writes an [`EnrollCode`] straight into the [`Store`] the way
//! `shoephoned enroll` would, then drives `/api/enroll/start` and
//! `/api/enroll/finish` for real.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;
use ssh_key::sha2::{Digest, Sha256};

use shoephone::api::{ApproverState, ErrorReply, RequestBody, RequestState};
use shoephone::ca::UserCa;
use shoephone::client::Client;
use shoephone::config::{Config, PolicyConfig};
use shoephone::server::Daemon;
use shoephone::session::Session;
use shoephone::store::{EnrollCode, Store, sha256_hex};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

// ---------------------------------------------------------------------
// A minimal CBOR encoder. COSE keys and attestation objects only need
// unsigned/negative integers, byte strings, text strings, and maps, and the
// daemon's verifier looks values up by key rather than relying on encoding
// order, so this does not need to be canonical CBOR.
// ---------------------------------------------------------------------

enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Map(Vec<(Cbor, Cbor)>),
}

impl Cbor {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Int(v) => encode_int(*v, out),
            Cbor::Bytes(b) => {
                encode_head(2, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Cbor::Text(s) => {
                encode_head(3, s.len() as u64, out);
                out.extend_from_slice(s.as_bytes());
            }
            Cbor::Map(entries) => {
                encode_head(5, entries.len() as u64, out);
                for (k, v) in entries {
                    k.encode(out);
                    v.encode(out);
                }
            }
        }
    }
}

fn encode_int(v: i64, out: &mut Vec<u8>) {
    if v >= 0 {
        encode_head(0, v as u64, out);
    } else {
        // CBOR negative integers encode -1-n as major type 1 with argument n.
        encode_head(1, (-1 - v) as u64, out);
    }
}

fn encode_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

// ---------------------------------------------------------------------
// A software security key: one ES256 keypair, a 16-byte credential id, and
// a signature counter. `register` produces the JSON `/api/enroll/finish`
// expects as `credential`; `assert*` produce what `/api/approve/finish`
// expects, with hooks to sign over the wrong origin or a chosen counter for
// the negative-path tests.
// ---------------------------------------------------------------------

struct SoftKey {
    key: EcdsaKeyPair,
    cred_id: Vec<u8>,
    counter: u32,
    rp_id: String,
    origin: String,
}

impl SoftKey {
    fn new(rp_id: &str, origin: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("generate ES256 key");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("parse the key just generated");
        let mut cred_id = vec![0u8; 16];
        rng.fill(&mut cred_id).expect("random credential id");
        SoftKey {
            key,
            cred_id,
            counter: 0,
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
        }
    }

    fn client_data(&self, type_: &str, challenge_b64url: &str, origin: &str) -> Vec<u8> {
        format!(
            "{{\"type\":\"{type_}\",\"challenge\":\"{challenge_b64url}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}"
        )
        .into_bytes()
    }

    fn cose_key(&self) -> Vec<u8> {
        let public = self.key.public_key().as_ref();
        // Uncompressed SEC1 point: 0x04 || x(32) || y(32).
        let x = public[1..33].to_vec();
        let y = public[33..65].to_vec();
        Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Int(2)),  // kty: EC2
            (Cbor::Int(3), Cbor::Int(-7)), // alg: ES256
            (Cbor::Int(-1), Cbor::Int(1)), // crv: P-256
            (Cbor::Int(-2), Cbor::Bytes(x)),
            (Cbor::Int(-3), Cbor::Bytes(y)),
        ])
        .to_bytes()
    }

    fn attestation_object(&self, flags: u8) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&sha256(self.rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID: none
        auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        auth_data.extend_from_slice(&self.cose_key());

        Cbor::Map(vec![
            (Cbor::Text("fmt".to_owned()), Cbor::Text("none".to_owned())),
            (Cbor::Text("attStmt".to_owned()), Cbor::Map(Vec::new())),
            (Cbor::Text("authData".to_owned()), Cbor::Bytes(auth_data)),
        ])
        .to_bytes()
    }

    /// The JSON `/api/enroll/finish` expects as `credential`.
    fn register(&self, challenge_b64url: &str, flags: u8) -> serde_json::Value {
        let client_data = self.client_data("webauthn.create", challenge_b64url, &self.origin);
        let attestation_object = self.attestation_object(flags);
        let id = b64url(&self.cred_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "attestationObject": b64url(&attestation_object),
                "clientDataJSON": b64url(&client_data),
                "transports": ["internal"],
            },
            "extensions": {},
        })
    }

    /// A normal assertion: increments the counter, signs over this key's own
    /// origin.
    fn assert(
        &mut self,
        challenge_b64url: &str,
        flags: u8,
        user_handle_b64url: &str,
    ) -> serde_json::Value {
        self.counter += 1;
        let counter = self.counter;
        self.assert_as(
            challenge_b64url,
            flags,
            user_handle_b64url,
            &self.origin.clone(),
            counter,
        )
    }

    /// An assertion signed as if the client page were loaded from `origin`
    /// instead of this key's enrolled origin.
    fn assert_with_origin(
        &mut self,
        challenge_b64url: &str,
        flags: u8,
        user_handle_b64url: &str,
        origin: &str,
    ) -> serde_json::Value {
        self.counter += 1;
        let counter = self.counter;
        self.assert_as(challenge_b64url, flags, user_handle_b64url, origin, counter)
    }

    /// An assertion carrying an explicit signature counter, for the
    /// counter-regression test. Does not touch `self.counter`.
    fn assert_with_counter(
        &self,
        challenge_b64url: &str,
        flags: u8,
        user_handle_b64url: &str,
        counter: u32,
    ) -> serde_json::Value {
        self.assert_as(
            challenge_b64url,
            flags,
            user_handle_b64url,
            &self.origin,
            counter,
        )
    }

    fn assert_as(
        &self,
        challenge_b64url: &str,
        flags: u8,
        user_handle_b64url: &str,
        origin: &str,
        counter: u32,
    ) -> serde_json::Value {
        let client_data = self.client_data("webauthn.get", challenge_b64url, origin);
        let mut auth_data = Vec::with_capacity(32 + 1 + 4);
        auth_data.extend_from_slice(&sha256(self.rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&sha256(&client_data));
        let rng = SystemRandom::new();
        let signature = self.key.sign(&rng, &signed).expect("ring signature");

        let id = b64url(&self.cred_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "authenticatorData": b64url(&auth_data),
                "clientDataJSON": b64url(&client_data),
                "signature": b64url(signature.as_ref()),
                "userHandle": user_handle_b64url,
            },
            "extensions": {},
        })
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch")
        .as_secs()
}

// ---------------------------------------------------------------------
// Daemon plumbing, copied from tests/loop.rs (not imported: integration
// test binaries are separate crates).
// ---------------------------------------------------------------------

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("shoephone-webauthn-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn start(dir: &Path) -> (Client, Arc<Daemon>) {
    let ca_key = dir.join("user_ca");
    UserCa::generate("test CA")
        .unwrap()
        .write_openssh_file(&ca_key)
        .unwrap();
    let mut principals = BTreeMap::new();
    principals.insert("web01".to_owned(), "agent-admin:web01".to_owned());
    let config = Config {
        listen: "127.0.0.1:0".into(),
        state_dir: dir.to_path_buf(),
        ca_key,
        rp_id: "localhost".into(),
        rp_origin: "http://localhost".into(),
        rp_name: "test".into(),
        principals,
        policy: PolicyConfig::default(),
        notify: None,
        allow_synced_credentials: false,
        apns: None,
        access: None,
    };
    let daemon = Arc::new(Daemon::new(config).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = daemon.clone().router();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (Client::new(&format!("http://{addr}")), daemon)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

fn test_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

/// Assert a 200 and decode the body as `T`, panicking with the raw body on
/// any other status so a positive-path failure shows the daemon's own
/// explanation rather than a generic deserialization error.
fn expect_ok<T: serde::de::DeserializeOwned>(mut resp: ureq::http::Response<ureq::Body>) -> T {
    let status = resp.status();
    if status != 200 {
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        panic!("expected 200, got {status}: {text}");
    }
    resp.body_mut().read_json().expect("valid JSON body")
}

/// Assert an exact status and error `code`, per the house rule that a
/// negative case checks the machine-readable code, not just the HTTP status.
fn expect_error(
    mut resp: ureq::http::Response<ureq::Body>,
    want_status: u16,
    want_code: &str,
) -> ErrorReply {
    let status = resp.status().as_u16();
    let body: ErrorReply = resp.body_mut().read_json().expect("valid JSON error body");
    assert_eq!(status, want_status, "{body:?}");
    assert_eq!(body.code, want_code, "{body:?}");
    body
}

// ---------------------------------------------------------------------
// Enrollment. The daemon has no HTTP endpoint that mints a code (the
// console's `shoephoned enroll` does), so tests write the code straight into
// the store, the way the console would.
// ---------------------------------------------------------------------

const ENROLL_CODE: &str = "TESTCODE";

fn enroll_start(
    dir: &Path,
    base: &str,
    agent: &ureq::Agent,
    device_name: &str,
) -> (SoftKey, CreationChallengeResponse) {
    Store::new(dir)
        .save_enroll_code(&EnrollCode {
            sha256: sha256_hex(ENROLL_CODE),
            device_name: device_name.to_owned(),
            expires_at: now_unix() + 600,
            failures: 0,
        })
        .expect("write the enrollment code the console would have written");
    let resp = agent
        .post(format!("{base}/api/enroll/start"))
        .send_json(json!({ "code": ENROLL_CODE }))
        .unwrap();
    let ccr: CreationChallengeResponse = expect_ok(resp);
    (SoftKey::new("localhost", "http://localhost"), ccr)
}

/// Enroll one device end to end. Returns the software key, the enrolled
/// user handle (base64url, for later assertions' `userHandle`), and the
/// one-time push secret `/api/enroll/finish` hands back.
fn enroll(
    dir: &Path,
    base: &str,
    agent: &ureq::Agent,
    device_name: &str,
) -> (SoftKey, String, String) {
    let (key, ccr) = enroll_start(dir, base, agent, device_name);
    let challenge_b64 = b64url(ccr.public_key.challenge.as_slice());
    let user_handle_b64 = b64url(ccr.public_key.user.id.as_slice());
    let credential = key.register(&challenge_b64, 0x45); // UP | UV | AT
    let resp = agent
        .post(format!("{base}/api/enroll/finish"))
        .send_json(json!({ "code": ENROLL_CODE, "credential": credential }))
        .unwrap();
    let body: serde_json::Value = expect_ok(resp);
    let push_secret = body["push_secret"]
        .as_str()
        .expect("enroll/finish returns push_secret")
        .to_owned();
    (key, user_handle_b64, push_secret)
}

fn request_body(session_key: &str, reason: &str) -> RequestBody {
    RequestBody {
        host: "web01".into(),
        public_key: session_key.to_owned(),
        requester: "agent".into(),
        reason: reason.into(),
        context: None,
        window_minutes: None,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enroll_approve_issue_with_a_real_assertion() {
    let dir = scratch("enroll-approve-issue");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let base = client.base().to_owned();
    let agent = test_agent();

    let (mut key, user_handle_b64, push_secret) = enroll(&dir, &base, &agent, "test-phone");

    let session = Session::new(dir.join("session"));
    let session_key = session.public_key().unwrap();

    let c = client.clone();
    let body = request_body(&session_key, "webauthn test: full approval");
    let reply = blocking(move || c.request(&body)).await.unwrap();

    let resp = agent.get(format!("{base}/api/pending")).call().unwrap();
    let state: ApproverState = expect_ok(resp);
    let pending = state.pending.expect("the request just filed is pending");
    // The daemon stores the canonical form of the requested key (no
    // trailing comment), not the raw line the CLI sent.
    let canonical_session_key = shoephone::ca::canonical_public_key(&session_key).unwrap();
    assert_eq!(pending.public_key, canonical_session_key);
    assert_eq!(pending.nonce.len(), 64);
    assert!(
        pending
            .nonce
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "nonce is not lowercase hex: {}",
        pending.nonce
    );

    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply.id }))
        .unwrap();
    let rcr: RequestChallengeResponse = expect_ok(resp);

    // The scope-binding property: the challenge the approver is asked to
    // sign is SHA-256 of the exact enforced-scope string, built here from
    // the pending view's own fields rather than by calling back into the
    // daemon's own bytes_to_sign/bound_challenge helpers.
    let expected_bytes = format!(
        "shoephone-scope-v1\nhost={}\nprincipal={}\nkey={}\nends_at={}\nnonce={}\n",
        pending.host, pending.principal, pending.public_key, pending.ends_at, pending.nonce
    );
    let expected_challenge = b64url(&sha256(expected_bytes.as_bytes()));
    assert_eq!(
        b64url(rcr.public_key.challenge.as_slice()),
        expected_challenge
    );

    assert_eq!(rcr.public_key.allow_credentials.len(), 1);
    assert_eq!(
        rcr.public_key.allow_credentials[0].id.as_slice(),
        key.cred_id.as_slice()
    );

    let challenge_b64 = b64url(rcr.public_key.challenge.as_slice());
    let assertion = key.assert(&challenge_b64, 0x05, &user_handle_b64); // UP | UV

    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(json!({ "id": reply.id, "credential": assertion }))
        .unwrap();
    let body: serde_json::Value = expect_ok(resp);
    assert_eq!(body["approved"], reply.id);

    let c = client.clone();
    let id = reply.id;
    match blocking(move || c.poll(id)).await.unwrap() {
        RequestState::Approved { .. } => {}
        other => panic!("expected an approved window, got {other:?}"),
    }

    let c = client.clone();
    let session_key_for_issue = session_key.clone();
    let issued = blocking(move || c.issue("web01", &session_key_for_issue))
        .await
        .unwrap();
    assert!(!issued.certificate.is_empty());

    let resp = agent
        .post(format!("{base}/api/push/register"))
        .send_json(json!({
            "credential_id": b64url(&key.cred_id),
            "token": "00ff",
            "secret": push_secret,
            "kinds": ["request_waiting"],
        }))
        .unwrap();
    let _: serde_json::Value = expect_ok(resp);

    let resp = agent
        .post(format!("{base}/api/push/register"))
        .send_json(json!({
            "credential_id": b64url(&key.cred_id),
            "token": "00ff",
            "secret": "0000",
            "kinds": ["request_waiting"],
        }))
        .unwrap();
    expect_error(resp, 403, "bad_secret");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assertion_over_the_wrong_origin_is_rejected() {
    let dir = scratch("wrong-origin");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let base = client.base().to_owned();
    let agent = test_agent();

    let (mut key, user_handle_b64, _push_secret) = enroll(&dir, &base, &agent, "test-phone");

    let session = Session::new(dir.join("session"));
    let session_key = session.public_key().unwrap();

    let c = client.clone();
    let body = request_body(&session_key, "webauthn test: wrong origin");
    let reply = blocking(move || c.request(&body)).await.unwrap();

    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply.id }))
        .unwrap();
    let rcr: RequestChallengeResponse = expect_ok(resp);
    let challenge_b64 = b64url(rcr.public_key.challenge.as_slice());

    let bad_assertion = key.assert_with_origin(
        &challenge_b64,
        0x05,
        &user_handle_b64,
        "https://evil.example",
    );
    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(json!({ "id": reply.id, "credential": bad_assertion }))
        .unwrap();
    expect_error(resp, 403, "assertion_rejected");

    let c = client.clone();
    let id = reply.id;
    assert_eq!(
        blocking(move || c.poll(id)).await.unwrap(),
        RequestState::Pending,
        "a failed ceremony must not consume the request"
    );

    // A fresh ceremony (the failed finish already consumed the first one)
    // with a correctly signed assertion succeeds.
    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply.id }))
        .unwrap();
    let rcr: RequestChallengeResponse = expect_ok(resp);
    let challenge_b64 = b64url(rcr.public_key.challenge.as_slice());
    let good_assertion = key.assert(&challenge_b64, 0x05, &user_handle_b64);
    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(json!({ "id": reply.id, "credential": good_assertion }))
        .unwrap();
    let body: serde_json::Value = expect_ok(resp);
    assert_eq!(body["approved"], reply.id);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assertion_over_a_different_challenge_is_rejected() {
    let dir = scratch("wrong-challenge");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let base = client.base().to_owned();
    let agent = test_agent();

    let (mut key, user_handle_b64, _push_secret) = enroll(&dir, &base, &agent, "test-phone");

    let session = Session::new(dir.join("session"));
    let session_key = session.public_key().unwrap();

    let c = client.clone();
    let body = request_body(&session_key, "webauthn test: wrong challenge");
    let reply = blocking(move || c.request(&body)).await.unwrap();

    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply.id }))
        .unwrap();
    let _rcr: RequestChallengeResponse = expect_ok(resp);

    let wrong_challenge = b64url(&[7u8; 32]);
    let bad_assertion = key.assert(&wrong_challenge, 0x05, &user_handle_b64);
    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(json!({ "id": reply.id, "credential": bad_assertion }))
        .unwrap();
    expect_error(resp, 403, "assertion_rejected");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assertion_cannot_be_replayed() {
    let dir = scratch("replay");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let base = client.base().to_owned();
    let agent = test_agent();

    let (mut key, user_handle_b64, _push_secret) = enroll(&dir, &base, &agent, "test-phone");

    let session = Session::new(dir.join("session"));
    let session_key = session.public_key().unwrap();

    let c = client.clone();
    let body = request_body(&session_key, "webauthn test: replay");
    let reply = blocking(move || c.request(&body)).await.unwrap();

    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply.id }))
        .unwrap();
    let rcr: RequestChallengeResponse = expect_ok(resp);
    let challenge_b64 = b64url(rcr.public_key.challenge.as_slice());
    let assertion = key.assert(&challenge_b64, 0x05, &user_handle_b64);
    let finish_body = json!({ "id": reply.id, "credential": assertion });

    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(finish_body.clone())
        .unwrap();
    let body: serde_json::Value = expect_ok(resp);
    assert_eq!(body["approved"], reply.id);

    // Replaying the identical finish body: the ceremony state was consumed
    // by the first call, win or lose.
    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(finish_body)
        .unwrap();
    expect_error(resp, 409, "no_ceremony");

    // The request itself is gone too (it became a window), so starting a
    // ceremony for it again finds nothing to approve.
    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply.id }))
        .unwrap();
    expect_error(resp, 404, "no_such_request");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_presence_is_required() {
    let dir = scratch("no-up");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let base = client.base().to_owned();
    let agent = test_agent();

    let (mut key, user_handle_b64, _push_secret) = enroll(&dir, &base, &agent, "test-phone");

    let session = Session::new(dir.join("session"));
    let session_key = session.public_key().unwrap();

    let c = client.clone();
    let body = request_body(&session_key, "webauthn test: no user presence");
    let reply = blocking(move || c.request(&body)).await.unwrap();

    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply.id }))
        .unwrap();
    let rcr: RequestChallengeResponse = expect_ok(resp);
    let challenge_b64 = b64url(rcr.public_key.challenge.as_slice());

    let assertion = key.assert(&challenge_b64, 0x04, &user_handle_b64); // UV only, no UP
    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(json!({ "id": reply.id, "credential": assertion }))
        .unwrap();
    expect_error(resp, 403, "assertion_rejected");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_eligible_credential_cannot_enroll() {
    let dir = scratch("synced-cred");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let base = client.base().to_owned();
    let agent = test_agent();

    let (key, ccr) = enroll_start(&dir, &base, &agent, "synced-phone");
    let challenge_b64 = b64url(ccr.public_key.challenge.as_slice());
    let credential = key.register(&challenge_b64, 0x45 | 0x08); // UP | UV | AT | BE

    let resp = agent
        .post(format!("{base}/api/enroll/finish"))
        .send_json(json!({ "code": ENROLL_CODE, "credential": credential }))
        .unwrap();
    expect_error(resp, 403, "synced_credential");

    let c = client.clone();
    let status = blocking(move || c.status()).await.unwrap();
    assert!(status.devices.is_empty(), "{:?}", status.devices);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_regressing_counter_is_rejected() {
    let dir = scratch("counter-regression");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let base = client.base().to_owned();
    let agent = test_agent();

    let (key, user_handle_b64, _push_secret) = enroll(&dir, &base, &agent, "test-phone");

    let session = Session::new(dir.join("session"));
    let session_key = session.public_key().unwrap();

    // First window: approve with a forced counter of 5.
    let c = client.clone();
    let body = request_body(
        &session_key,
        "webauthn test: counter regression, first window",
    );
    let reply1 = blocking(move || c.request(&body)).await.unwrap();

    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply1.id }))
        .unwrap();
    let rcr: RequestChallengeResponse = expect_ok(resp);
    let challenge_b64 = b64url(rcr.public_key.challenge.as_slice());
    let assertion = key.assert_with_counter(&challenge_b64, 0x05, &user_handle_b64, 5);
    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(json!({ "id": reply1.id, "credential": assertion }))
        .unwrap();
    let body: serde_json::Value = expect_ok(resp);
    assert_eq!(body["approved"], reply1.id);

    // Second window on the same host and key (the first one stays open; two
    // windows per host is allowed).
    let c = client.clone();
    let body = request_body(
        &session_key,
        "webauthn test: counter regression, second window",
    );
    let reply2 = blocking(move || c.request(&body)).await.unwrap();

    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply2.id }))
        .unwrap();
    let rcr: RequestChallengeResponse = expect_ok(resp);
    let challenge_b64 = b64url(rcr.public_key.challenge.as_slice());
    let stale = key.assert_with_counter(&challenge_b64, 0x05, &user_handle_b64, 3);
    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(json!({ "id": reply2.id, "credential": stale }))
        .unwrap();
    expect_error(resp, 403, "assertion_rejected");

    // The failed finish consumed that ceremony; start a fresh one and sign
    // with a counter that moves forward from the stored high-water mark.
    let resp = agent
        .post(format!("{base}/api/approve/start"))
        .send_json(json!({ "id": reply2.id }))
        .unwrap();
    let rcr: RequestChallengeResponse = expect_ok(resp);
    let challenge_b64 = b64url(rcr.public_key.challenge.as_slice());
    let fresh = key.assert_with_counter(&challenge_b64, 0x05, &user_handle_b64, 6);
    let resp = agent
        .post(format!("{base}/api/approve/finish"))
        .send_json(json!({ "id": reply2.id, "credential": fresh }))
        .unwrap();
    let body: serde_json::Value = expect_ok(resp);
    assert_eq!(body["approved"], reply2.id);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forgetting_a_device_removes_only_that_one_and_survives_reload() {
    // Enrolment is the only way to get a real webauthn credential into
    // devices.json, so removal is tested against one rather than against a
    // hand-written fixture that could drift from what the daemon writes.
    let dir = scratch("forget-device");
    let (client, _daemon) = start(&dir).await;
    let base = client.base().to_owned();
    let agent = test_agent();

    let (_k1, _h1, _s1) = enroll(&dir, &base, &agent, "old-phone");
    let (_k2, _h2, _s2) = enroll(&dir, &base, &agent, "new-phone");

    let store = Store::new(&dir);
    assert_eq!(store.load_devices().unwrap().len(), 2, "both enrolled");

    assert_eq!(
        store.forget_device("ghost").unwrap(),
        None,
        "a handle nobody has is not a removal"
    );
    assert_eq!(
        store.load_devices().unwrap().len(),
        2,
        "a miss must not disturb the file"
    );

    let old_handle = store
        .load_devices()
        .unwrap()
        .into_iter()
        .find(|d| d.name == "old-phone")
        .unwrap()
        .handle();
    assert_eq!(store.forget_device(&old_handle).unwrap(), Some(1));

    // Re-read from disk, not from memory: the point of the verb is that the
    // next `serve` loads a list without the removed device in it.
    let left = Store::new(&dir).load_devices().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].name, "new-phone");
    assert!(
        left[0].push_secret_sha256.is_some(),
        "the surviving device keeps its push secret"
    );

    let last = store.load_devices().unwrap()[0].handle();
    assert_eq!(
        store.forget_device(&last).unwrap(),
        Some(0),
        "removing the last approver is allowed; only the console can undo it"
    );
    assert!(Store::new(&dir).load_devices().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_devices_may_share_a_name_and_are_still_separable() {
    // The case that bit: a replacement enrolled under the name it replaces.
    // Both answer to "7phone"; only the handle tells them apart, and a
    // name-matching removal would take the working one with the stale one.
    let dir = scratch("same-name");
    let (client, _daemon) = start(&dir).await;
    let base = client.base().to_owned();
    let agent = test_agent();

    let _ = enroll(&dir, &base, &agent, "7phone");
    let _ = enroll(&dir, &base, &agent, "7phone");

    let store = Store::new(&dir);
    let devices = store.load_devices().unwrap();
    assert_eq!(devices.len(), 2, "one name, two devices");
    let handles: Vec<String> = devices.iter().map(|d| d.handle()).collect();
    assert_ne!(handles[0], handles[1], "handles distinguish them");

    assert_eq!(
        store.match_devices("7phone").unwrap().len(),
        2,
        "the name is ambiguous and must be seen to be"
    );
    assert_eq!(
        store.match_devices(&handles[0]).unwrap().len(),
        1,
        "a handle is not"
    );

    assert_eq!(store.forget_device(&handles[0]).unwrap(), Some(1));
    let left = Store::new(&dir).load_devices().unwrap();
    assert_eq!(left.len(), 1, "the other one survives");
    assert_eq!(left[0].handle(), handles[1]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrollment_returns_a_secret_only_once_and_stores_its_hash() {
    let dir = scratch("secret-once");
    let (client, _daemon) = start(&dir).await;
    let base = client.base().to_owned();
    let agent = test_agent();

    let (_key, _user_handle_b64, push_secret) = enroll(&dir, &base, &agent, "test-phone");

    let contents = std::fs::read_to_string(dir.join("devices.json")).unwrap();
    let expected_hash = sha256_hex(&push_secret);
    assert!(
        contents.contains(&expected_hash),
        "devices.json is missing push_secret_sha256:\n{contents}"
    );
    assert!(
        !contents.contains(&push_secret),
        "devices.json must not contain the raw push secret:\n{contents}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
