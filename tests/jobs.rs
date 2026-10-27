// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The agent-side Terraform endpoints, driven by the real client.

mod common;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use shoephone::api::{ApplyBody, TrustBody};
use shoephone::client::Error;
use shoephone::exit::Status;

use common::*;

fn trust_body(project: &str, archive: &[u8]) -> TrustBody {
    TrustBody {
        project: project.into(),
        archive: STANDARD.encode(archive),
        reason: "jobs test: trust".into(),
        requester: "test".into(),
        context: Some("https://claude.ai/code/session_test".into()),
    }
}

fn apply_body(project: &str, manifest: &str) -> ApplyBody {
    ApplyBody {
        project: project.into(),
        manifest: manifest.into(),
        allow_destroy: false,
        reason: "jobs test: apply".into(),
        requester: "test".into(),
        context: None,
    }
}

fn code(e: &Error) -> (u16, String) {
    match e {
        Error::Daemon { http, reply } => (*http, reply.code.clone()),
        other => panic!("expected a daemon refusal, got {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_request_returns_match_code() {
    let dir = scratch("jobs-trust");
    let (client, _d) = start_projects(&dir, &[("net", "r1")]).await;
    let client = Arc::new(client);

    let c = client.clone();
    let body = trust_body("net", b"not really a tar");
    let reply = blocking(move || c.trust(&body)).await.unwrap();
    assert_eq!(reply.match_code.len(), 9);
    assert!(reply.expires > 0);

    let c = client.clone();
    let id = reply.id;
    let status = blocking(move || c.job(id)).await.unwrap();
    assert_eq!(status.id, id);
    assert_eq!(status.project, "net");
    assert_eq!(status.kind, "trust");
    assert_eq!(status.state, "queued");
    assert_eq!(status.result, None);

    let base = client.base().to_owned();
    let ledger = blocking(move || {
        ureq::get(format!("{base}/api/ledger"))
            .call()
            .unwrap()
            .into_body()
            .read_to_string()
            .unwrap()
    })
    .await;
    assert!(ledger.contains("trust_requested"), "{ledger}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_for_unknown_project_is_400_unknown_project() {
    let dir = scratch("jobs-unknown");
    let (client, _d) = start_projects(&dir, &[("net", "r1")]).await;
    let body = apply_body("nope", "{}");
    let err = blocking(move || client.apply(&body)).await.unwrap_err();
    assert_eq!(code(&err), (400, "unknown_project".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_archive_is_413() {
    let dir = scratch("jobs-big");
    let (client, _d) = start_projects(&dir, &[("net", "r1")]).await;
    let client = Arc::new(client);

    let c = client.clone();
    let body = trust_body("net", &vec![0u8; 16 * 1024 * 1024 + 1]);
    let err = blocking(move || c.trust(&body)).await.unwrap_err();
    assert_eq!(code(&err).0, 413, "{err}");

    let c = client.clone();
    let mut body = trust_body("net", b"x");
    body.archive = "!!not base64!!".into();
    let err = blocking(move || c.trust(&body)).await.unwrap_err();
    assert_eq!(code(&err), (400, "bad_archive".to_owned()));

    let c = client.clone();
    let body = apply_body("net", &"x".repeat(64 * 1024 + 1));
    let err = blocking(move || c.apply(&body)).await.unwrap_err();
    assert_eq!(code(&err).0, 413, "{err}");

    let c = client.clone();
    let body = trust_body("net", &vec![0u8; 16 * 1024 * 1024]);
    blocking(move || c.trust(&body)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_request_while_job_active_is_busy() {
    let dir = scratch("jobs-busy");
    let (client, _d) = start_projects(&dir, &[("net", "r1")]).await;
    let client = Arc::new(client);

    let c = client.clone();
    let body = trust_body("net", b"one");
    blocking(move || c.trust(&body)).await.unwrap();

    let c = client.clone();
    let body = apply_body("net", "{}");
    let err = blocking(move || c.apply(&body)).await.unwrap_err();
    assert_eq!(code(&err), (409, "busy".to_owned()));
    assert_eq!(err.status(), Status::RetryClean);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_project_declines_waiting_job() {
    let dir = scratch("jobs-kill");
    let (client, _d) = start_projects(&dir, &[("net", "r1")]).await;
    let client = Arc::new(client);

    let c = client.clone();
    let body = apply_body("net", "{}");
    let id = blocking(move || c.apply(&body)).await.unwrap().id;

    let c = client.clone();
    blocking(move || c.kill_project("net")).await.unwrap();

    let c = client.clone();
    let status = blocking(move || c.job(id)).await.unwrap();
    assert_eq!(status.state, "done");
    assert_eq!(status.result.as_deref(), Some("killed"));

    let c = client.clone();
    let err = blocking(move || c.kill_project("nope")).await.unwrap_err();
    assert_eq!(code(&err), (400, "unknown_project".to_owned()));

    let c = client.clone();
    let body = apply_body("net", "{}");
    blocking(move || c.apply(&body)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_status_never_contains_manifest_values() {
    let dir = scratch("jobs-secret");
    let (client, _d) = start_projects(&dir, &[("net", "r1")]).await;
    let base = client.base().to_owned();
    let client = Arc::new(client);

    let mut body = apply_body("net", r#"{"secret_looking":"VALUE123"}"#);
    body.reason = "jobs test: secret".into();
    let reply = {
        let c = client.clone();
        blocking(move || c.apply(&body)).await.unwrap()
    };
    let id = reply.id;
    let mut seen = vec![serde_json::to_string(&reply).unwrap()];

    let c = client.clone();
    blocking(move || c.kill_project("net")).await.unwrap();
    let c = client.clone();
    let mut body = trust_body("net", b"tar bytes holding VALUE123");
    body.reason = "jobs test: secret".into();
    let trust_reply = blocking(move || c.trust(&body)).await.unwrap();
    seen.push(serde_json::to_string(&trust_reply).unwrap());
    let tid = trust_reply.id;
    let c = client.clone();
    seen.push(serde_json::to_string(&blocking(move || c.job(tid)).await.unwrap()).unwrap());
    let c = client.clone();
    blocking(move || c.kill_project("net")).await.unwrap();

    let c = client.clone();
    seen.push(serde_json::to_string(&blocking(move || c.job(id)).await.unwrap()).unwrap());

    seen.push(
        blocking(move || {
            ureq::get(format!("{base}/api/job/{id}"))
                .call()
                .unwrap()
                .into_body()
                .read_to_string()
                .unwrap()
        })
        .await,
    );

    let c = client.clone();
    blocking(move || c.kill_project("net")).await.unwrap();
    let base = client.base().to_owned();
    seen.push(
        blocking(move || {
            ureq::post(format!("{base}/api/kill"))
                .send_json(serde_json::json!({ "project": "net" }))
                .unwrap()
                .into_body()
                .read_to_string()
                .unwrap()
        })
        .await,
    );

    let c = client.clone();
    seen.push(serde_json::to_string(&blocking(move || c.job(id)).await.unwrap()).unwrap());

    for body in &seen {
        assert!(!body.contains("VALUE123"), "{body}");
    }
}

// ---------------------------------------------------------------------
// Runner endpoints
// ---------------------------------------------------------------------

use serde_json::{Value, json};
use shoephone::store::{Store, sha256_hex};
use ssh_key::PrivateKey;

/// A signing runner pointed at a daemon.
#[derive(Clone)]
struct Rig {
    base: String,
    key: PrivateKey,
    name: String,
}

impl Rig {
    fn new(client: &shoephone::client::Client, name: &str, key: &PrivateKey) -> Rig {
        Rig {
            base: client.base().to_owned(),
            key: key.clone(),
            name: name.to_owned(),
        }
    }

    async fn post(&self, path: &str, body: Value, job: Option<u64>) -> RunnerReply {
        let r = self.clone();
        let path = path.to_owned();
        blocking(move || runner_post(&r.base, &r.key, &r.name, &path, &body, job)).await
    }

    async fn get(&self, path: &str, job: Option<u64>) -> RunnerReply {
        let r = self.clone();
        let path = path.to_owned();
        blocking(move || runner_call(&r.base, &r.key, &r.name, "GET", &path, b"", job)).await
    }

    async fn poll(&self) -> Value {
        let reply = self.post("/api/runner/poll", json!({}), None).await;
        assert_eq!(reply.http, 200, "{}", String::from_utf8_lossy(&reply.body));
        reply.json()
    }
}

fn hex(c: char) -> String {
    c.to_string().repeat(64)
}

/// A well-formed apply scope and the display that backs it.
fn apply_pair(
    project: &str,
    lines: &[&str],
    counts: [u32; 4],
    destructive: bool,
) -> (Value, Value) {
    let address_text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let manifest = r#"{"region":"us-east-1"}"#;
    let scope = json!({
        "kind": "apply",
        "project": project,
        "revision": hex('1'),
        "schema": hex('2'),
        "manifest": sha256_hex(manifest),
        "baseline_manifest": null,
        "baseline_status": "none",
        "plan": hex('3'),
        "destructive": destructive,
        "counts": {
            "create": counts[0], "update": counts[1],
            "replace": counts[2], "delete": counts[3],
        },
        "addresses": sha256_hex(&address_text),
    });
    let display = json!({
        "manifest": manifest,
        "baseline_manifest": null,
        "address_text": address_text,
    });
    (scope, display)
}

fn trust_pair(project: &str) -> (Value, Value) {
    let diff = "+ resource added\n";
    let scope = json!({
        "kind": "trust",
        "project": project,
        "baseline": null,
        "candidate": hex('c'),
        "diff": sha256_hex(diff),
        "schema": hex('5'),
        "policy_version": 1,
        "files_changed": 1,
        "lines_added": 1,
        "lines_removed": 0,
        "schema_changed": false,
    });
    (scope, json!({ "diff": diff }))
}

async fn file_apply(client: &Arc<shoephone::client::Client>, project: &str) -> u64 {
    let c = client.clone();
    let body = apply_body(project, r#"{"agent":"manifest"}"#);
    blocking(move || c.apply(&body)).await.unwrap().id
}

async fn file_trust(client: &Arc<shoephone::client::Client>, project: &str, tar: &[u8]) -> u64 {
    let c = client.clone();
    let body = trust_body(project, tar);
    blocking(move || c.trust(&body)).await.unwrap().id
}

async fn submit(rig: &Rig, id: u64, scope: Value, display: Value) -> RunnerReply {
    rig.post(
        "/api/runner/submit",
        json!({ "id": id, "scope": scope, "display": display }),
        Some(id),
    )
    .await
}

async fn approve_job(base: &str, id: u64) {
    let base = base.to_owned();
    blocking(move || {
        ureq::post(format!("{base}/api/test/approve_job"))
            .send_json(json!({ "id": id }))
            .unwrap();
    })
    .await;
}

async fn status_of(client: &Arc<shoephone::client::Client>, id: u64) -> shoephone::api::JobStatus {
    let c = client.clone();
    blocking(move || c.job(id)).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_poll_is_401() {
    let dir = scratch("jobs-unsigned");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let base = client.base().to_owned();

    let b = base.clone();
    let status = blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        agent
            .post(format!("{b}/api/runner/poll"))
            .send("{}")
            .unwrap()
            .status()
            .as_u16()
    })
    .await;
    assert_eq!(status, 401);

    let stranger = Rig::new(&client, "r1", &runner_key());
    let reply = stranger.post("/api/runner/poll", json!({}), None).await;
    assert_eq!(reply.http, 401);
    assert_eq!(reply.code(), "wrong_runner");

    let unknown = Rig::new(&client, "nobody", &key);
    assert_eq!(
        unknown.post("/api/runner/poll", json!({}), None).await.http,
        401
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_hands_queued_job_to_its_runner_only() {
    let dir = scratch("jobs-poll");
    let (k1, k2) = (runner_key(), runner_key());
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &k1), ("r2", &k2)]).await;
    let (r1, r2) = (Rig::new(&client, "r1", &k1), Rig::new(&client, "r2", &k2));
    let client = Arc::new(client);

    assert!(r1.poll().await.is_null());
    let id = file_apply(&client, "net").await;

    assert!(r2.poll().await.is_null());
    assert_eq!(status_of(&client, id).await.state, "queued");

    let job = r1.poll().await;
    assert_eq!(job["id"], id);
    assert_eq!(job["project"], "net");
    assert_eq!(job["kind"], "apply");
    assert_eq!(job["state"], "working");
    assert_eq!(job["manifest"], r#"{"agent":"manifest"}"#);
    assert_eq!(job["allow_destroy"], false);
    assert!(job["trusted"].is_null());
    assert_eq!(status_of(&client, id).await.state, "working");
    assert!(r1.poll().await.is_null());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_with_digest_not_matching_display_is_400() {
    let dir = scratch("jobs-digest");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);

    let id = file_apply(&client, "net").await;
    rig.poll().await;

    let (scope, display) = apply_pair("net", &["create a.b"], [1, 0, 0, 0], false);
    let mut bad = display.clone();
    bad["address_text"] = json!("create a.c\n");
    let reply = submit(&rig, id, scope.clone(), bad).await;
    assert_eq!(
        (reply.http, reply.code().as_str()),
        (400, "inconsistent_scope")
    );

    let mut bad = display.clone();
    bad["manifest"] = json!("another manifest");
    assert_eq!(submit(&rig, id, scope.clone(), bad).await.http, 400);

    let mut bad = display.clone();
    bad["baseline_manifest"] = json!("a baseline the scope does not name");
    assert_eq!(submit(&rig, id, scope.clone(), bad).await.http, 400);

    assert_eq!(status_of(&client, id).await.state, "working");

    let reply = submit(&rig, id, scope, display).await;
    assert_eq!(reply.http, 200, "{}", String::from_utf8_lossy(&reply.body));
    assert_eq!(status_of(&client, id).await.state, "waiting");

    let id = {
        approve_job(client.base(), id).await;
        let claim = rig
            .post("/api/runner/claim", json!({ "id": id }), Some(id))
            .await;
        assert_eq!(claim.http, 200);
        let finish = rig
            .post(
                "/api/runner/finish",
                json!({ "id": id, "result": "applied" }),
                Some(id),
            )
            .await;
        assert_eq!(finish.http, 200);
        file_trust(&client, "net", b"tar").await
    };
    rig.poll().await;
    let (mut scope, display) = trust_pair("net");
    scope["diff"] = json!(hex('9'));
    let reply = submit(&rig, id, scope.clone(), display.clone()).await;
    assert_eq!(
        (reply.http, reply.code().as_str()),
        (400, "inconsistent_scope")
    );

    let external = json!({ "external": true, "verify_command": "git diff a b | sha256sum" });
    let reply = submit(&rig, id, scope, external).await;
    assert_eq!(reply.http, 200, "{}", String::from_utf8_lossy(&reply.body));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_with_counts_not_matching_addresses_is_400() {
    let dir = scratch("jobs-counts");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);

    let id = file_apply(&client, "net").await;
    rig.poll().await;

    let lines = ["create a.b", "update c.d", "delete e.f"];
    let (scope, display) = apply_pair("net", &lines, [2, 0, 0, 1], false);
    let reply = submit(&rig, id, scope, display).await;
    assert_eq!(
        (reply.http, reply.code().as_str()),
        (400, "inconsistent_scope")
    );

    let (scope, display) = apply_pair("net", &["bogus a.b"], [1, 0, 0, 0], false);
    assert_eq!(submit(&rig, id, scope, display).await.http, 400);

    let (scope, display) = apply_pair("net", &lines, [1, 1, 0, 1], true);
    let reply = submit(&rig, id, scope, display).await;
    assert_eq!(reply.http, 200, "{}", String::from_utf8_lossy(&reply.body));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_with_destructive_flag_wrong_is_400() {
    let dir = scratch("jobs-destructive");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);

    let id = file_apply(&client, "net").await;
    rig.poll().await;

    let (scope, display) = apply_pair("net", &["delete a.b"], [0, 0, 0, 1], false);
    let reply = submit(&rig, id, scope, display).await;
    assert_eq!(
        (reply.http, reply.code().as_str()),
        (400, "inconsistent_scope")
    );

    let (scope, display) = apply_pair("net", &["create a.b"], [1, 0, 0, 0], true);
    assert_eq!(submit(&rig, id, scope, display).await.http, 400);

    let (scope, display) = apply_pair("net", &["replace a.b"], [0, 0, 1, 0], true);
    assert_eq!(submit(&rig, id, scope, display).await.http, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_is_single_use() {
    let dir = scratch("jobs-claim");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);

    let id = file_apply(&client, "net").await;
    rig.poll().await;
    let (scope, display) = apply_pair("net", &["create a.b"], [1, 0, 0, 0], false);
    assert_eq!(submit(&rig, id, scope.clone(), display).await.http, 200);

    let early = rig
        .post("/api/runner/claim", json!({ "id": id }), Some(id))
        .await;
    assert_eq!(early.http, 404);

    approve_job(client.base(), id).await;
    let approved = rig.poll().await;
    assert_eq!(
        (approved["id"].as_u64(), approved["state"].as_str()),
        (Some(id), Some("approved"))
    );

    let first = rig
        .post("/api/runner/claim", json!({ "id": id }), Some(id))
        .await;
    assert_eq!(first.http, 200, "{}", String::from_utf8_lossy(&first.body));
    assert_eq!(first.json(), scope);
    assert_eq!(status_of(&client, id).await.state, "claimed");

    let second = rig
        .post("/api/runner/claim", json!({ "id": id }), Some(id))
        .await;
    assert_eq!(
        (second.http, second.code().as_str()),
        (409, "already_claimed")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_job_result_is_ledgered_as_outcome_unknown() {
    let dir = scratch("jobs-unknown-result");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);

    let applied = rig
        .post(
            "/api/runner/finish",
            json!({ "id": 4242, "result": "applied", "project": "net" }),
            Some(4242),
        )
        .await;
    assert_eq!(applied.http, 404);

    let reply = rig
        .post(
            "/api/runner/finish",
            json!({ "id": 4242, "result": "outcome_unknown", "project": "net" }),
            Some(4242),
        )
        .await;
    assert_eq!(reply.http, 200, "{}", String::from_utf8_lossy(&reply.body));

    let nameless = rig
        .post(
            "/api/runner/finish",
            json!({ "id": 4243, "result": "outcome_unknown" }),
            Some(4243),
        )
        .await;
    assert_eq!(nameless.http, 400);

    let base = client.base().to_owned();
    let ledger = blocking(move || {
        ureq::get(format!("{base}/api/ledger"))
            .call()
            .unwrap()
            .into_body()
            .read_to_string()
            .unwrap()
    })
    .await;
    assert!(ledger.contains("outcome_unknown"), "{ledger}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_trusted_persists_trust_record() {
    let dir = scratch("jobs-trusted");
    let key = runner_key();
    let (client, d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);

    let id = file_trust(&client, "net", b"candidate tar").await;
    rig.poll().await;
    let (scope, display) = trust_pair("net");
    assert_eq!(submit(&rig, id, scope, display).await.http, 200);
    approve_job(client.base(), id).await;
    let claim = rig
        .post("/api/runner/claim", json!({ "id": id }), Some(id))
        .await;
    assert_eq!(claim.http, 200, "{}", String::from_utf8_lossy(&claim.body));
    assert_eq!(claim.json()["kind"], "trust");

    let finish = rig
        .post(
            "/api/runner/finish",
            json!({ "id": id, "result": "trusted" }),
            Some(id),
        )
        .await;
    assert_eq!(
        finish.http,
        200,
        "{}",
        String::from_utf8_lossy(&finish.body)
    );

    let records = Store::new(&dir).load_trusted().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].project, "net");
    assert_eq!(records[0].digest, hex('c'));
    assert_eq!(records[0].schema, hex('5'));
    assert_eq!(records[0].job, id);

    let status = status_of(&client, id).await;
    assert_eq!(status.result.as_deref(), Some("trusted"));
    drop(d);

    let ca_key = dir.join("user_ca");
    let (client2, _d2) =
        start_everything(&dir, &ca_key, None, &[("net", "r1")], &[("r1", &key)]).await;
    let rig2 = Rig::new(&client2, "r1", &key);
    let client2 = Arc::new(client2);
    let id2 = file_apply(&client2, "net").await;
    let job = rig2.poll().await;
    assert_eq!(job["id"], id2);
    assert_eq!(job["trusted"]["digest"], hex('c'));
    assert_eq!(job["trusted"]["job"], id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_unavailable_after_submit() {
    let dir = scratch("jobs-archive");
    let (k1, k2) = (runner_key(), runner_key());
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &k1), ("r2", &k2)]).await;
    let (r1, r2) = (Rig::new(&client, "r1", &k1), Rig::new(&client, "r2", &k2));
    let client = Arc::new(client);

    let id = file_trust(&client, "net", b"the archive bytes").await;
    let path = format!("/api/runner/archive/{id}");

    assert_eq!(r1.get(&path, Some(id)).await.http, 404, "still queued");
    r1.poll().await;
    assert_eq!(r2.get(&path, Some(id)).await.http, 404, "wrong runner");
    let got = r1.get(&path, Some(id)).await;
    assert_eq!(got.http, 200);
    assert_eq!(got.body, b"the archive bytes");

    let (scope, display) = trust_pair("net");
    assert_eq!(submit(&r1, id, scope, display).await.http, 200);
    assert_eq!(r1.get(&path, Some(id)).await.http, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuse_ends_a_working_job_with_the_runners_words() {
    let dir = scratch("jobs-refuse");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);

    let id = file_apply(&client, "net").await;
    rig.poll().await;
    let reply = rig
        .post(
            "/api/runner/refuse",
            json!({
                "id": id,
                "result": "refused",
                "failure": { "category": "policy", "addresses": ["a.b"], "detail": null },
            }),
            Some(id),
        )
        .await;
    assert_eq!(reply.http, 200, "{}", String::from_utf8_lossy(&reply.body));
    let status = status_of(&client, id).await;
    assert_eq!(status.result.as_deref(), Some("refused"));
    assert_eq!(status.failure.unwrap().category, "policy");
}

use std::os::unix::fs::PermissionsExt;

/// A trust job taken through submit, approval and claim.
async fn claimed_trust(rig: &Rig, client: &Arc<shoephone::client::Client>) -> u64 {
    let id = file_trust(client, "net", b"tar").await;
    rig.poll().await;
    let (scope, display) = trust_pair("net");
    assert_eq!(submit(rig, id, scope, display).await.http, 200);
    approve_job(client.base(), id).await;
    let claim = rig
        .post("/api/runner/claim", json!({ "id": id }), Some(id))
        .await;
    assert_eq!(claim.http, 200);
    id
}

async fn ledger_text(client: &Arc<shoephone::client::Client>) -> String {
    let base = client.base().to_owned();
    blocking(move || {
        ureq::get(format!("{base}/api/ledger"))
            .call()
            .unwrap()
            .into_body()
            .read_to_string()
            .unwrap()
    })
    .await
}

fn chmod(path: &std::path::Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_trusted_save_failure_leaves_job_claimed_and_retry_succeeds() {
    let dir = scratch("jobs-save-fail");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = claimed_trust(&rig, &client).await;

    chmod(&dir, 0o555);
    let finish = json!({ "id": id, "result": "trusted" });
    let failed = rig
        .post("/api/runner/finish", finish.clone(), Some(id))
        .await;
    chmod(&dir, 0o755);
    assert_eq!(
        (failed.http, failed.code().as_str()),
        (500, "trust_save_failed")
    );
    assert_eq!(status_of(&client, id).await.state, "claimed");
    assert!(Store::new(&dir).load_trusted().unwrap().is_empty());
    assert!(!ledger_text(&client).await.contains("\"trusted\""));

    let retry = rig.post("/api/runner/finish", finish, Some(id)).await;
    assert_eq!(retry.http, 200, "{}", String::from_utf8_lossy(&retry.body));
    assert_eq!(Store::new(&dir).load_trusted().unwrap().len(), 1);
    assert_eq!(
        status_of(&client, id).await.result.as_deref(),
        Some("trusted")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_trusted_with_broken_ledger_is_refused() {
    let dir = scratch("jobs-ledger-broken");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = claimed_trust(&rig, &client).await;

    chmod(&dir.join("ledger.jsonl"), 0o000);
    let unknown = rig
        .post(
            "/api/runner/finish",
            json!({ "id": 9001, "result": "outcome_unknown", "project": "net" }),
            Some(9001),
        )
        .await;
    assert_eq!(unknown.http, 200, "outcome reports still go through");

    let finish = rig
        .post(
            "/api/runner/finish",
            json!({ "id": id, "result": "trusted" }),
            Some(id),
        )
        .await;
    chmod(&dir.join("ledger.jsonl"), 0o600);
    assert_eq!(
        (finish.http, finish.code().as_str()),
        (503, "ledger_unavailable")
    );
    assert!(Store::new(&dir).load_trusted().unwrap().is_empty());
    assert_eq!(status_of(&client, id).await.state, "claimed");

    let applied = rig
        .post(
            "/api/runner/finish",
            json!({ "id": id, "result": "applied" }),
            Some(id),
        )
        .await;
    assert_eq!(applied.http, 400, "a result that does not fit the job kind");
    assert_eq!(applied.code(), "scope_mismatch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_with_unchecked_display_fields_is_400() {
    let dir = scratch("jobs-display-fields");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);

    let id = file_trust(&client, "net", b"tar").await;
    rig.poll().await;
    let (scope, good) = trust_pair("net");
    let cases = [
        json!({ "external": true, "diff": "x", "verify_command": "v" }),
        json!({ "external": true }),
        json!({ "external": true, "verify_command": "" }),
        json!({ "diff": good["diff"], "manifest": "m" }),
        json!({ "diff": good["diff"], "baseline_manifest": "m" }),
        json!({ "diff": good["diff"], "address_text": "" }),
        json!({ "diff": good["diff"], "verify_command": "v" }),
    ];
    for display in cases {
        let reply = submit(&rig, id, scope.clone(), display.clone()).await;
        assert_eq!(
            (reply.http, reply.code().as_str()),
            (400, "inconsistent_scope"),
            "{display}"
        );
    }
    assert_eq!(status_of(&client, id).await.state, "working");
    assert_eq!(submit(&rig, id, scope, good).await.http, 200);
    approve_job(client.base(), id).await;
    rig.post("/api/runner/claim", json!({ "id": id }), Some(id))
        .await;
    rig.post(
        "/api/runner/finish",
        json!({ "id": id, "result": "trusted" }),
        Some(id),
    )
    .await;

    let id = file_apply(&client, "net").await;
    rig.poll().await;
    let (scope, good) = apply_pair("net", &["create a.b"], [1, 0, 0, 0], false);
    for (field, value) in [
        ("diff", json!("x")),
        ("external", json!(true)),
        ("verify_command", json!("v")),
    ] {
        let mut display = good.clone();
        display[field] = value;
        let reply = submit(&rig, id, scope.clone(), display).await;
        assert_eq!(
            (reply.http, reply.code().as_str()),
            (400, "inconsistent_scope"),
            "{field}"
        );
    }
    assert_eq!(submit(&rig, id, scope, good).await.http, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_warnings_are_checked_field_by_field() {
    let dir = scratch("jobs-warnings");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = file_trust(&client, "net", b"tar").await;
    rig.poll().await;
    let (scope, good) = trust_pair("net");

    let ok = |extra: serde_json::Value| {
        let mut w = json!({"kind": "provisioner", "file": "infra/main.tf", "line": 3});
        for (k, v) in extra.as_object().unwrap() {
            w[k] = v.clone();
        }
        w
    };
    let many: Vec<_> = (0..201).map(|_| ok(json!({}))).collect();
    let bad = [
        ok(json!({"kind": "shell"})),
        ok(json!({"kind": ""})),
        ok(json!({"file": ""})),
        ok(json!({"file": "a".repeat(256)})),
        ok(json!({"file": "a\u{202e}b.tf"})),
        ok(json!({"file": "a\nb.tf"})),
        ok(json!({"file": "a\u{200b}b.tf"})),
        ok(json!({"kind": "schema_variable_steers", "variable": "Region", "into": "count"})),
        ok(json!({"kind": "schema_variable_steers", "variable": "1x", "into": "count"})),
        ok(json!({"kind": "schema_variable_steers", "variable": "a".repeat(65), "into": "count"})),
        ok(json!({"kind": "schema_variable_steers", "variable": "r\u{202e}", "into": "count"})),
        ok(json!({"kind": "schema_variable_steers", "variable": "region", "into": "network"})),
    ];
    for w in bad {
        let mut display = good.clone();
        display["warnings"] = json!([w]);
        let reply = submit(&rig, id, scope.clone(), display).await;
        assert_eq!(
            (reply.http, reply.code().as_str()),
            (400, "inconsistent_scope"),
            "{w}"
        );
    }
    let steer = |variable: serde_json::Value, into: serde_json::Value, kind: &str| {
        ok(json!({"kind": kind, "variable": variable, "into": into}))
    };
    for w in [
        steer(json!("v"), json!(null), "schema_variable_steers"),
        steer(json!(null), json!("count"), "schema_variable_steers"),
        steer(json!(null), json!(null), "schema_variable_steers"),
        steer(json!("v"), json!("count"), "provisioner"),
        steer(json!("v"), json!(null), "import"),
        steer(json!(null), json!("count"), "import"),
    ] {
        let mut display = good.clone();
        display["warnings"] = json!([w]);
        let reply = submit(&rig, id, scope.clone(), display).await;
        assert_eq!(
            (reply.http, reply.code().as_str()),
            (400, "inconsistent_scope"),
            "{w}"
        );
    }
    let mut display = good.clone();
    display["warnings"] = json!([ok(json!({})), ok(json!({}))]);
    display["warnings_omitted"] = json!(3);
    assert_eq!(submit(&rig, id, scope.clone(), display).await.http, 400);
    let mut display = good.clone();
    display["warnings"] = json!(many);
    let reply = submit(&rig, id, scope.clone(), display).await;
    assert_eq!(
        (reply.http, reply.code().as_str()),
        (400, "inconsistent_scope"),
        "201 warnings"
    );
    assert_eq!(status_of(&client, id).await.state, "working");

    let mut display = good;
    let mut all: Vec<_> = (0..200).map(|_| ok(json!({}))).collect();
    all[0] = ok(json!({
        "kind": "schema_variable_steers", "variable": "_r1", "into": "for_each", "file": "a".repeat(255)
    }));
    display["warnings"] = json!(all);
    display["warnings_omitted"] = json!(50);
    assert_eq!(submit(&rig, id, scope, display).await.http, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_display_with_warnings_is_refused() {
    let dir = scratch("jobs-apply-warnings");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = file_apply(&client, "net").await;
    rig.poll().await;
    let (scope, mut display) = apply_pair("net", &["create a.b"], [1, 0, 0, 0], false);
    let mut omitted = display.clone();
    omitted["warnings_omitted"] = json!(1);
    display["warnings"] = json!([{"kind": "provisioner", "file": "a.tf", "line": 1}]);
    for d in [display, omitted] {
        let reply = submit(&rig, id, scope.clone(), d).await;
        assert_eq!(
            (reply.http, reply.code().as_str()),
            (400, "inconsistent_scope")
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn baseline_status_must_match_baseline_manifest() {
    let dir = scratch("jobs-baseline");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = file_apply(&client, "net").await;
    rig.poll().await;

    let (mut scope, mut display) = apply_pair("net", &["create a.b"], [1, 0, 0, 0], false);
    scope["baseline_status"] = json!("applied");
    let reply = submit(&rig, id, scope.clone(), display.clone()).await;
    assert_eq!(
        (reply.http, reply.code().as_str()),
        (400, "inconsistent_scope")
    );

    scope["baseline_status"] = json!("none");
    scope["baseline_manifest"] = json!(sha256_hex(r#"{"old":1}"#));
    display["baseline_manifest"] = json!(r#"{"old":1}"#);
    assert_eq!(
        submit(&rig, id, scope.clone(), display.clone()).await.http,
        400
    );

    scope["baseline_status"] = json!("uncertain");
    assert_eq!(submit(&rig, id, scope, display).await.http, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_manifests_must_be_json_objects() {
    let dir = scratch("jobs-json");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = file_apply(&client, "net").await;
    rig.poll().await;

    let (mut scope, mut display) = apply_pair("net", &["create a.b"], [1, 0, 0, 0], false);
    for text in [
        "plain text",
        "[1]",
        "null",
        r#"{"a":1,"a":2}"#,
        r#"{"a":{"b":1,"b":2}}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"\u0061":1,"a":2}"#,
        r#"{"x":{"b\u00e9":1,"b\u00E9":2}}"#,
    ] {
        scope["manifest"] = json!(sha256_hex(text));
        display["manifest"] = json!(text);
        let reply = submit(&rig, id, scope.clone(), display.clone()).await;
        assert_eq!(
            (reply.http, reply.code().as_str()),
            (400, "inconsistent_scope"),
            "{text}"
        );
    }
    let (mut scope, mut display) = apply_pair("net", &["create a.b"], [1, 0, 0, 0], false);
    scope["baseline_status"] = json!("applied");
    scope["baseline_manifest"] = json!(sha256_hex("not json"));
    display["baseline_manifest"] = json!("not json");
    let reply = submit(&rig, id, scope, display).await;
    assert_eq!(
        (reply.http, reply.code().as_str()),
        (400, "inconsistent_scope")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_category_is_restricted() {
    let dir = scratch("jobs-category");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = file_apply(&client, "net").await;
    rig.poll().await;

    for bad in ["", "Policy", "has space", "a.b", "x\ny", &"a".repeat(65)] {
        let reply = rig
            .post(
                "/api/runner/refuse",
                json!({ "id": id, "result": "refused",
                        "failure": { "category": bad, "addresses": [] } }),
                Some(id),
            )
            .await;
        assert_eq!(reply.http, 400, "{bad:?}");
    }
    assert_eq!(status_of(&client, id).await.state, "working");
}

async fn finish_trusted(rig: &Rig, id: u64) -> RunnerReply {
    rig.post(
        "/api/runner/finish",
        json!({ "id": id, "result": "trusted" }),
        Some(id),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrust_takes_effect_without_restart() {
    let dir = scratch("jobs-untrust-live");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = claimed_trust(&rig, &client).await;
    assert_eq!(finish_trusted(&rig, id).await.http, 200);

    let removed = Store::new(&dir).untrust("net").unwrap();
    assert_eq!(removed.map(|r| r.digest), Some(hex('c')));

    let second = file_trust(&client, "net", b"tar again").await;
    let polled = rig.poll().await;
    assert_eq!(polled["id"], second);
    assert!(polled["trusted"].is_null(), "{polled}");
    let (scope, display) = trust_pair("net");
    assert_eq!(scope["baseline"], Value::Null);
    assert_eq!(submit(&rig, second, scope, display).await.http, 200);
    approve_job(client.base(), second).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_untrust_and_trust_finish_do_not_lose_either() {
    let dir = scratch("jobs-untrust-race");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1"), ("db", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let seeded = shoephone::store::TrustRecord {
        project: "db".into(),
        digest: hex('9'),
        schema: hex('8'),
        job: 1,
        at: 1,
    };
    Store::new(&dir).save_trusted(&[seeded]).unwrap();
    let id = claimed_trust(&rig, &client).await;

    let store_dir = dir.clone();
    let untrust = blocking(move || {
        let store = Store::new(&store_dir);
        std::thread::spawn(move || store.untrust("db").unwrap())
    });
    let (finish, untrust) = tokio::join!(finish_trusted(&rig, id), untrust);
    assert_eq!(
        finish.http,
        200,
        "{}",
        String::from_utf8_lossy(&finish.body)
    );
    let removed = blocking(move || untrust.join().unwrap()).await;
    assert!(removed.is_some());

    let records = Store::new(&dir).load_trusted().unwrap();
    let names: Vec<&str> = records.iter().map(|r| r.project.as_str()).collect();
    assert_eq!(names, vec!["net"], "{records:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_and_apply_refusals_come_before_the_payload_is_read() {
    let dir = scratch("jobs-cheap");
    let (client, _d) = start_projects(&dir, &[("net", "r1")]).await;
    let client = Arc::new(client);

    let c = client.clone();
    let mut body = trust_body("nope", b"x");
    body.archive = "!!not base64!!".into();
    let err = blocking(move || c.trust(&body)).await.unwrap_err();
    assert_eq!(code(&err), (400, "unknown_project".to_owned()));

    let c = client.clone();
    let body = apply_body("nope", &"x".repeat(64 * 1024 + 1));
    let err = blocking(move || c.apply(&body)).await.unwrap_err();
    assert_eq!(code(&err), (400, "unknown_project".to_owned()));

    file_trust(&client, "net", b"one").await;
    let c = client.clone();
    let mut body = trust_body("net", b"x");
    body.archive = "!!not base64!!".into();
    let err = blocking(move || c.trust(&body)).await.unwrap_err();
    assert_eq!(code(&err), (409, "busy".to_owned()));

    let c = client.clone();
    let body = apply_body("net", &"x".repeat(64 * 1024 + 1));
    let err = blocking(move || c.apply(&body)).await.unwrap_err();
    assert_eq!(code(&err), (409, "busy".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_trusted_with_failing_ledger_rolls_the_trust_back() {
    let dir = scratch("jobs-rollback");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let first = claimed_trust(&rig, &client).await;
    assert_eq!(finish_trusted(&rig, first).await.http, 200);
    let before = std::fs::read(dir.join("trusted.json")).unwrap();

    let second = file_trust(&client, "net", b"tar two").await;
    rig.poll().await;
    let (mut scope, display) = trust_pair("net");
    scope["baseline"] = json!(hex('c'));
    scope["candidate"] = json!(hex('d'));
    assert_eq!(submit(&rig, second, scope, display).await.http, 200);
    approve_job(client.base(), second).await;
    let claim = rig
        .post("/api/runner/claim", json!({ "id": second }), Some(second))
        .await;
    assert_eq!(claim.http, 200);

    chmod(&dir.join("ledger.jsonl"), 0o000);
    let failed = finish_trusted(&rig, second).await;
    chmod(&dir.join("ledger.jsonl"), 0o600);
    assert_eq!(
        (failed.http, failed.code().as_str()),
        (503, "ledger_unavailable")
    );
    assert_eq!(std::fs::read(dir.join("trusted.json")).unwrap(), before);
    assert_eq!(status_of(&client, second).await.state, "claimed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_without_a_previous_record_removes_the_file_entry() {
    let dir = scratch("jobs-rollback-none");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = claimed_trust(&rig, &client).await;

    chmod(&dir.join("ledger.jsonl"), 0o000);
    let failed = finish_trusted(&rig, id).await;
    chmod(&dir.join("ledger.jsonl"), 0o600);
    assert_eq!(
        (failed.http, failed.code().as_str()),
        (503, "ledger_unavailable")
    );
    assert!(Store::new(&dir).load_trusted().unwrap().is_empty());
    assert_eq!(status_of(&client, id).await.state, "claimed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrust_between_claim_and_finish_refuses_the_trust() {
    let dir = scratch("jobs-untrust-mid");
    let key = runner_key();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let first = claimed_trust(&rig, &client).await;
    assert_eq!(finish_trusted(&rig, first).await.http, 200);

    let second = file_trust(&client, "net", b"tar two").await;
    rig.poll().await;
    let (mut scope, display) = trust_pair("net");
    scope["baseline"] = json!(hex('c'));
    scope["candidate"] = json!(hex('d'));
    assert_eq!(submit(&rig, second, scope, display).await.http, 200);
    approve_job(client.base(), second).await;
    let claim = rig
        .post("/api/runner/claim", json!({ "id": second }), Some(second))
        .await;
    assert_eq!(claim.http, 200);

    assert!(Store::new(&dir).untrust("net").unwrap().is_some());
    let finish = finish_trusted(&rig, second).await;
    assert_eq!(
        (finish.http, finish.code().as_str()),
        (409, "stale_baseline")
    );
    assert!(Store::new(&dir).load_trusted().unwrap().is_empty());
    let status = status_of(&client, second).await;
    assert_eq!(status.result.as_deref(), Some("refused"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_drops_trust_without_a_ledger_entry() {
    let dir = scratch("jobs-reconcile");
    let key = runner_key();
    let seeded = shoephone::store::TrustRecord {
        project: "net".into(),
        digest: hex('9'),
        schema: hex('8'),
        job: 41,
        at: 1,
    };
    Store::new(&dir).save_trusted(&[seeded]).unwrap();
    let (client, _d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);

    assert!(Store::new(&dir).load_trusted().unwrap().is_empty());
    file_trust(&client, "net", b"tar").await;
    let polled = rig.poll().await;
    assert!(polled["trusted"].is_null(), "{polled}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_keeps_an_audited_trust() {
    let dir = scratch("jobs-reconcile-keep");
    let key = runner_key();
    let (client, d) = start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = claimed_trust(&rig, &client).await;
    assert_eq!(finish_trusted(&rig, id).await.http, 200);
    drop(d);

    let ca_key = dir.join("user_ca");
    let (client2, _d2) =
        start_everything(&dir, &ca_key, None, &[("net", "r1")], &[("r1", &key)]).await;
    let rig2 = Rig::new(&client2, "r1", &key);
    let client2 = Arc::new(client2);
    let records = Store::new(&dir).load_trusted().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].job, id);
    file_trust(&client2, "net", b"tar again").await;
    let polled = rig2.poll().await;
    assert_eq!(polled["trusted"]["digest"], hex('c'));
}

fn push_bodies(rx: &std::sync::mpsc::Receiver<String>, want: usize) -> Vec<String> {
    (0..want)
        .map(|_| {
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .expect("a push was expected")
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trust_job_pushes_one_per_event_and_only_the_waiting_one_asks() {
    let dir = scratch("jobs-push");
    let ca_key = dir.join("user_ca");
    shoephone::ca::UserCa::generate("test CA")
        .unwrap()
        .write_openssh_file(&ca_key)
        .unwrap();
    let (url, pushes) = fake_topic();
    let notify = shoephone::notify::NotifyConfig {
        url,
        token: None,
        click: None,
    };
    let key = runner_key();
    let (client, _d) = start_everything(
        &dir,
        &ca_key,
        Some(notify),
        &[("net", "r1")],
        &[("r1", &key)],
    )
    .await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    claimed_trust(&rig, &client).await;
    assert_eq!(
        push_bodies(&pushes, 4),
        [
            "A deploy request was filed.",
            "A deploy plan was started.",
            "A code change is waiting for your approval.",
            "A deploy was approved.",
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undone_trust_sends_no_push() {
    let dir = scratch("jobs-push-undo");
    let ca_key = dir.join("user_ca");
    shoephone::ca::UserCa::generate("test CA")
        .unwrap()
        .write_openssh_file(&ca_key)
        .unwrap();
    let (url, pushes) = fake_topic();
    let notify = shoephone::notify::NotifyConfig {
        url,
        token: None,
        click: None,
    };
    let key = runner_key();
    let (client, _d) = start_everything(
        &dir,
        &ca_key,
        Some(notify),
        &[("net", "r1")],
        &[("r1", &key)],
    )
    .await;
    let rig = Rig::new(&client, "r1", &key);
    let client = Arc::new(client);
    let id = claimed_trust(&rig, &client).await;
    push_bodies(&pushes, 4);

    chmod(&dir.join("ledger.jsonl"), 0o000);
    let failed = finish_trusted(&rig, id).await;
    chmod(&dir.join("ledger.jsonl"), 0o600);
    assert_eq!(
        (failed.http, failed.code().as_str()),
        (503, "ledger_unavailable")
    );
    assert_eq!(status_of(&client, id).await.state, "claimed");
    let late = pushes.recv_timeout(std::time::Duration::from_millis(700));
    assert!(late.is_err(), "the undone trust was pushed: {late:?}");
    assert!(!ledger_text(&client).await.contains("\"trusted\""));
}
