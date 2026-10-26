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
