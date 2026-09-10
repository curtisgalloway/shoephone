// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The daemon in-process, driven by the real client over real HTTP.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use shoephone::api::{RequestBody, RequestState};
use shoephone::ca::UserCa;
use shoephone::client::{Client, Error};
use shoephone::config::{Config, PolicyConfig};
use shoephone::exit::Status;
use shoephone::server::Daemon;
use shoephone::session::Session;
use ssh_key::{Certificate, HashAlg};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shoephone-loop-{}-{name}", std::process::id()));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_decline_cooldown_and_gone() {
    let dir = scratch("decline");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let session = Session::new(dir.join("session"));
    let key = session.public_key().unwrap();

    let c = client.clone();
    let status = blocking(move || c.status()).await.unwrap();
    assert_eq!(status.hosts, ["web01"]);
    assert!(status.devices.is_empty());

    let body = RequestBody {
        host: "web01".into(),
        public_key: key.clone(),
        requester: "test".into(),
        reason: "loop test: decline path".into(),
        context: Some("https://claude.ai/code/session_test".into()),
        window_minutes: Some(30),
    };
    let c = client.clone();
    let b = body.clone();
    let reply = blocking(move || c.request(&b)).await.unwrap();
    assert_eq!(reply.principal, "agent-admin:web01");
    assert_eq!(reply.match_code.len(), 9);

    let c = client.clone();
    let id = reply.id;
    assert_eq!(
        blocking(move || c.poll(id)).await.unwrap(),
        RequestState::Pending
    );

    let c = client.clone();
    let b = body.clone();
    let err = blocking(move || c.request(&b)).await.unwrap_err();
    assert_eq!(err.status(), Status::RetryClean, "busy: {err}");

    let c = client.clone();
    let k = key.clone();
    let err = blocking(move || c.issue("web01", &k)).await.unwrap_err();
    assert_eq!(err.status(), Status::AuthNeedsHuman, "no window yet: {err}");

    let http = ureq::post(format!("{}/api/decline", client.base()))
        .send_json(serde_json::json!({ "id": id }))
        .unwrap();
    assert_eq!(http.status(), 200);

    let c = client.clone();
    assert_eq!(
        blocking(move || c.poll(id)).await.unwrap(),
        RequestState::Gone
    );

    let c = client.clone();
    let b = body.clone();
    let err = blocking(move || c.request(&b)).await.unwrap_err();
    assert_eq!(err.status(), Status::RetryLater, "cooldown: {err}");
    match err {
        Error::Daemon { reply, .. } => assert!(reply.until.is_some()),
        other => panic!("{other}"),
    }

    let c = client.clone();
    let err = blocking(move || c.kill("web01")).await.unwrap_err();
    assert_eq!(err.status(), Status::AuthNeedsHuman);

    let ledger = std::fs::read_to_string(dir.join("ledger.jsonl")).unwrap();
    assert_eq!(ledger.lines().count(), 2, "{ledger}");
    assert!(ledger.contains("\"declined\""));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approved_window_issues_certificates_bound_to_the_key() {
    let dir = scratch("approve");
    let (client, daemon) = start(&dir).await;
    let client = Arc::new(client);
    let session = Session::new(dir.join("session"));
    let key = session.public_key().unwrap();
    let other = Session::new(dir.join("other")).public_key().unwrap();

    let c = client.clone();
    let k = key.clone();
    let reply = blocking(move || {
        c.request(&RequestBody {
            host: "web01".into(),
            public_key: k,
            requester: "test".into(),
            reason: "loop test: approve path".into(),
            context: None,
            window_minutes: None,
        })
    })
    .await
    .unwrap();

    let http = ureq::post(format!("{}/api/test/approve", client.base()))
        .send_json(serde_json::json!({ "id": reply.id }))
        .unwrap();
    assert_eq!(http.status(), 200);

    let c = client.clone();
    let id = reply.id;
    match blocking(move || c.poll(id)).await.unwrap() {
        RequestState::Approved { ends_at } => assert_eq!(ends_at, reply.ends_at),
        other => panic!("{other:?}"),
    }

    let c = client.clone();
    let o = other.clone();
    let err = blocking(move || c.issue("web01", &o)).await.unwrap_err();
    assert_eq!(err.status(), Status::AuthDenied, "other key: {err}");

    let c = client.clone();
    let k = key.clone();
    let issued = blocking(move || c.issue("web01", &k)).await.unwrap();
    assert_eq!(issued.ends_at, reply.ends_at);
    assert!(issued.valid_before <= issued.ends_at);
    let cert = Certificate::from_openssh(&issued.certificate).unwrap();
    assert_eq!(cert.valid_principals(), ["agent-admin:web01"]);
    assert_eq!(cert.serial(), issued.serial);
    let ca_fp = UserCa::from_openssh_file(&daemon.config().ca_key)
        .unwrap()
        .fingerprint();
    cert.validate_at(issued.valid_before - 1, [&ca_fp]).unwrap();
    let subject = ssh_key::PublicKey::from_openssh(&key).unwrap();
    assert_eq!(
        cert.public_key().fingerprint(HashAlg::Sha256),
        subject.fingerprint(HashAlg::Sha256)
    );

    let c = client.clone();
    let k = key.clone();
    let renewed = blocking(move || c.issue("web01", &k)).await.unwrap();
    assert!(renewed.serial > issued.serial, "renewal is a new serial");

    let c = client.clone();
    blocking(move || c.kill("web01")).await.unwrap();
    let c = client.clone();
    let k = key.clone();
    let err = blocking(move || c.issue("web01", &k)).await.unwrap_err();
    assert_eq!(err.status(), Status::AuthNeedsHuman, "after kill: {err}");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let ledger = std::fs::read_to_string(dir.join("ledger.jsonl")).unwrap();
    for kind in ["requested", "approved", "issued", "killed"] {
        assert!(
            ledger.contains(&format!("\"{kind}\"")),
            "{kind} missing:\n{ledger}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
