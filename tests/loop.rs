// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The daemon in-process, driven by the real client over real HTTP.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use shoephone::api::{ErrorReply, RequestBody, RequestState};
use shoephone::ca::UserCa;
use shoephone::client::{Client, Error};
use shoephone::config::{Config, PolicyConfig};
use shoephone::exit::Status;
use shoephone::notify::NotifyConfig;
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
    start_at(dir, &ca_key).await
}

/// Start a daemon against a state directory (and CA) an earlier daemon in
/// this test already used, the way a restart does: neither is regenerated.
/// Used to check that ids and serials survive a restart.
async fn start_reusing(dir: &Path) -> (Client, Arc<Daemon>) {
    start_at(dir, &dir.join("user_ca")).await
}

async fn start_at(dir: &Path, ca_key: &Path) -> (Client, Arc<Daemon>) {
    start_with(dir, ca_key, None).await
}

async fn start_with(
    dir: &Path,
    ca_key: &Path,
    notify: Option<NotifyConfig>,
) -> (Client, Arc<Daemon>) {
    let mut principals = BTreeMap::new();
    principals.insert("web01".to_owned(), "agent-admin:web01".to_owned());
    let config = Config {
        listen: "127.0.0.1:0".into(),
        state_dir: dir.to_path_buf(),
        ca_key: ca_key.to_path_buf(),
        rp_id: "localhost".into(),
        rp_origin: "http://localhost".into(),
        rp_name: "test".into(),
        principals,
        policy: PolicyConfig::default(),
        notify,
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
    // An immediate renewal falls well inside half the certificate's TTL,
    // so `Grants::issue` says to reuse rather than mint: the daemon hands
    // back the identical certificate it already issued and signed, instead
    // of minting (and logging) a new one for a session that never used the
    // old one.
    assert_eq!(
        renewed.serial, issued.serial,
        "an immediate renewal reuses the certificate"
    );
    assert_eq!(
        renewed.certificate, issued.certificate,
        "and gets back the identical signed certificate"
    );

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

/// A stand-in ntfy topic: answers every POST with 200 and a closed
/// connection, and sends each body down the channel.
fn fake_topic() -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/shoephone", listener.local_addr().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let mut sock = sock.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            let body = loop {
                let n = sock.read(&mut buf).unwrap();
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw);
                let Some(head_end) = text.find("\r\n\r\n") else {
                    continue;
                };
                let len = text[..head_end]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if raw.len() >= head_end + 4 + len {
                    break text[head_end + 4..].to_string();
                }
            };
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            if tx.send(body).is_err() {
                return;
            }
        }
    });
    (url, rx)
}

/// DESIGN.md: every issuance, renewal, decline and kill is reported to the
/// approver's device, because the daemon's own ledger is worthless once the
/// daemon is compromised. So every line the ledger gains must have gone out
/// as a push too -- one for one, not just the events that need a tap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_ledger_event_is_pushed_to_the_device() {
    let dir = scratch("audit-push");
    let ca_key = dir.join("user_ca");
    UserCa::generate("test CA")
        .unwrap()
        .write_openssh_file(&ca_key)
        .unwrap();
    let (url, pushes) = fake_topic();
    let notify = NotifyConfig {
        url,
        token: None,
        click: None,
    };
    let (client, _daemon) = start_with(&dir, &ca_key, Some(notify)).await;
    let client = Arc::new(client);
    let key = Session::new(dir.join("session")).public_key().unwrap();
    let body = RequestBody {
        host: "web01".into(),
        public_key: key.clone(),
        requester: "test".into(),
        reason: "loop test: every event is pushed".into(),
        context: None,
        window_minutes: None,
    };

    // requested, approved, issued, killed
    let c = client.clone();
    let b = body.clone();
    let reply = blocking(move || c.request(&b)).await.unwrap();
    let http = ureq::post(format!("{}/api/test/approve", client.base()))
        .send_json(serde_json::json!({ "id": reply.id }))
        .unwrap();
    assert_eq!(http.status(), 200);
    let c = client.clone();
    let k = key.clone();
    blocking(move || c.issue("web01", &k)).await.unwrap();
    let c = client.clone();
    blocking(move || c.kill("web01")).await.unwrap();

    // requested, declined
    let c = client.clone();
    let b = body.clone();
    let reply = blocking(move || c.request(&b)).await.unwrap();
    let http = ureq::post(format!("{}/api/decline", client.base()))
        .send_json(serde_json::json!({ "id": reply.id }))
        .unwrap();
    assert_eq!(http.status(), 200);

    let ledger = std::fs::read_to_string(dir.join("ledger.jsonl")).unwrap();
    let mut expected: Vec<&str> = ledger
        .lines()
        .map(|line| {
            let kind = serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned();
            match kind.as_str() {
                "requested" => "A request is waiting for your approval.",
                "approved" => "An authorization is now active.",
                "issued" => "A certificate was issued.",
                "killed" => "An authorization was terminated.",
                "declined" => "A request was declined.",
                "timed_out" => "A request expired without an answer.",
                other => panic!("ledger kind {other} has no push"),
            }
        })
        .collect();
    assert_eq!(expected.len(), 6, "{ledger}");

    // Each call's pushes go out on their own blocking task, so arrival
    // order across calls is not guaranteed; compare as multisets.
    let mut got: Vec<String> = (0..expected.len())
        .map(|_| pushes.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect();
    assert!(
        pushes.recv_timeout(Duration::from_millis(200)).is_err(),
        "more pushes than ledger lines"
    );
    expected.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, expected);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_register_refuses_an_unknown_credential() {
    let dir = scratch("push-unknown");
    let (client, _daemon) = start(&dir).await;

    let err = ureq::post(format!("{}/api/push/register", client.base()))
        .send_json(serde_json::json!({
            "credential_id": "AAAA",
            "token": "00",
            "secret": "irrelevant",
        }))
        .unwrap_err();
    match err {
        ureq::Error::StatusCode(403) => {}
        other => panic!("expected 403 for an unknown credential id, got {other}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A ledger that cannot be written must refuse everything that would grant
/// a certificate or open a window, but must not stop the kill switch: kill
/// and decline stay effective under `with`, which appends best-effort and
/// returns its own result either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_broken_ledger_refuses_audited_calls_but_kill_still_works() {
    let dir = scratch("ledger-fail");
    let (client, _daemon) = start(&dir).await;
    let client = Arc::new(client);
    let session = Session::new(dir.join("session"));
    let key = session.public_key().unwrap();

    let c = client.clone();
    let k = key.clone();
    let reply = blocking(move || {
        c.request(&RequestBody {
            host: "web01".into(),
            public_key: k,
            requester: "test".into(),
            reason: "loop test: ledger failure".into(),
            context: None,
            window_minutes: None,
        })
    })
    .await
    .unwrap();

    let ledger_path = dir.join("ledger.jsonl");
    assert!(
        ledger_path.exists(),
        "the request itself should have written a ledger line"
    );
    std::fs::remove_file(&ledger_path).unwrap();
    std::fs::create_dir(&ledger_path).unwrap();

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = agent
        .post(format!("{}/api/test/approve", client.base()))
        .send_json(serde_json::json!({ "id": reply.id }))
        .unwrap();
    assert_eq!(resp.status(), 503, "approve must be refused closed");
    let body: ErrorReply = resp.body_mut().read_json().unwrap();
    assert_eq!(body.code, "ledger_unavailable");

    let c = client.clone();
    let k = key.clone();
    let err = blocking(move || c.issue("web01", &k)).await.unwrap_err();
    match err {
        Error::Daemon { http, reply } => {
            assert_eq!(http, 503);
            assert_eq!(reply.code, "ledger_unavailable");
        }
        other => panic!("issue should also fail closed: {other}"),
    }

    let c = client.clone();
    let killed = blocking(move || c.kill("web01")).await;
    assert!(
        killed.is_ok(),
        "kill must stay effective when the ledger cannot be written: {killed:?}"
    );

    // Cleans up the directory planted at ledger.jsonl along with everything
    // else in the scratch dir.
    let _ = std::fs::remove_dir_all(&dir);
}

/// Ids and serials come from a counter the daemon persists to disk (see
/// `Store::load_next_id`/`save_next_id`), precisely so a restart does not
/// hand out an id or serial that is already in the ledger. This starts a
/// daemon, files a request, then starts a second daemon against the same
/// state directory and CA the way a restart does, and checks the second
/// request gets a higher id than the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_ids_survive_a_restart() {
    let dir = scratch("restart-ids");
    let (client, daemon) = start(&dir).await;
    let client = Arc::new(client);
    let session = Session::new(dir.join("session"));
    let key = session.public_key().unwrap();

    let c = client.clone();
    let k = key.clone();
    let first = blocking(move || {
        c.request(&RequestBody {
            host: "web01".into(),
            public_key: k,
            requester: "test".into(),
            reason: "loop test: id survives a restart, first daemon".into(),
            context: None,
            window_minutes: None,
        })
    })
    .await
    .unwrap();

    drop(client);
    drop(daemon);

    let (client2, _daemon2) = start_reusing(&dir).await;
    let client2 = Arc::new(client2);
    let c = client2.clone();
    let second = blocking(move || {
        c.request(&RequestBody {
            host: "web01".into(),
            public_key: key,
            requester: "test".into(),
            reason: "loop test: id survives a restart, second daemon".into(),
            context: None,
            window_minutes: None,
        })
    })
    .await
    .unwrap();

    assert!(
        second.id > first.id,
        "a restart must not reuse an id: first {}, second {}",
        first.id,
        second.id
    );
    let _ = std::fs::remove_dir_all(&dir);
}
