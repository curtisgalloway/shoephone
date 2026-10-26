// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The in-process daemon harness shared by the integration tests. Each test
//! crate uses a different subset, hence the `dead_code` allowance.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use shoephone::ca::UserCa;
use shoephone::client::Client;
use shoephone::config::{Config, PolicyConfig, ProjectConfig, RunnerConfig};
use shoephone::notify::NotifyConfig;
use shoephone::runner_auth;
use shoephone::server::Daemon;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};

pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shoephone-loop-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub async fn start(dir: &Path) -> (Client, Arc<Daemon>) {
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
pub async fn start_reusing(dir: &Path) -> (Client, Arc<Daemon>) {
    start_at(dir, &dir.join("user_ca")).await
}

pub async fn start_at(dir: &Path, ca_key: &Path) -> (Client, Arc<Daemon>) {
    start_with(dir, ca_key, None).await
}

pub async fn start_with(
    dir: &Path,
    ca_key: &Path,
    notify: Option<NotifyConfig>,
) -> (Client, Arc<Daemon>) {
    start_full(dir, ca_key, notify, &[]).await
}

/// Like [`start`], with Terraform projects configured as `(project, runner)`.
pub async fn start_projects(dir: &Path, projects: &[(&str, &str)]) -> (Client, Arc<Daemon>) {
    let ca_key = dir.join("user_ca");
    UserCa::generate("test CA")
        .unwrap()
        .write_openssh_file(&ca_key)
        .unwrap();
    start_full(dir, &ca_key, None, projects).await
}

pub async fn start_full(
    dir: &Path,
    ca_key: &Path,
    notify: Option<NotifyConfig>,
    projects: &[(&str, &str)],
) -> (Client, Arc<Daemon>) {
    start_everything(dir, ca_key, notify, projects, &[]).await
}

/// A fresh runner signing key. Generated per test run, never committed.
pub fn runner_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}

/// Like [`start_projects`], with the named runners' public keys configured.
pub async fn start_runners(
    dir: &Path,
    projects: &[(&str, &str)],
    runners: &[(&str, &PrivateKey)],
) -> (Client, Arc<Daemon>) {
    let ca_key = dir.join("user_ca");
    UserCa::generate("test CA")
        .unwrap()
        .write_openssh_file(&ca_key)
        .unwrap();
    start_everything(dir, &ca_key, None, projects, runners).await
}

/// What a runner request came back with.
pub struct RunnerReply {
    pub http: u16,
    pub body: Vec<u8>,
}

impl RunnerReply {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&self.body)))
    }

    pub fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }
}

static NONCE: AtomicU64 = AtomicU64::new(1);

/// One signed runner request, sent the way a runner sends it.
pub fn runner_call(
    base: &str,
    key: &PrivateKey,
    runner: &str,
    method: &str,
    path: &str,
    body: &[u8],
    job: Option<u64>,
) -> RunnerReply {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = format!(
        "n{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::SeqCst)
    );
    let msg = runner_auth::canonical(method, path, body, job, ts, &nonce);
    let sig = runner_auth::sign(key, &msg).unwrap();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let url = format!("{base}{path}");
    let headers = [
        (runner_auth::RUNNER_HEADER, runner.to_owned()),
        (runner_auth::SIGNATURE_HEADER, sig),
        ("shoephone-runner-timestamp", ts.to_string()),
        ("shoephone-runner-nonce", nonce),
    ];
    let resp = if method == "GET" {
        let mut req = agent.get(&url);
        for (k, v) in &headers {
            req = req.header(*k, v);
        }
        req.call().unwrap()
    } else {
        let mut req = agent.post(&url);
        for (k, v) in &headers {
            req = req.header(*k, v);
        }
        req.send(body).unwrap()
    };
    let http = resp.status().as_u16();
    let body = resp.into_body().read_to_vec().unwrap();
    RunnerReply { http, body }
}

/// POST a JSON body as a runner. `job` is the id the body names, if any.
pub fn runner_post(
    base: &str,
    key: &PrivateKey,
    runner: &str,
    path: &str,
    body: &serde_json::Value,
    job: Option<u64>,
) -> RunnerReply {
    let bytes = serde_json::to_vec(body).unwrap();
    runner_call(base, key, runner, "POST", path, &bytes, job)
}

pub async fn start_everything(
    dir: &Path,
    ca_key: &Path,
    notify: Option<NotifyConfig>,
    projects: &[(&str, &str)],
    runners: &[(&str, &PrivateKey)],
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
        runners: runners
            .iter()
            .map(|(n, k)| {
                (
                    (*n).to_owned(),
                    RunnerConfig {
                        public_key: k.public_key().to_openssh().unwrap(),
                    },
                )
            })
            .collect(),
        projects: projects
            .iter()
            .map(|(p, r)| {
                (
                    (*p).to_owned(),
                    ProjectConfig {
                        runner: (*r).to_owned(),
                    },
                )
            })
            .collect(),
    };
    let daemon = Arc::new(Daemon::new(config).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = daemon.clone().router();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (Client::new(&format!("http://{addr}")), daemon)
}

pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}
