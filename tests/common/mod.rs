// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The in-process daemon harness shared by the integration tests. Each test
//! crate uses a different subset, hence the `dead_code` allowance.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use shoephone::ca::UserCa;
use shoephone::client::Client;
use shoephone::config::{Config, PolicyConfig, ProjectConfig};
use shoephone::notify::NotifyConfig;
use shoephone::server::Daemon;

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
        runners: Default::default(),
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
