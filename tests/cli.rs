// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! CLI-side behavior that does not need the daemon in the loop: per-host
//! session keys, atomic certificate writes, and how transport failures map
//! onto exit codes.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use shoephone::client::Client;
use shoephone::exit::Status;
use shoephone::session::Session;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shoephone-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn for_host_gives_distinct_keys_under_expected_paths() {
    let base = scratch("distinct-hosts");
    let a = Session::for_host(base.clone(), "host-a").unwrap();
    let b = Session::for_host(base.clone(), "host-b").unwrap();
    assert_eq!(a.dir(), base.join("hosts").join("host-a"));
    assert_eq!(b.dir(), base.join("hosts").join("host-b"));
    assert_eq!(a.key_path(), base.join("hosts/host-a/session_ed25519"));
    assert_eq!(b.key_path(), base.join("hosts/host-b/session_ed25519"));

    let key_a = a.public_key().unwrap();
    let key_b = b.public_key().unwrap();
    assert!(key_a.starts_with("ssh-ed25519 "));
    assert!(key_b.starts_with("ssh-ed25519 "));
    assert_ne!(key_a, key_b, "each host must get its own keypair");
    assert!(a.key_path().exists());
    assert!(b.key_path().exists());

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn for_host_refuses_unsafe_host_names() {
    let base = scratch("unsafe-hosts");
    assert!(Session::for_host(base.clone(), "../x").is_err());
    assert!(Session::for_host(base.clone(), "a/b").is_err());
    assert!(Session::for_host(base.clone(), ".hidden").is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn write_certificate_is_atomic_and_leaves_no_tmp_file() {
    let base = scratch("atomic-cert");
    let session = Session::for_host(base.clone(), "web01").unwrap();
    session.public_key().unwrap();
    session
        .write_certificate("  ssh-ed25519-cert-v01@openssh.com AAAAsomefakecert  ")
        .unwrap();

    let cert_path = session.cert_path();
    let content = std::fs::read_to_string(&cert_path).unwrap();
    assert_eq!(
        content,
        "ssh-ed25519-cert-v01@openssh.com AAAAsomefakecert\n"
    );

    let leftovers: Vec<_> = std::fs::read_dir(cert_path.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "leftover tmp files: {leftovers:?}");

    std::fs::remove_dir_all(&base).unwrap();
}

/// A timeout after the connection is already open is ambiguous: the daemon
/// may have received and acted on the request before the response never
/// arrived.
#[test]
fn timeout_after_connecting_is_retry_unknown() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // Accept and hold the connection open, but never write a
            // response, so the client's request eventually times out
            // waiting for one.
            let mut stream = stream;
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            std::thread::sleep(Duration::from_secs(5));
        }
    });

    let client = Client::with_timeout(&format!("http://{addr}"), Duration::from_millis(300));
    let err = client.status().unwrap_err();
    assert_eq!(err.status(), Status::RetryUnknown);
}

/// Nothing listening at all fails the connection outright: the daemon was
/// never reached, so this is unambiguous.
#[test]
fn refused_connection_is_unreachable() {
    let client = Client::new("http://127.0.0.1:1");
    let err = client.status().unwrap_err();
    assert_eq!(err.status(), Status::Unreachable);
}

// ---------------------------------------------------------------------
// The binary itself: stdout piped, stdin closed, NO_COLOR=1, as CI runs it
// ---------------------------------------------------------------------

mod common;

use std::process::{Command, Output, Stdio};

use serde_json::json;

fn shoephone(args: &[&str], dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shoephone"));
    cmd.args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env_remove("SHOEPHONE_DAEMON")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .args([
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
        ])
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn trust_in_dirty_tree_exits_3() {
    let repo = scratch("dirty-tree");
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join("main.tf"), "# one\n").unwrap();
    git(&repo, &["add", "main.tf"]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    std::fs::write(repo.join("main.tf"), "# two\n").unwrap();

    let out = shoephone(
        &[
            "trust",
            "net",
            "--reason",
            "r",
            "--daemon",
            "http://127.0.0.1:1",
        ],
        &repo,
    )
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(3), "stderr: {}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("git status"),
        "{}",
        text(&out.stderr)
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn trust_outside_a_repository_exits_3() {
    let dir = scratch("not-a-repo");
    let out = shoephone(
        &[
            "trust",
            "net",
            "--reason",
            "r",
            "--daemon",
            "http://127.0.0.1:1",
        ],
        &dir,
    )
    .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap())
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(3), "stderr: {}", text(&out.stderr));
}

#[test]
fn apply_missing_manifest_exits_3() {
    let dir = scratch("no-manifest");
    let out = shoephone(
        &[
            "apply",
            "net",
            "--manifest",
            "does-not-exist.json",
            "--reason",
            "r",
            "--daemon",
            "http://127.0.0.1:1",
        ],
        &dir,
    )
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(3), "stderr: {}", text(&out.stderr));
    assert!(out.stdout.is_empty());
}

#[test]
fn apply_oversized_manifest_exits_30() {
    let dir = scratch("big-manifest");
    std::fs::write(dir.join("m.json"), vec![b' '; 64 * 1024 + 1]).unwrap();
    let out = shoephone(
        &[
            "apply",
            "net",
            "--manifest",
            "m.json",
            "--reason",
            "r",
            "--daemon",
            "http://127.0.0.1:1",
        ],
        &dir,
    )
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(30), "stderr: {}", text(&out.stderr));
}

#[test]
fn skill_mentions_trust_and_apply() {
    let dir = scratch("skill");
    let out = shoephone(&["--skill"], &dir).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let skill = text(&out.stdout);
    for needle in [
        "shoephone trust",
        "shoephone apply",
        "outcome_unknown",
        "102",
        "never retry",
    ] {
        assert!(skill.contains(needle), "SKILL.md lacks {needle:?}");
    }
}

fn run_apply_against_daemon(
    result: &'static str,
    category: &'static str,
    extra: &'static [&'static str],
    name: &str,
) -> Output {
    let dir = scratch(name);
    std::fs::write(dir.join("m.json"), "{}").unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let key = common::runner_key();
        let (client, _d) = common::start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
        let base = client.base().to_owned();
        let mut args = vec![
            "apply",
            "net",
            "--manifest",
            "m.json",
            "--reason",
            "r",
            "--daemon",
            &base,
        ];
        args.extend_from_slice(extra);
        let mut child = shoephone(&args, &dir).spawn().unwrap();
        let client = std::sync::Arc::new(client);
        let c = client.clone();
        let id = common::blocking(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                if let Some(job) = c.status().unwrap().job {
                    return Some((job.id, child));
                }
                if child.try_wait().unwrap().is_some() || std::time::Instant::now() > deadline {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
        .await;
        let Some((id, child)) = id else {
            panic!("the binary never filed a job");
        };
        let (b2, k2) = (base.clone(), key.clone());
        let reply = common::blocking(move || {
            common::runner_post(&b2, &k2, "r1", "/api/runner/poll", &json!({}), None);
            common::runner_post(
                &b2,
                &k2,
                "r1",
                "/api/runner/refuse",
                &json!({
                    "id": id,
                    "result": result,
                    "failure": { "category": category, "addresses": ["a.b"], "detail": null },
                }),
                Some(id),
            )
        })
        .await;
        assert_eq!(reply.http, 200, "{}", text(&reply.body));
        common::blocking(move || child.wait_with_output().unwrap()).await
    })
}

#[test]
fn apply_refused_exits_30_with_category_on_stderr() {
    let out = run_apply_against_daemon("refused", "policy", &[], "apply-refused");
    assert_eq!(out.status.code(), Some(30), "stderr: {}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.contains("policy"), "{err}");
    assert!(err.contains("a.b"), "{err}");
}

#[test]
fn apply_plan_failed_exits_100_and_json_has_the_shape() {
    let out = run_apply_against_daemon("plan_failed", "tf_error", &["--json"], "apply-planfail");
    assert_eq!(
        out.status.code(),
        Some(100),
        "stderr: {}",
        text(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["empty"], false);
    let r = &v["result"];
    assert_eq!(r["project"], "net");
    assert_eq!(r["kind"], "apply");
    assert_eq!(r["outcome"], "plan_failed");
    assert_eq!(r["category"], "tf_error");
    assert_eq!(r["addresses"], json!(["a.b"]));
    assert!(r["counts"].is_null());
    assert!(r["changed_variables"].is_null());
}

#[test]
fn apply_json_carries_counts_and_changed_variables() {
    let dir = scratch("apply-summary");
    std::fs::write(dir.join("m.json"), "{}").unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let out = rt.block_on(async {
        let key = common::runner_key();
        let (client, _d) = common::start_runners(&dir, &[("net", "r1")], &[("r1", &key)]).await;
        let base = client.base().to_owned();
        let mut child = shoephone(
            &[
                "apply",
                "net",
                "--manifest",
                "m.json",
                "--reason",
                "r",
                "--daemon",
                &base,
                "--json",
            ],
            &dir,
        )
        .spawn()
        .unwrap();
        let client = std::sync::Arc::new(client);
        let c = client.clone();
        let (id, child) = common::blocking(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                if let Some(job) = c.status().unwrap().job {
                    return (job.id, child);
                }
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "the binary exited early"
                );
                assert!(std::time::Instant::now() < deadline, "no job filed");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
        .await;
        let hex = |c: char| c.to_string().repeat(64);
        let sha = |t: &str| shoephone::store::sha256_hex(t);
        let record = shoephone::store::TrustRecord {
            project: "net".into(),
            digest: hex('1'),
            schema: hex('2'),
            job: 1,
            at: 1,
        };
        shoephone::store::Store::new(&dir)
            .save_trusted(&[record])
            .unwrap();
        let manifest = r#"{"region":"us-east-1"}"#;
        let addresses = "create a.b\n";
        let (b2, k2) = (base.clone(), key.clone());
        let scope = json!({
            "kind": "apply", "project": "net", "revision": hex('1'), "schema": hex('2'),
            "manifest": sha(manifest), "baseline_manifest": null, "baseline_status": "none",
            "plan": hex('3'), "destructive": false,
            "counts": { "create": 1, "update": 0, "replace": 0, "delete": 0 },
            "addresses": sha(addresses),
        });
        let display = json!({
            "manifest": manifest, "baseline_manifest": null, "address_text": addresses,
        });
        let reply = common::blocking(move || {
            common::runner_post(&b2, &k2, "r1", "/api/runner/poll", &json!({}), None);
            common::runner_post(
                &b2,
                &k2,
                "r1",
                "/api/runner/submit",
                &json!({ "id": id, "scope": scope, "display": display }),
                Some(id),
            )
        })
        .await;
        assert_eq!(reply.http, 200, "{}", text(&reply.body));
        let b3 = base.clone();
        common::blocking(move || {
            ureq::post(format!("{b3}/api/test/approve_job"))
                .send_json(json!({ "id": id }))
                .unwrap();
        })
        .await;
        let (b4, k4) = (base.clone(), key.clone());
        let reply = common::blocking(move || {
            common::runner_post(
                &b4,
                &k4,
                "r1",
                "/api/runner/claim",
                &json!({ "id": id }),
                Some(id),
            );
            common::runner_post(
                &b4,
                &k4,
                "r1",
                "/api/runner/finish",
                &json!({ "id": id, "result": "applied" }),
                Some(id),
            )
        })
        .await;
        assert_eq!(reply.http, 200, "{}", text(&reply.body));
        common::blocking(move || child.wait_with_output().unwrap()).await
    });
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = &v["result"];
    assert_eq!(r["outcome"], "applied");
    assert_eq!(
        r["counts"],
        json!({"create": 1, "update": 0, "replace": 0, "delete": 0})
    );
    assert_eq!(r["changed_variables"], json!(["region"]));
    assert!(!text(&out.stdout).contains("us-east-1"));
}

/// A scripted daemon: answers a job filing with job 7, and each
/// `GET /api/job/7` with the next `(status, body)` from `polls`, repeating
/// the last one.
fn scripted_daemon(polls: Vec<(u16, serde_json::Value)>) -> String {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut polls = polls.into_iter().peekable();
        let mut last = (500, json!({}));
        for sock in listener.incoming() {
            let mut sock = sock.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let head = loop {
                let n = sock.read(&mut buf).unwrap();
                raw.extend_from_slice(&buf[..n]);
                let t = String::from_utf8_lossy(&raw).into_owned();
                if let Some(end) = t.find("\r\n\r\n") {
                    let len = t[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if raw.len() >= end + 4 + len || n == 0 {
                        break t[..end].to_string();
                    }
                }
            };
            let (status, body) = if head.starts_with("POST /api/") {
                (
                    200,
                    json!({ "id": 7, "match_code": "ABCD-EFGH", "expires": 0 }),
                )
            } else {
                if let Some(next) = polls.next() {
                    last = next;
                }
                last.clone()
            };
            let body = body.to_string();
            let _ = write!(
                sock,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    base
}

fn job_state(kind: &str, state: &str) -> (u16, serde_json::Value) {
    (
        200,
        json!({ "id": 7, "project": "net", "kind": kind, "state": state }),
    )
}

fn forgotten() -> (u16, serde_json::Value) {
    (
        404,
        json!({ "code": "no_such_job", "error": "no job with that id" }),
    )
}

fn apply_against(base: &str, name: &str) -> Output {
    let dir = scratch(name);
    std::fs::write(dir.join("m.json"), "{}").unwrap();
    shoephone(
        &[
            "apply",
            "net",
            "--manifest",
            "m.json",
            "--reason",
            "r",
            "--daemon",
            base,
        ],
        &dir,
    )
    .output()
    .unwrap()
}

#[test]
fn a_job_forgotten_before_its_approval_exits_22() {
    let base = scripted_daemon(vec![job_state("apply", "working"), forgotten()]);
    let out = apply_against(&base, "forgotten-early");
    assert_eq!(out.status.code(), Some(22), "stderr: {}", text(&out.stderr));
    assert!(!text(&out.stderr).contains("outcome is unknown"));
}

#[test]
fn a_job_forgotten_after_its_claim_exits_102() {
    for state in ["approved", "claimed"] {
        let base = scripted_daemon(vec![job_state("apply", state), forgotten()]);
        let out = apply_against(&base, &format!("forgotten-{state}"));
        assert_eq!(
            out.status.code(),
            Some(102),
            "{state}: {}",
            text(&out.stderr)
        );
    }
}

#[test]
fn a_failed_trust_is_reported_as_a_trust() {
    let repo = scratch("trust-failed");
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join("main.tf"), "# one\n").unwrap();
    git(&repo, &["add", "main.tf"]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let done = json!({
        "id": 7, "project": "net", "kind": "trust", "state": "done",
        "result": "apply_failed",
        "failure": { "category": "plan_lost", "addresses": [], "detail": null },
    });
    let base = scripted_daemon(vec![(200, done)]);
    let out = shoephone(&["trust", "net", "--reason", "r", "--daemon", &base], &repo)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(101),
        "stderr: {}",
        text(&out.stderr)
    );
    let err = text(&out.stderr);
    assert!(err.contains("plan_lost"), "{err}");
    assert!(err.contains("not trusted"), "{err}");
    assert!(!err.contains("the apply"), "{err}");
}
