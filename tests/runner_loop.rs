// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The runner loop end to end: the real daemon (with test hooks), the
//! runner in-process with the fake terraform and no sandbox, and approvals
//! through `/api/test/approve_job`.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use shoephone::api::{ApplyBody, JobStatus, TrustBody};
use shoephone::client::Client;
use shoephone::runner::client::Fault;
use shoephone::runner::config::{ProjectConfig, RunnerConfig, Source};
use shoephone::runner::exec;
use shoephone::runner::journal::Journal;
use shoephone::runner::run::{Runner, StartupError};
use shoephone::runner::state::{Applied, AppliedStatus, ProjectPaths};
use ssh_key::LineEnding;

use common::*;

const FAKE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fake-terraform.sh"
);
const CREATE_ONLY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/plan/create_only.json"
);
const REPLACE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/plan/replace.json"
);

const SCHEMA: &str = "[variables.region]\ntype = \"string\"\npattern = \"[a-z]+\"\n";

struct Fx {
    root: PathBuf,
    client: Arc<Client>,
    cfg: RunnerConfig,
    _daemon: Arc<shoephone::server::Daemon>,
}

impl Fx {
    async fn new(name: &str, show: &str) -> Fx {
        let root = scratch(&format!("runner-{name}"));
        let key = runner_key();
        let daemon_dir = root.join("daemon");
        std::fs::create_dir_all(&daemon_dir).unwrap();
        let (client, daemon) = start_runners(&daemon_dir, &[("web", "r1")], &[("r1", &key)]).await;
        let key_file = root.join("runner.key");
        key.write_openssh_file(&key_file, LineEnding::LF).unwrap();
        std::fs::create_dir_all(root.join("plugins/registry/p")).unwrap();
        std::fs::write(root.join("plugins/registry/p/provider"), b"provider v1").unwrap();
        let mut env = BTreeMap::new();
        env.insert(
            "FAKE_TERRAFORM_RECORD".to_string(),
            Source::Value(root.join("record").display().to_string()),
        );
        env.insert(
            "FAKE_TERRAFORM_SHOW".to_string(),
            Source::Value(show.to_string()),
        );
        let mut projects = BTreeMap::new();
        projects.insert(
            "web".to_string(),
            ProjectConfig {
                path: "infra".into(),
                terraform_version: "1.9.8".into(),
                backend_config: BTreeMap::new(),
                env,
                variables: BTreeMap::new(),
                schema_file: "shoephone-schema.toml".into(),
            },
        );
        let cfg = RunnerConfig {
            name: "r1".into(),
            daemon: client.base().to_owned(),
            key: key_file,
            state_dir: root.join("state"),
            log_dir: root.join("logs"),
            log_days: 30,
            terraform: FAKE.into(),
            plugin_dir: root.join("plugins"),
            bwrap: "/usr/bin/bwrap".into(),
            review_user: "shoephone-review".into(),
            terraform_user: "shoephone-terraform".into(),
            secret_command: vec!["/bin/echo".into()],
            secret_env: Vec::new(),
            terraform_timeout_minutes: 1,
            projects,
        };
        exec::test_hooks_run_without_sandbox();
        Fx {
            root,
            client: Arc::new(client),
            cfg,
            _daemon: daemon,
        }
    }

    /// A fresh runner over this fixture's state, started up.
    async fn runner(&self) -> Runner {
        let cfg = self.cfg.clone();
        blocking(move || {
            let mut r = Runner::new(cfg).unwrap();
            r.startup().unwrap();
            r
        })
        .await
    }

    fn set_env(&mut self, name: &str, value: Option<&str>) {
        let env = &mut self.cfg.projects.get_mut("web").unwrap().env;
        match value {
            Some(v) => env.insert(name.to_string(), Source::Value(v.to_string())),
            None => env.remove(name),
        };
    }

    fn project_dir(&self) -> PathBuf {
        self.cfg.state_dir.join("projects/web")
    }

    fn applied(&self) -> Option<Applied> {
        std::fs::read(self.project_dir().join("applied.json"))
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap())
    }

    fn record(&self) -> String {
        std::fs::read_to_string(self.root.join("record")).unwrap_or_default()
    }

    async fn status(&self, id: u64) -> JobStatus {
        let c = self.client.clone();
        blocking(move || c.job(id)).await.unwrap()
    }

    async fn pending(&self) -> serde_json::Value {
        let base = self.client.base().to_owned();
        blocking(move || {
            ureq::get(format!("{base}/api/pending"))
                .call()
                .unwrap()
                .into_body()
                .read_json::<serde_json::Value>()
                .unwrap()
        })
        .await
    }

    async fn approve(&self, id: u64) {
        let base = self.client.base().to_owned();
        blocking(move || {
            ureq::post(format!("{base}/api/test/approve_job"))
                .send_json(json!({ "id": id }))
                .unwrap();
        })
        .await;
    }

    async fn trust(&self, files: &[(&str, &str)]) -> u64 {
        let body = TrustBody {
            project: "web".into(),
            archive: STANDARD.encode(archive(files)),
            reason: "runner loop test: trust".into(),
            requester: "test".into(),
            context: None,
        };
        let c = self.client.clone();
        blocking(move || c.trust(&body)).await.unwrap().id
    }

    async fn apply(&self, manifest: &str) -> u64 {
        let body = ApplyBody {
            project: "web".into(),
            manifest: manifest.into(),
            allow_destroy: false,
            reason: "runner loop test: apply".into(),
            requester: "test".into(),
            context: None,
        };
        let c = self.client.clone();
        blocking(move || c.apply(&body)).await.unwrap().id
    }

    /// Trust the standard tree, driving `runner` through the whole job.
    async fn trusted(&self, runner: Runner) -> Runner {
        let id = self.trust(&standard_files()).await;
        let runner = step(runner).await;
        assert_eq!(self.status(id).await.state, "waiting");
        self.approve(id).await;
        let runner = step(runner).await;
        let st = self.status(id).await;
        assert_eq!(st.result.as_deref(), Some("trusted"), "{st:?}");
        runner
    }

    /// File an apply and drive it to its end, approving it on the way.
    async fn applied_job(&self, runner: Runner, manifest: &str) -> (Runner, JobStatus) {
        let id = self.apply(manifest).await;
        let runner = step(runner).await;
        let st = self.status(id).await;
        assert_eq!(st.state, "waiting", "{st:?}");
        self.approve(id).await;
        let runner = step(runner).await;
        (runner, self.status(id).await)
    }

    fn assert_no_job_leftovers(&self) {
        let jobs = self.cfg.state_dir.join("jobs");
        let left: Vec<_> = std::fs::read_dir(&jobs)
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "job directories left: {left:?}");
        let plans = self.project_dir().join("plans");
        let left: Vec<_> = std::fs::read_dir(&plans)
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "plan copies left: {left:?}");
    }
}

fn standard_files() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "infra/main.tf",
            "variable \"region\" {}\nresource \"null_resource\" \"c\" {}\n",
        ),
        ("infra/shoephone-schema.toml", SCHEMA),
        ("README.md", "not part of the execution input\n"),
    ]
}

/// A gzip tar of `files`, as `git archive` would produce.
fn archive(files: &[(&str, &str)]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for (path, content) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        tar.append_data(&mut h, path, content.as_bytes()).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

/// One pass of the loop, returning what it returned.
async fn try_step(mut runner: Runner) -> (Runner, Result<(), String>) {
    blocking(move || {
        let r = runner.step();
        (runner, r)
    })
    .await
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// A review worker that lies: it swaps in a harmless-looking diff, with a
/// digest to match, over the real candidate.
fn forge_review(job_dir: &Path) {
    let path = job_dir.join("review.json");
    let mut review: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let benign = "--- a/infra/main.tf\n+++ b/infra/main.tf\n+# a comment\n";
    review["diff"] = json!(benign);
    review["scope"]["diff"] = json!(shoephone::store::sha256_hex(benign));
    std::fs::write(&path, serde_json::to_vec(&review).unwrap()).unwrap();
}

/// One pass of the loop.
async fn step(mut runner: Runner) -> Runner {
    blocking(move || {
        runner.step().unwrap();
        runner
    })
    .await
}

fn sha(s: &str) -> String {
    shoephone::store::sha256_hex(s)
}

fn exists(p: &Path) -> bool {
    p.exists()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_mid_apply_reports_outcome_unknown() {
    let fx = Fx::new("unknown", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let (runner, st) = fx.applied_job(runner, r#"{"region":"east"}"#).await;
    assert_eq!(st.result.as_deref(), Some("applied"));
    drop(runner);
    // A crash between the journal's begin and end.
    let paths = ProjectPaths::new(&fx.cfg.state_dir, "web").unwrap();
    let journal = Journal::new(&paths);
    journal.begin(9_999).unwrap();

    let _runner = fx.runner().await;
    assert_eq!(
        journal.pending_unknown().unwrap(),
        None,
        "reported, then closed"
    );
    let applied = fx.applied().unwrap();
    assert_eq!(applied.status, AppliedStatus::Uncertain);
    assert_eq!(applied.manifest, r#"{"region":"east"}"#);
    let base = fx.client.base().to_owned();
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
async fn trust_then_apply_end_to_end() {
    let fx = Fx::new("e2e", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let project = fx.project_dir();
    assert!(exists(&project.join("trusted/infra/main.tf")));
    assert!(
        !exists(&project.join("trusted/README.md")),
        "only the execution input is trusted"
    );
    let trusted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join("trusted.json")).unwrap()).unwrap();
    assert_eq!(trusted["modes"]["infra/main.tf"], json!(0o644));
    fx.assert_no_job_leftovers();

    let (_runner, st) = fx.applied_job(runner, r#"{ "region" : "west" }"#).await;
    assert_eq!(st.result.as_deref(), Some("applied"), "{st:?}");
    let applied = fx.applied().unwrap();
    assert_eq!(applied.status, AppliedStatus::Applied);
    assert_eq!(applied.manifest, r#"{"region":"west"}"#);
    let record = fx.record();
    assert!(record.contains("planfile:fake plan"), "{record}");
    assert!(
        record.contains("manifest.tfvars.json"),
        "terraform reads the canonical manifest file"
    );
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_without_trust_refuses_no_trusted_revision() {
    let fx = Fx::new("untrusted", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let id = fx.apply(r#"{"region":"west"}"#).await;
    let _runner = step(runner).await;
    let st = fx.status(id).await;
    assert_eq!(st.result.as_deref(), Some("refused"), "{st:?}");
    assert_eq!(st.failure.unwrap().category, "no_trusted_revision");
    assert!(!fx.record().contains("arg:plan"), "nothing was planned");
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destructive_plan_without_flag_is_refused() {
    let fx = Fx::new("destroy", REPLACE).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let id = fx.apply(r#"{"region":"west"}"#).await;
    let _runner = step(runner).await;
    let st = fx.status(id).await;
    assert_eq!(st.result.as_deref(), Some("refused"), "{st:?}");
    let failure = st.failure.unwrap();
    assert_eq!(failure.category, "destroy_not_requested");
    assert!(!failure.addresses.is_empty(), "{failure:?}");
    assert!(fx.applied().is_none());
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_failure_marks_baseline_uncertain() {
    let mut fx = Fx::new("fail", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let (runner, st) = fx.applied_job(runner, r#"{"region":"east"}"#).await;
    assert_eq!(st.result.as_deref(), Some("applied"), "{st:?}");
    drop(runner);

    fx.set_env("FAKE_TERRAFORM_FAIL", Some("apply"));
    let runner = fx.runner().await;
    let (runner, st) = fx.applied_job(runner, r#"{"region":"west"}"#).await;
    assert_eq!(st.result.as_deref(), Some("apply_failed"), "{st:?}");
    let applied = fx.applied().unwrap();
    assert_eq!(applied.status, AppliedStatus::Uncertain);
    assert_eq!(
        applied.manifest, r#"{"region":"east"}"#,
        "the last applied manifest is kept"
    );
    fx.assert_no_job_leftovers();
    drop(runner);

    fx.set_env("FAKE_TERRAFORM_FAIL", None);
    let runner = fx.runner().await;
    let id = fx.apply(r#"{"region":"north"}"#).await;
    let _runner = step(runner).await;
    let job = fx.pending().await["job"].clone();
    assert_eq!(job["id"], json!(id));
    assert_eq!(job["scope"]["baseline_status"], "uncertain");
    assert_eq!(
        job["scope"]["baseline_manifest"],
        json!(sha(r#"{"region":"east"}"#))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_apply_shows_diff_against_last_applied() {
    let fx = Fx::new("second", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let (runner, st) = fx.applied_job(runner, r#"{"region":"east"}"#).await;
    assert_eq!(st.result.as_deref(), Some("applied"));

    fx.apply(r#"{"region":"west"}"#).await;
    let _runner = step(runner).await;
    let job = fx.pending().await["job"].clone();
    assert_eq!(job["kind"], "apply");
    assert_eq!(job["scope"]["baseline_status"], "applied");
    assert_eq!(job["display"]["manifest"], r#"{"region":"west"}"#);
    assert_eq!(job["display"]["baseline_manifest"], r#"{"region":"east"}"#);
    assert_eq!(
        job["scope"]["baseline_manifest"],
        json!(sha(r#"{"region":"east"}"#))
    );
    assert_eq!(job["scope"]["manifest"], json!(sha(r#"{"region":"west"}"#)));
    let text = job["display"]["address_text"].as_str().unwrap();
    assert_eq!(job["scope"]["addresses"], json!(sha(text)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_change_after_plan_fails_the_apply() {
    let fx = Fx::new("context", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let id = fx.apply(r#"{"region":"west"}"#).await;
    let runner = step(runner).await;
    fx.approve(id).await;
    std::fs::write(
        fx.root.join("plugins/registry/p/provider"),
        b"provider v2, swapped after the plan",
    )
    .unwrap();
    let _runner = step(runner).await;
    let st = fx.status(id).await;
    assert_eq!(st.result.as_deref(), Some("apply_failed"), "{st:?}");
    assert_eq!(st.failure.unwrap().category, "context_changed");
    let record = fx.record();
    assert!(record.contains("arg:plan"), "{record}");
    assert!(!record.contains("arg:apply"), "nothing was applied");
    assert!(fx.applied().is_none(), "the baseline is untouched");
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn declined_apply_cleans_up_its_plan() {
    let fx = Fx::new("declined", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let id = fx.apply(r#"{"region":"west"}"#).await;
    let runner = step(runner).await;
    assert!(
        fx.cfg.state_dir.join("jobs").join(id.to_string()).is_dir(),
        "the job directory is kept while the job waits"
    );
    assert!(
        fx.project_dir()
            .join(format!("plans/{id}.tfplan"))
            .is_file()
    );
    let c = fx.client.clone();
    blocking(move || c.kill_project("web")).await.unwrap();
    assert_eq!(fx.status(id).await.result.as_deref(), Some("killed"));
    let _runner = step(runner).await;
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_trust_reviews_against_the_trusted_baseline() {
    let fx = Fx::new("retrust", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let read = |p: PathBuf| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
    };
    let first = read(fx.project_dir().join("trusted.json"));

    let mut files = standard_files();
    files[0].1 = "variable \"region\" {}\nresource \"null_resource\" \"d\" {}\n";
    let id = fx.trust(&files).await;
    let runner = step(runner).await;
    let job = fx.pending().await["job"].clone();
    assert_eq!(job["id"], json!(id));
    assert_eq!(job["scope"]["baseline"], first["digest"]);
    let diff = job["display"]["diff"].as_str().unwrap();
    assert!(
        diff.contains("+resource \"null_resource\" \"d\" {}"),
        "{diff}"
    );
    assert!(
        diff.contains("-resource \"null_resource\" \"c\" {}"),
        "{diff}"
    );
    fx.approve(id).await;
    let _runner = step(runner).await;
    assert_eq!(fx.status(id).await.result.as_deref(), Some("trusted"));
    let second = read(fx.project_dir().join("trusted.json"));
    assert_eq!(second["digest"], job["scope"]["candidate"]);
    assert_ne!(second["digest"], first["digest"]);
    assert!(!fx.project_dir().join("trusted.prev").exists());
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_review_is_refused_review_inconsistent() {
    let fx = Fx::new("forged", CREATE_ONLY).await;
    exec::test_hooks_tamper_review(&fx.cfg.state_dir, forge_review);
    let runner = fx.runner().await;
    let id = fx.trust(&standard_files()).await;
    let _runner = step(runner).await;
    let st = fx.status(id).await;
    assert_eq!(st.result.as_deref(), Some("refused"), "{st:?}");
    assert_eq!(st.failure.unwrap().category, "review_inconsistent");
    assert!(!fx.project_dir().join("trusted.json").exists());
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_without_a_plan_is_failed_plan_lost() {
    let fx = Fx::new("orphan", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let id = fx.apply(r#"{"region":"west"}"#).await;
    let runner = step(runner).await;
    fx.approve(id).await;
    drop(runner);
    // A restart between submit and approval: the plan is gone.
    let runner = fx.runner().await;
    let _runner = step(runner).await;
    let st = fx.status(id).await;
    assert_eq!(st.result.as_deref(), Some("apply_failed"), "{st:?}");
    assert_eq!(st.failure.unwrap().category, "plan_lost");
    assert!(!fx.record().contains("arg:apply"), "nothing was applied");
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_claim_reply_still_applies_exactly_once() {
    let fx = Fx::new("lostclaim", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let id = fx.apply(r#"{"region":"west"}"#).await;
    let runner = step(runner).await;
    fx.approve(id).await;
    runner.test_hooks_fault("/api/runner/claim", Fault::LoseReply);
    let (runner, r) = try_step(runner).await;
    assert!(r.is_err(), "the lost reply is an error to back off on");
    assert_eq!(fx.status(id).await.state, "claimed");
    let _runner = step(runner).await;
    let st = fx.status(id).await;
    assert_eq!(st.result.as_deref(), Some("applied"), "{st:?}");
    assert_eq!(count(&fx.record(), "arg:apply"), 1, "applied exactly once");
    fx.assert_no_job_leftovers();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_trusted_finish_reply_keeps_the_trust() {
    let fx = Fx::new("losttrust", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let id = fx.trust(&standard_files()).await;
    let runner = step(runner).await;
    fx.approve(id).await;
    runner.test_hooks_fault("/api/runner/finish", Fault::LoseReply);
    let (runner, r) = try_step(runner).await;
    assert!(r.is_err());
    // The daemon recorded it; the runner does not know yet.
    assert_eq!(fx.status(id).await.result.as_deref(), Some("trusted"));
    let runner = step(runner).await;
    assert!(
        fx.project_dir().join("trusted.json").exists(),
        "the trust stands"
    );
    assert!(!fx.project_dir().join("install.json").exists());
    let paths = ProjectPaths::new(&fx.cfg.state_dir, "web").unwrap();
    assert_eq!(Journal::new(&paths).unfinished().unwrap(), None);
    // Daemon and runner agree, so an apply goes through.
    let (_runner, st) = fx.applied_job(runner, r#"{"region":"west"}"#).await;
    assert_eq!(st.result.as_deref(), Some("applied"), "{st:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_finish_failure_is_delivered_on_retry() {
    let fx = Fx::new("retryfinish", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let id = fx.apply(r#"{"region":"west"}"#).await;
    let runner = step(runner).await;
    fx.approve(id).await;
    runner.test_hooks_fault("/api/runner/finish", Fault::Unreachable);
    runner.test_hooks_fault("/api/runner/finish", Fault::Unreachable);
    let (runner, r) = try_step(runner).await;
    assert!(r.is_err());
    assert_eq!(fx.status(id).await.state, "claimed");
    let paths = ProjectPaths::new(&fx.cfg.state_dir, "web").unwrap();
    assert!(
        matches!(
            Journal::new(&paths).unfinished().unwrap(),
            Some(shoephone::runner::journal::Unfinished::Reporting { .. })
        ),
        "the result is journaled before it is sent"
    );
    // The next pass retries before polling, and fails again.
    let (runner, r) = try_step(runner).await;
    assert!(r.is_err());
    let _runner = step(runner).await;
    let st = fx.status(id).await;
    assert_eq!(st.result.as_deref(), Some("applied"), "{st:?}");
    assert_eq!(count(&fx.record(), "arg:apply"), 1);
    assert_eq!(Journal::new(&paths).unfinished().unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_with_the_daemon_unreachable_retries() {
    let fx = Fx::new("startretry", CREATE_ONLY).await;
    let paths = ProjectPaths::new(&fx.cfg.state_dir, "web").unwrap();
    let journal = Journal::new(&paths);
    journal.begin(4_242).unwrap();
    let cfg = fx.cfg.clone();
    let mut runner = blocking(move || Runner::new(cfg).unwrap()).await;
    runner.test_hooks_fault("/api/runner/finish", Fault::Unreachable);
    let (mut runner, first) = blocking(move || {
        let r = runner.startup();
        (runner, r)
    })
    .await;
    assert!(matches!(first, Err(StartupError::Retry(_))), "{first:?}");
    assert!(
        journal.unfinished().unwrap().is_some(),
        "kept until delivered"
    );
    let second = blocking(move || runner.startup()).await;
    assert!(second.is_ok(), "{second:?}");
    assert_eq!(journal.unfinished().unwrap(), None);
    let base = fx.client.base().to_owned();
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
async fn result_of_an_apply_cut_off_before_finish_is_resent_at_startup() {
    let fx = Fx::new("resend", CREATE_ONLY).await;
    let runner = fx.runner().await;
    let runner = fx.trusted(runner).await;
    let id = fx.apply(r#"{"region":"west"}"#).await;
    let runner = step(runner).await;
    fx.approve(id).await;
    runner.test_hooks_fault("/api/runner/finish", Fault::Unreachable);
    let (runner, r) = try_step(runner).await;
    assert!(r.is_err());
    // The runner dies with the result unsent.
    drop(runner);
    assert_eq!(fx.status(id).await.state, "claimed");
    let paths = ProjectPaths::new(&fx.cfg.state_dir, "web").unwrap();
    assert_eq!(
        Journal::new(&paths).unfinished().unwrap(),
        Some(shoephone::runner::journal::Unfinished::Reporting {
            job: id,
            result: "applied".into(),
            failure: None,
        })
    );

    let _runner = fx.runner().await;
    let st = fx.status(id).await;
    assert_eq!(st.result.as_deref(), Some("applied"), "{st:?}");
    assert_eq!(count(&fx.record(), "arg:apply"), 1);
    assert_eq!(Journal::new(&paths).unfinished().unwrap(), None);
}
