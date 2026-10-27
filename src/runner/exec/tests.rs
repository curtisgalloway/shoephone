// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! Executor tests. They run `tests/fixtures/fake-terraform.sh` in place of
//! Terraform, with the sandbox replaced by direct execution through the
//! `cfg(test)`-only `TEST_LAUNCH` switch.

use super::*;
use crate::runner::config::Source;
use crate::runner::state::ProjectPaths;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Instant, SystemTime};

const FAKE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fake-terraform.sh"
);
const SHOW: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/plan/create_only.json"
);

/// What every resolved secret looks like: `value-of-<reference>`.
const SENTINEL: &str = "value-of-ref/";

/// Variables a POSIX shell adds to its own environment, which the fake
/// terraform's `env` call then shows.
const SHELL_ADDED: [&str; 4] = ["PWD", "SHLVL", "_", "OLDPWD"];

struct Fx {
    root: tempfile::TempDir,
    cfg: RunnerConfig,
    project: ProjectConfig,
}

impl Fx {
    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    fn job_dir(&self) -> PathBuf {
        self.path("job")
    }

    fn record(&self) -> String {
        fs::read_to_string(self.path("record")).unwrap_or_default()
    }

    /// The fake terraform's calls, each as (argv, env).
    fn calls(&self) -> Vec<(Vec<String>, BTreeMap<String, String>)> {
        let mut calls = Vec::new();
        for line in self.record().lines() {
            if line == "call" {
                calls.push((Vec::new(), BTreeMap::new()));
            } else if let Some(a) = line.strip_prefix("arg:") {
                calls.last_mut().unwrap().0.push(a.to_string());
            } else if let Some(e) = line.strip_prefix("env:") {
                let (k, v) = e.split_once('=').unwrap();
                calls
                    .last_mut()
                    .unwrap()
                    .1
                    .insert(k.to_string(), v.to_string());
            }
        }
        calls
    }

    fn set_env(&mut self, name: &str, value: &str) {
        self.project
            .env
            .insert(name.to_string(), Source::Value(value.to_string()));
    }
}

fn source_map(items: &[(&str, Source)]) -> BTreeMap<String, Source> {
    items
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn secret(r: &str) -> Source {
    Source::Secret(r.to_string())
}

fn value(v: &str) -> Source {
    Source::Value(v.to_string())
}

/// A secret command that logs each reference to `calls` and its own
/// environment to `secret-env`, then prints `value-of-<reference>`.
fn echo_script(root: &Path) -> String {
    format!(
        "printf '%s\\n' \"$1\" >> '{calls}'\n/usr/bin/env > '{env}'\nprintf 'value-of-%s\\n' \"$1\"\n",
        calls = root.join("calls").display(),
        env = root.join("secret-env").display(),
    )
}

fn fixture() -> Fx {
    let root = tempfile::tempdir().unwrap();
    let r = root.path().to_path_buf();
    fs::write(r.join("secret.sh"), echo_script(&r)).unwrap();
    for d in ["state", "logs", "plugins/registry/p", "job/checkout/infra"] {
        fs::create_dir_all(r.join(d)).unwrap();
    }
    fs::write(r.join("plugins/registry/p/provider"), b"provider v1").unwrap();
    fs::write(r.join("state/runner.key"), b"RUNNER-KEY").unwrap();
    let cfg = RunnerConfig {
        name: "runner-1".into(),
        daemon: "https://daemon.invalid".into(),
        key: r.join("state/runner.key"),
        state_dir: r.join("state"),
        log_dir: r.join("logs"),
        log_days: 30,
        terraform: FAKE.into(),
        plugin_dir: r.join("plugins"),
        bwrap: "/usr/bin/bwrap".into(),
        review_user: "shoephone-review".into(),
        terraform_user: "shoephone-terraform".into(),
        secret_command: vec!["/bin/sh".into(), r.join("secret.sh").display().to_string()],
        secret_env: Vec::new(),
        projects: BTreeMap::new(),
    };
    let project = ProjectConfig {
        path: "infra".into(),
        terraform_version: "1.9.8".into(),
        backend_config: source_map(&[
            ("address", value("https://state.invalid/web")),
            ("password", secret("ref/backend")),
        ]),
        env: source_map(&[
            ("PROVIDER_TOKEN", secret("ref/token")),
            (
                "FAKE_TERRAFORM_RECORD",
                value(&r.join("record").display().to_string()),
            ),
            ("FAKE_TERRAFORM_SHOW", value(SHOW)),
        ]),
        variables: source_map(&[("api_key", secret("ref/api")), ("region", value("r1"))]),
        schema_file: "shoephone-schema.toml".into(),
    };
    Fx { root, cfg, project }
}

fn job(dir: &Path) -> Job<'_> {
    Job {
        project: "web",
        id: 7,
        dir,
        module: "infra",
    }
}

/// Runs this test thread's Terraform directly, without bubblewrap.
fn no_sandbox() {
    TEST_LAUNCH.with(|c| c.set(Some(Launch::Direct)));
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let t = e.file_type().unwrap();
        if t.is_dir() {
            files_under(&e.path(), out);
        } else if t.is_file() {
            out.push(e.path());
        }
    }
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------------
// Resolver

#[test]
fn resolver_output_never_reaches_review_worker() {
    // The review worker is a child of the root process and reads only its
    // job directory. So a resolved value must not land in the root
    // process's environment (which a child inherits), in any file, or in
    // anything printed with `{:?}`.
    let fx = fixture();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let got = |list: &[(String, Secret)], k: &str| {
        list.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.expose().to_string())
    };
    assert_eq!(
        got(&resolved.env, "PROVIDER_TOKEN").as_deref(),
        Some("value-of-ref/token")
    );
    assert_eq!(
        got(&resolved.tf_vars, "api_key").as_deref(),
        Some("value-of-ref/api")
    );
    assert_eq!(got(&resolved.tf_vars, "region").as_deref(), Some("r1"));
    assert_eq!(
        got(&resolved.backend, "password").as_deref(),
        Some("value-of-ref/backend")
    );
    let masks: BTreeSet<&str> = resolved.masks.iter().map(Secret::expose).collect();
    assert_eq!(
        masks,
        BTreeSet::from([
            "value-of-ref/api",
            "value-of-ref/backend",
            "value-of-ref/token"
        ])
    );

    let debug = format!("{resolved:?}");
    assert!(!debug.contains(SENTINEL), "{debug}");
    assert!(debug.contains("[redacted]"));
    for (k, v) in std::env::vars() {
        assert!(!v.contains(SENTINEL), "{k} holds a resolved value");
    }
    let mut files = Vec::new();
    files_under(fx.root.path(), &mut files);
    for f in files {
        let text = fs::read(&f).unwrap();
        assert!(
            !String::from_utf8_lossy(&text).contains(SENTINEL),
            "{} holds a resolved value",
            f.display()
        );
    }
}

#[test]
fn secret_command_runs_once_per_reference_in_a_clean_environment() {
    let mut fx = fixture();
    fx.project
        .variables
        .insert("again".into(), secret("ref/token"));
    resolve(&fx.cfg, &fx.project).unwrap();
    let calls = fs::read_to_string(fx.path("calls")).unwrap();
    let mut refs: Vec<&str> = calls.lines().collect();
    refs.sort();
    assert_eq!(refs, ["ref/api", "ref/backend", "ref/token"]);

    let env = fs::read_to_string(fx.path("secret-env")).unwrap();
    let names: BTreeSet<&str> = env
        .lines()
        .map(|l| l.split_once('=').unwrap().0)
        .filter(|n| !SHELL_ADDED.contains(n))
        .collect();
    assert_eq!(names, BTreeSet::from(["PATH"]), "{env}");
    assert!(env.contains("PATH=/usr/bin:/bin\n"));
}

#[test]
fn secret_failure_names_nothing() {
    let fx = fixture();
    let cases = [
        "printf 'stderr names %s\\n' \"$1\" >&2\nexit 3\n".to_string(),
        "exit 0\n".to_string(),
        "printf '\\n'\n".to_string(),
        "/usr/bin/head -c 70000 /dev/zero | /usr/bin/tr '\\0' a\n".to_string(),
    ];
    for script in cases {
        fs::write(fx.path("secret.sh"), &script).unwrap();
        let err = resolve(&fx.cfg, &fx.project).unwrap_err();
        assert_eq!(err.category, "secret_unavailable", "{script}");
        assert!(err.addresses.is_empty());
        assert_eq!(err.detail, None);
    }
}

#[test]
fn secret_value_has_one_trailing_newline_trimmed() {
    let fx = fixture();
    fs::write(fx.path("secret.sh"), "printf ' two words \\n\\n'\n").unwrap();
    let got = run_secret(&fx.cfg.secret_command, "r", &[], Duration::from_secs(5)).unwrap();
    assert_eq!(got.expose(), " two words \n");
}

#[test]
fn secret_command_is_killed_at_its_timeout() {
    let fx = fixture();
    fs::write(fx.path("secret.sh"), "sleep 30\nprintf late\n").unwrap();
    let start = Instant::now();
    let err = run_secret(&fx.cfg.secret_command, "r", &[], Duration::from_millis(300)).unwrap_err();
    assert_eq!(err.category, "secret_unavailable");
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[test]
fn reserved_and_malformed_names_are_refused() {
    for name in [
        "HOME",
        "TF_CLI_ARGS_init",
        "TF_CLI_ARGS",
        "TF_VAR_x",
        "A=B",
        "",
    ] {
        let mut fx = fixture();
        fx.set_env(name, "v");
        let err = resolve(&fx.cfg, &fx.project).unwrap_err();
        assert_eq!(err.category, "env_name_refused", "{name:?}");
    }
    let mut fx = fixture();
    fx.project
        .backend_config
        .insert("bad key".into(), value("v"));
    assert_eq!(
        resolve(&fx.cfg, &fx.project).unwrap_err().category,
        "backend_config_refused"
    );
    let mut fx = fixture();
    fx.project.variables.insert("a=b".into(), value("v"));
    assert_eq!(
        resolve(&fx.cfg, &fx.project).unwrap_err().category,
        "variable_name_refused"
    );
}

// ---------------------------------------------------------------------
// Terraform invocation

#[test]
fn terraform_env_has_only_resolved_values() {
    let fx = fixture();
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let out = terraform(&fx.cfg, &job(&dir), &["init", "-input=false"], &resolved).unwrap();
    assert_eq!(out.code, Some(0));

    let calls = fx.calls();
    assert_eq!(calls.len(), 1);
    let (argv, env) = &calls[0];
    assert_eq!(
        argv,
        &[
            format!("-chdir={}/checkout/infra", dir.display()),
            "init".to_string(),
            "-input=false".to_string(),
        ]
    );
    let want: BTreeMap<String, String> = [
        ("PROVIDER_TOKEN", "value-of-ref/token".to_string()),
        (
            "FAKE_TERRAFORM_RECORD",
            fx.path("record").display().to_string(),
        ),
        ("FAKE_TERRAFORM_SHOW", SHOW.to_string()),
        ("TF_VAR_api_key", "value-of-ref/api".to_string()),
        ("TF_VAR_region", "r1".to_string()),
        ("TF_IN_AUTOMATION", "1".to_string()),
        ("TF_INPUT", "0".to_string()),
        ("HOME", dir.display().to_string()),
        (
            "TF_CLI_ARGS_init",
            format!(
                "-plugin-dir={} -backend-config={}/backend.hcl",
                fx.cfg.plugin_dir.display(),
                dir.display()
            ),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let mut got = env.clone();
    for n in SHELL_ADDED {
        got.remove(n);
    }
    assert_eq!(got, want);
    assert!(
        env.values().all(|v| !v.contains("value-of-ref/backend")),
        "the backend secret goes only into backend.hcl"
    );
}

#[test]
fn terraform_refuses_without_root_outside_test_mode() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let fx = fixture();
    let resolved = Resolved::default();
    let dir = fx.job_dir();
    let err = terraform(&fx.cfg, &job(&dir), &["init"], &resolved).unwrap_err();
    assert_eq!(err.category, "sandbox_unavailable");
    let err = plan(&fx.cfg, &job(&dir), &Canonical("{}".into()), &resolved).unwrap_err();
    assert_eq!(err.category, "sandbox_unavailable");
    assert!(!dir.join(MANIFEST_FILE).exists());
    assert!(fx.calls().is_empty());
}

#[test]
fn bwrap_args_expose_only_job_and_plugin_dirs() {
    let fx = fixture();
    let dir = fx.job_dir();
    let args: Vec<String> = bwrap_args(&fx.cfg, &dir)
        .into_iter()
        .map(|a| a.into_string().unwrap())
        .collect();
    let has = |seq: &[&str]| args.windows(seq.len()).any(|w| w == seq);
    for flag in [
        "--die-with-parent",
        "--unshare-all",
        "--share-net",
        "--new-session",
    ] {
        assert!(has(&[flag]), "{flag}");
    }
    let job_s = dir.display().to_string();
    let plugins = fx.cfg.plugin_dir.display().to_string();
    for seq in [
        &["--proc", "/proc"][..],
        &["--dev", "/dev"],
        &["--tmpfs", "/tmp"],
        &["--ro-bind", "/usr", "/usr"],
        &["--ro-bind", "/etc/ssl", "/etc/ssl"],
        &["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"],
        &["--ro-bind", FAKE, FAKE],
        &["--ro-bind", &plugins, &plugins],
        &["--bind", &job_s, &job_s],
        &["--chdir", &job_s],
    ] {
        assert!(has(seq), "{seq:?} in {args:?}");
    }
    let tmp = args.iter().position(|a| a == "--tmpfs").unwrap();
    let bind = args.iter().position(|a| a == "--bind").unwrap();
    assert!(tmp < bind, "a job dir under /tmp must survive the tmpfs");
    for hidden in [&fx.cfg.state_dir, &fx.cfg.log_dir, &fx.cfg.key] {
        let h = hidden.display().to_string();
        assert!(args.iter().all(|a| !a.starts_with(&h)), "{h} is bound");
    }
    assert!(
        args.iter().all(|a| a != "--setenv"),
        "values on the bwrap command line are readable by every local user"
    );
    assert_eq!(args.iter().filter(|a| *a == "--bind").count(), 1);
}

#[test]
fn log_file_is_0600() {
    let mut fx = fixture();
    fx.cfg.log_dir = fx.path("fresh-logs");
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    terraform(&fx.cfg, &job(&dir), &["init"], &resolved).unwrap();
    terraform(&fx.cfg, &job(&dir), &["apply", "x"], &resolved).unwrap();

    let log = fx.path("fresh-logs/web/7.log");
    assert_eq!(mode(&log), 0o600);
    assert_eq!(mode(&fx.path("fresh-logs/web")), 0o700);
    assert_eq!(mode(&fx.path("fresh-logs")), 0o700);
    let text = fs::read_to_string(&log).unwrap();
    for want in [
        "Terraform has been successfully initialized!",
        "fake-terraform stderr for init",
        "\"apply_complete\"",
        "fake-terraform stderr for apply",
    ] {
        assert!(text.contains(want), "{want} missing from\n{text}");
    }

    // A planted symlink at a log path is refused, and its target untouched.
    fs::write(fx.path("target"), b"keep").unwrap();
    std::os::unix::fs::symlink(fx.path("target"), fx.path("fresh-logs/web/8.log")).unwrap();
    let job8 = Job { id: 8, ..job(&dir) };
    let err = terraform(&fx.cfg, &job8, &["init"], &resolved).unwrap_err();
    assert_eq!(err.category, "log_unavailable");
    assert_eq!(fs::read(fx.path("target")).unwrap(), b"keep");
}

#[test]
fn old_logs_are_pruned() {
    let fx = fixture();
    let logs = fx.path("logs");
    fs::create_dir_all(logs.join("web")).unwrap();
    fs::create_dir_all(fx.path("outside")).unwrap();
    let age = |p: &Path, days: u64| {
        let f = fs::File::options().write(true).open(p).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(days * 86_400))
            .unwrap();
    };
    for (rel, days) in [("web/old.log", 40), ("web/new.log", 1)] {
        fs::write(logs.join(rel), b"x").unwrap();
        age(&logs.join(rel), days);
    }
    fs::write(fx.path("outside/old.log"), b"keep").unwrap();
    age(&fx.path("outside/old.log"), 400);
    std::os::unix::fs::symlink(fx.path("outside/old.log"), logs.join("web/link.log")).unwrap();
    std::os::unix::fs::symlink(fx.path("outside"), logs.join("linked-project")).unwrap();

    assert_eq!(prune_logs(&logs, 30).unwrap(), 1);
    assert!(!logs.join("web/old.log").exists());
    assert!(logs.join("web/new.log").exists());
    assert!(fs::symlink_metadata(logs.join("web/link.log")).is_ok());
    assert_eq!(fs::read(fx.path("outside/old.log")).unwrap(), b"keep");
    assert_eq!(prune_logs(&fx.path("no-such-dir"), 30).unwrap(), 0);
}

// ---------------------------------------------------------------------
// Plan and apply

#[test]
fn manifest_file_is_outside_checkout() {
    let fx = fixture();
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let canonical = Canonical(r#"{"count":2,"name":"web"}"#.into());
    let (summary, plan_file, sha) = plan(&fx.cfg, &job(&dir), &canonical, &resolved).unwrap();

    let manifest = dir.join(MANIFEST_FILE);
    assert_eq!(fs::read_to_string(&manifest).unwrap(), canonical.0);
    assert_eq!(mode(&manifest), 0o600);
    let mut files = Vec::new();
    files_under(&dir.join(CHECKOUT), &mut files);
    assert!(
        files.iter().all(|f| !f.ends_with(MANIFEST_FILE)),
        "{files:?}"
    );
    assert!(
        !dir.join(BACKEND_FILE).exists(),
        "backend.hcl is removed after init"
    );

    let calls = fx.calls();
    let subcommands: Vec<&str> = calls.iter().map(|(a, _)| a[1].as_str()).collect();
    assert_eq!(subcommands, ["init", "plan", "show"]);
    let plan_args = &calls[1].0;
    for want in [
        "-json".to_string(),
        "-input=false".to_string(),
        "-lock-timeout=60s".to_string(),
        format!("-out={}", dir.join(PLAN_FILE).display()),
        format!("-var-file={}", manifest.display()),
    ] {
        assert!(plan_args.contains(&want), "{want} not in {plan_args:?}");
    }
    assert_eq!(
        calls[2].0[2..],
        [
            "-json".to_string(),
            dir.join(PLAN_FILE).display().to_string()
        ]
    );
    assert_eq!(calls[0].0[2..], ["-input=false".to_string()]);

    assert_eq!(plan_file, dir.join(PLAN_FILE));
    assert_eq!(sha, sha256_file(&plan_file));
    let want = crate::runner::plan::summarize(&fs::read_to_string(SHOW).unwrap()).unwrap();
    assert_eq!(summary, want);
}

fn sha256_file(p: &Path) -> String {
    use ssh_key::sha2::{Digest, Sha256};
    Sha256::digest(fs::read(p).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn backend_file_is_written_before_init_and_escaped() {
    let mut fx = fixture();
    fx.project
        .backend_config
        .insert("path".into(), value("a \"q\" \\ ${x} %{y}\nz"));
    // Copy backend.hcl aside while init runs, since the executor removes it.
    let copy = fx.path("backend-copy");
    fs::write(
        fx.path("tf.sh"),
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" init \"*) /bin/cp '{}' '{}' ;; esac\nexec /bin/sh '{FAKE}' \"$@\"\n",
            fx.job_dir().join(BACKEND_FILE).display(),
            copy.display()
        ),
    )
    .unwrap();
    fs::set_permissions(fx.path("tf.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    fx.cfg.terraform = fx.path("tf.sh");
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    plan(&fx.cfg, &job(&dir), &Canonical("{}".into()), &resolved).unwrap();

    let text = fs::read_to_string(&copy).unwrap();
    let body = hcl::parse(&text).unwrap();
    let mut got = BTreeMap::new();
    for attr in body.attributes() {
        let v = match &attr.expr {
            hcl::Expression::String(s) => s.clone(),
            hcl::Expression::TemplateExpr(t) => t.to_string(),
            other => panic!("{other:?}"),
        };
        got.insert(attr.key.to_string(), v);
    }
    assert_eq!(got["password"], "value-of-ref/backend");
    assert_eq!(got["address"], "https://state.invalid/web");
    assert!(
        text.contains(r#"path = "a \"q\" \\ $${x} %%{y}\nz""#),
        "{text}"
    );
}

#[test]
fn hcl_string_escapes_every_special() {
    assert_eq!(hcl_string("plain"), r#""plain""#);
    assert_eq!(
        hcl_string("a\"b\\c\nd\re\tf\u{1}g${h}%{i}$j%k"),
        r#""a\"b\\c\nd\re\tf\u0001g$${h}%%{i}$j%k""#
    );
}

#[test]
fn plan_failure_carries_no_terraform_text() {
    for (stage, category) in [("init", "init_failed"), ("plan", "plan_failed")] {
        let mut fx = fixture();
        fx.set_env("FAKE_TERRAFORM_FAIL", stage);
        fx.project
            .env
            .insert("FAKE_TERRAFORM_TEXT".into(), secret("ref/leak"));
        no_sandbox();
        let resolved = resolve(&fx.cfg, &fx.project).unwrap();
        let dir = fx.job_dir();
        let err = plan(&fx.cfg, &job(&dir), &Canonical("{}".into()), &resolved).unwrap_err();
        assert_eq!(err.category, category);
        assert_eq!(err.addresses, ["null_resource.broken"]);
        assert_eq!(err.detail, None);
        assert!(!format!("{err:?}").contains(SENTINEL));
        // The full text is in the root-only log.
        let log = fs::read_to_string(fx.path("logs/web/7.log")).unwrap();
        assert!(log.contains("value-of-ref/leak"));
    }
}

#[test]
fn plan_file_tamper_is_refused() {
    let fx = fixture();
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let journal = Journal::new(&ProjectPaths::new(&fx.cfg.state_dir, "web").unwrap());
    let (_, plan_file, sha) =
        plan(&fx.cfg, &job(&dir), &Canonical("{}".into()), &resolved).unwrap();

    let wrong = "0".repeat(64);
    let err = apply(&fx.cfg, &job(&dir), &plan_file, &wrong, &resolved, &journal).unwrap_err();
    assert_eq!(err.category, "plan_changed");
    assert_eq!(
        journal.pending_unknown().unwrap(),
        None,
        "apply never began"
    );

    let mut bytes = fs::read(&plan_file).unwrap();
    bytes.push(b'!');
    fs::write(&plan_file, &bytes).unwrap();
    let err = apply(&fx.cfg, &job(&dir), &plan_file, &sha, &resolved, &journal).unwrap_err();
    assert_eq!(err.category, "plan_changed");

    let calls = fx.calls();
    assert!(
        calls.iter().all(|(a, _)| a[1] != "apply"),
        "terraform apply ran"
    );

    bytes.pop();
    fs::write(&plan_file, &bytes).unwrap();
    apply(&fx.cfg, &job(&dir), &plan_file, &sha, &resolved, &journal).unwrap();
    let calls = fx.calls();
    let (argv, _) = calls.last().unwrap();
    assert_eq!(
        argv[1..],
        [
            "apply".to_string(),
            "-json".to_string(),
            "-input=false".to_string(),
            "-lock-timeout=60s".to_string(),
            plan_file.display().to_string(),
        ]
    );
    assert_eq!(journal.pending_unknown().unwrap(), None);
    let entry: crate::runner::state::Journal = serde_json::from_slice(
        &fs::read(
            ProjectPaths::new(&fx.cfg.state_dir, "web")
                .unwrap()
                .journal_json(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(entry.result.as_deref(), Some("applied"));
}

#[test]
fn apply_failure_is_journaled_done_with_its_category() {
    let mut fx = fixture();
    no_sandbox();
    let dir = fx.job_dir();
    let journal = Journal::new(&ProjectPaths::new(&fx.cfg.state_dir, "web").unwrap());
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let (_, plan_file, sha) =
        plan(&fx.cfg, &job(&dir), &Canonical("{}".into()), &resolved).unwrap();
    fx.set_env("FAKE_TERRAFORM_FAIL", "apply");
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let err = apply(&fx.cfg, &job(&dir), &plan_file, &sha, &resolved, &journal).unwrap_err();
    assert_eq!(err.category, "apply_failed");
    assert_eq!(err.detail, None);
    assert_eq!(journal.pending_unknown().unwrap(), None);
}

// ---------------------------------------------------------------------
// Pinned context

#[test]
fn context_change_between_plan_and_claim_is_refused() {
    let mut fx = fixture();
    fs::copy(FAKE, fx.path("terraform")).unwrap();
    fx.cfg.terraform = fx.path("terraform");
    let at_plan = context_digest(&fx.cfg, &fx.project).unwrap();
    assert_eq!(at_plan.len(), 64);
    check_context(&fx.cfg, &fx.project, &at_plan).unwrap();

    let refused = |fx: &Fx| {
        let err = check_context(&fx.cfg, &fx.project, &at_plan).unwrap_err();
        assert_eq!(err.category, "context_changed");
        assert_eq!(err.detail, None);
    };

    let provider = fx.path("plugins/registry/p/provider");
    fs::write(&provider, b"provider v2").unwrap();
    refused(&fx);
    fs::write(&provider, b"provider v1").unwrap();
    check_context(&fx.cfg, &fx.project, &at_plan).unwrap();

    fs::write(fx.path("plugins/registry/p/extra"), b"").unwrap();
    refused(&fx);
    fs::remove_file(fx.path("plugins/registry/p/extra")).unwrap();

    fs::write(fx.path("terraform"), b"#!/bin/sh\nexit 0\n").unwrap();
    refused(&fx);
    fs::copy(FAKE, fx.path("terraform")).unwrap();
    check_context(&fx.cfg, &fx.project, &at_plan).unwrap();

    let saved = fx.project.clone();
    fx.project.variables.insert("region".into(), value("r2"));
    refused(&fx);
    fx.project = saved.clone();
    fx.project
        .env
        .insert("PROVIDER_TOKEN".into(), secret("ref/other-token"));
    refused(&fx);
    fx.project = saved;
    check_context(&fx.cfg, &fx.project, &at_plan).unwrap();

    fs::remove_file(fx.path("terraform")).unwrap();
    let err = check_context(&fx.cfg, &fx.project, &at_plan).unwrap_err();
    assert_eq!(err.category, "context_unavailable");
}

// ---------------------------------------------------------------------
// The real sandbox (Linux with bubblewrap only)

/// Ruling 28: this cannot run on the macOS development host. Run it on a
/// Linux host with bubblewrap before deployment:
/// `cargo test bwrap_hides_runner_secrets -- --ignored`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs Linux with bubblewrap at /usr/bin/bwrap"]
fn bwrap_hides_runner_secrets() {
    let fx = fixture();
    TEST_LAUNCH.with(|c| c.set(Some(Launch::BwrapAsSelf)));
    let dir = fx.job_dir();
    fs::write(dir.join("visible.txt"), b"job file").unwrap();
    fs::write(fx.path("runner.toml"), b"name = \"runner-1\"\n").unwrap();
    let run = |path: &Path| {
        let out = command(
            &fx.cfg,
            Launch::BwrapAsSelf,
            &dir,
            Path::new("/usr/bin/cat"),
            &[path.as_os_str().to_owned()],
            &[],
        )
        .output()
        .unwrap();
        eprintln!(
            "cat {} -> {:?}: {}",
            path.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    };
    let visible = run(&dir.join("visible.txt"));
    assert!(visible.status.success(), "positive control failed");
    assert_eq!(visible.stdout, b"job file");
    for hidden in [fx.cfg.key.clone(), fx.path("runner.toml"), fx.path("logs")] {
        let out = run(&hidden);
        assert!(!out.status.success(), "{} is visible", hidden.display());
    }
}
