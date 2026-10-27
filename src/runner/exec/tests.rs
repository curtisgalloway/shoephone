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
    for d in ["state", "plugins/registry/p", "job/checkout/infra"] {
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
        terraform_timeout_minutes: 60,
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
        "TF_CLI_CONFIG_FILE",
        "TF_LOG",
        "TF_LOG_PATH",
        "TF_LOG_CORE",
        "TF_LOG_PROVIDER",
        "TF_LOG_SDK",
        "TF_LOG_SDK_PROTO",
        "TF_LOG_SDK_PROTO_DATA_DIR",
        "TF_PLUGIN_CACHE_DIR",
        "TF_DATA_DIR",
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
            "TF_CLI_CONFIG_FILE",
            dir.join(CLI_CONFIG_FILE).display().to_string(),
        ),
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
    let rc = dir.join(CLI_CONFIG_FILE);
    assert_eq!(fs::read(&rc).unwrap(), b"", "an empty CLI config");
    assert_eq!(mode(&rc), 0o600);
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
    let args: Vec<String> = bwrap_args(&fx.cfg, &dir, Some(9))
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
    assert!(has(&["--cap-drop", "ALL"]));
    let job_s = dir.display().to_string();
    let plugins = fx.cfg.plugin_dir.display().to_string();
    for seq in [
        &["--proc", "/proc"][..],
        &["--dev", "/dev"],
        &["--tmpfs", "/tmp"],
        &["--ro-bind", "/usr", "/usr"],
        &["--ro-bind", FAKE, FAKE],
        &["--ro-bind", &plugins, &plugins],
        &["--bind", &job_s, &job_s],
        &["--chdir", &job_s],
    ] {
        assert!(has(seq), "{seq:?} in {args:?}");
    }
    for etc in ["/etc/ssl", "/etc/pki", "/etc/resolv.conf"] {
        assert_eq!(
            has(&["--ro-bind", etc, etc]),
            Path::new(etc).exists(),
            "{etc} is bound exactly when it exists"
        );
    }
    let plan_dest = dir.join(PLAN_FILE).display().to_string();
    assert!(has(&["--ro-bind-data", "9", &plan_dest]));
    let data = args.iter().position(|a| a == "--ro-bind-data").unwrap();
    let tmp = args.iter().position(|a| a == "--tmpfs").unwrap();
    let bind = args.iter().position(|a| a == "--bind").unwrap();
    assert!(tmp < bind, "a job dir under /tmp must survive the tmpfs");
    assert!(bind < data, "the verified plan is mounted over the job dir");
    let without: Vec<OsString> = bwrap_args(&fx.cfg, &dir, None);
    assert!(without.iter().all(|a| a != "--ro-bind-data"));
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

    // An existing log directory that is not exactly 0700 is refused.
    fs::set_permissions(fx.path("fresh-logs/web"), fs::Permissions::from_mode(0o755)).unwrap();
    let err = terraform(&fx.cfg, &job(&dir), &["init"], &resolved).unwrap_err();
    assert_eq!(err.category, "log_unavailable");
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

    // The returned plan is the root-only copy, identical to what plan wrote.
    let copy = fx.path("state/projects/web/plans/7.tfplan");
    assert_eq!(plan_file, copy);
    assert_eq!(sha, sha256_file(&copy));
    assert_eq!(
        fs::read(&copy).unwrap(),
        fs::read(dir.join(PLAN_FILE)).unwrap()
    );
    assert_eq!(mode(&copy), 0o600);
    assert_eq!(mode(&fx.path("state/projects/web/plans")), 0o700);
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
        assert!(
            !dir.join(BACKEND_FILE).exists(),
            "{stage}: backend.hcl left"
        );
        assert!(!fx.path("state/projects/web/plans/7.tfplan").exists());
    }
}

fn journal_result(fx: &Fx) -> Option<String> {
    let path = ProjectPaths::new(&fx.cfg.state_dir, "web")
        .unwrap()
        .journal_json();
    let entry: crate::runner::state::Journal =
        serde_json::from_slice(&fs::read(path).ok()?).unwrap();
    entry.result
}

fn planned(fx: &Fx) -> (Resolved, Journal, PathBuf, String) {
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let journal = Journal::new(&ProjectPaths::new(&fx.cfg.state_dir, "web").unwrap());
    let (_, copy, sha) = plan(&fx.cfg, &job(&dir), &Canonical("{}".into()), &resolved).unwrap();
    (resolved, journal, copy, sha)
}

fn apply_ran(fx: &Fx) -> bool {
    fx.calls().iter().any(|(a, _)| a[1] == "apply")
}

#[test]
fn plan_file_tamper_is_refused() {
    let fx = fixture();
    let (resolved, journal, copy, _) = planned(&fx);
    let dir = fx.job_dir();
    let wrong = "0".repeat(64);
    let err = apply(&fx.cfg, &job(&dir), &copy, &wrong, &resolved, &journal).unwrap_err();
    assert_eq!(err.category, "plan_changed");
    assert_eq!(
        journal.pending_unknown().unwrap(),
        None,
        "apply never began"
    );
    assert!(!apply_ran(&fx));
    assert!(!copy.exists(), "the job ended, so its copy is gone");
}

#[test]
fn root_copy_edit_is_refused_as_plan_changed() {
    let fx = fixture();
    let (resolved, journal, copy, sha) = planned(&fx);
    let mut bytes = fs::read(&copy).unwrap();
    bytes.push(b'!');
    fs::write(&copy, &bytes).unwrap();
    let dir = fx.job_dir();
    let err = apply(&fx.cfg, &job(&dir), &copy, &sha, &resolved, &journal).unwrap_err();
    assert_eq!(err.category, "plan_changed");
    assert!(!apply_ran(&fx));
    assert_eq!(journal_result(&fx), None);
    assert!(!copy.exists());
}

#[test]
fn job_dir_plan_edit_does_not_change_what_apply_uses() {
    let fx = fixture();
    let (resolved, journal, copy, sha) = planned(&fx);
    let dir = fx.job_dir();
    let original = fs::read_to_string(&copy).unwrap();
    // terraform_user owns the job dir and can rewrite its plan file.
    fs::write(dir.join(PLAN_FILE), b"evil plan\n").unwrap();

    apply(&fx.cfg, &job(&dir), &copy, &sha, &resolved, &journal).unwrap();
    let calls = fx.calls();
    let (argv, _) = calls.last().unwrap();
    assert_eq!(
        argv[1..],
        [
            "apply".to_string(),
            "-json".to_string(),
            "-input=false".to_string(),
            "-lock-timeout=60s".to_string(),
            dir.join(PLAN_FILE).display().to_string(),
        ]
    );
    let record = fx.record();
    let used: Vec<&str> = record
        .lines()
        .filter_map(|l| l.strip_prefix("planfile:"))
        .collect();
    assert_eq!(
        used,
        [original.trim_end_matches('\n')],
        "apply read the verified bytes"
    );
    assert_eq!(journal.pending_unknown().unwrap(), None);
    assert_eq!(journal_result(&fx).as_deref(), Some("applied"));
    assert_eq!(
        journal.unfinished().unwrap(),
        Some(crate::runner::journal::Unfinished::Reporting {
            job: 7,
            result: "applied".into(),
            failure: None,
        }),
        "the result is left to report, so a crash now is re-sent at startup"
    );
    assert!(!copy.exists(), "the copy is deleted when the job ends");

    // A copy path other than this job's is refused.
    let other = fx.path("state/projects/web/plans/8.tfplan");
    let err = apply(&fx.cfg, &job(&dir), &other, &sha, &resolved, &journal).unwrap_err();
    assert_eq!(err.category, "path_refused");
}

#[test]
fn discard_plan_removes_the_root_copy() {
    let fx = fixture();
    let (_, _, copy, _) = planned(&fx);
    assert!(copy.exists());
    discard_plan(&fx.cfg, &job(&fx.job_dir()));
    assert!(!copy.exists());
}

#[test]
fn terraform_is_killed_at_its_timeout() {
    let mut fx = fixture();
    fx.set_env("FAKE_TERRAFORM_SLEEP", "init");
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let start = Instant::now();
    let err = run(
        &fx.cfg,
        Launch::Direct,
        &job(&dir),
        &["init"],
        &resolved,
        None,
        Duration::from_millis(500),
    )
    .unwrap_err();
    assert_eq!(err.category, "terraform_timeout");
    assert!(start.elapsed() < Duration::from_secs(10));
    let log = fs::read_to_string(fx.path("logs/web/7.log")).unwrap();
    assert!(log.contains("killed: timeout"), "{log}");
}

#[test]
fn stdout_kept_in_memory_is_capped() {
    let mut fx = fixture();
    let big = fx.path("big.json");
    fs::write(&big, vec![b'x'; 17 * 1024 * 1024]).unwrap();
    fx.set_env("FAKE_TERRAFORM_SHOW", &big.display().to_string());
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let out = terraform(&fx.cfg, &job(&dir), &["show", "-json", "x"], &resolved).unwrap();
    assert!(out.truncated);
    assert!(out.stdout.len() <= 16 * 1024 * 1024);
    let logged = fs::metadata(fx.path("logs/web/7.log")).unwrap().len();
    assert!(logged > 17 * 1024 * 1024, "the log keeps all of it");
}

#[test]
fn plan_fd_is_moved_above_stdio() {
    let fx = fixture();
    fs::write(fx.path("p"), b"x").unwrap();
    let f = fs::File::open(fx.path("p")).unwrap();
    let dup = fd_above_stdio(&f).unwrap();
    assert!(dup.as_raw_fd() > 2);
    // SAFETY: F_GETFD on a descriptor we own.
    let flags = unsafe { libc::fcntl(dup.as_raw_fd(), libc::F_GETFD) };
    assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
}

#[test]
fn bwrap_version_gates_disable_userns() {
    use super::sandbox::version_has_disable_userns as has;
    assert!(has("bubblewrap 0.8.0"));
    assert!(has("bubblewrap 0.11.0\n"));
    assert!(has("bubblewrap 1.0"));
    assert!(!has("bubblewrap 0.6.2"));
    assert!(!has("bubblewrap"));
    assert!(!has(""));
}

#[test]
fn prune_continues_past_an_unreadable_project() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let fx = fixture();
    let logs = fx.path("logs");
    for d in ["a-locked", "b-open"] {
        fs::create_dir_all(logs.join(d)).unwrap();
    }
    let old = logs.join("b-open/old.log");
    fs::write(&old, b"x").unwrap();
    fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(90 * 86_400))
        .unwrap();
    fs::set_permissions(logs.join("a-locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let removed = prune_logs(&logs, 30);
    fs::set_permissions(logs.join("a-locked"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(removed.unwrap(), 1);
    assert!(!old.exists());
}

#[test]
fn apply_failure_is_journaled_for_reporting_with_its_category() {
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
    match journal.unfinished().unwrap() {
        Some(crate::runner::journal::Unfinished::Reporting {
            result, failure, ..
        }) => {
            assert_eq!(result, "apply_failed");
            assert_eq!(failure.unwrap().category, "apply_failed");
        }
        other => panic!("expected a result to report, got {other:?}"),
    }
}

#[test]
fn finish_result_maps_interrupted_applies_to_unknown() {
    let f = |c: &str| Err(refuse(c));
    assert_eq!(finish_result(&Ok(())), ("applied", None));
    assert_eq!(finish_result(&f("terraform_timeout")).0, "outcome_unknown");
    assert_eq!(finish_result(&f("terraform_crashed")).0, "outcome_unknown");
    let (r, failure) = finish_result(&f("apply_failed"));
    assert_eq!(r, "apply_failed");
    assert_eq!(failure.unwrap().category, "apply_failed");
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
    let run_with = |path: &Path, plan_fd: Option<std::os::fd::RawFd>| {
        let out = command(
            &fx.cfg,
            Launch::BwrapAsSelf,
            &dir,
            Path::new("/usr/bin/cat"),
            &[path.as_os_str().to_owned()],
            &[],
            plan_fd,
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
    let run = |path: &Path| run_with(path, None);
    let visible = run(&dir.join("visible.txt"));
    assert!(visible.status.success(), "positive control failed");
    assert_eq!(visible.stdout, b"job file");
    for hidden in [fx.cfg.key.clone(), fx.path("runner.toml"), fx.path("logs")] {
        let out = run(&hidden);
        assert!(!out.status.success(), "{} is visible", hidden.display());
    }

    // The verified plan is what the sandbox sees at job_dir/plan.tfplan,
    // whatever terraform_user left in the job directory.
    let verified_bytes = b"verified plan bytes".to_vec();
    let copy = fx.path("state/verified.tfplan");
    fs::write(&copy, &verified_bytes).unwrap();
    fs::write(dir.join(PLAN_FILE), b"evil plan").unwrap();
    let sha = sha256_file(&copy);
    let verified = open_verified(&copy, &sha).unwrap();
    let fd = fd_above_stdio(&verified).unwrap();
    let out = run_with(&dir.join(PLAN_FILE), Some(fd.as_raw_fd()));
    assert!(out.status.success());
    assert_eq!(out.stdout, verified_bytes);
}

// ---------------------------------------------------------------------
// Secret values never leave in an address

#[test]
fn reveals_and_scrub_use_only_secrets_of_eight_or_more_characters() {
    let resolved = Resolved {
        masks: vec![Secret("s3cr3t-value".into()), Secret("short".into())],
        ..Resolved::default()
    };
    assert!(resolved.reveals("aws_x.a[\"s3cr3t-value\"]"));
    assert!(!resolved.reveals("aws_x.short"), "under 8 characters");
    let f = resolved.scrub(Failure {
        category: "apply_failed".into(),
        addresses: vec!["ok.a".into(), "x.s3cr3t-value".into(), "x.short".into()],
        detail: None,
    });
    assert_eq!(f.addresses, ["ok.a", "x.short"]);
    assert_eq!(f.category, "apply_failed");
}

#[test]
fn plan_failure_addresses_holding_a_secret_are_dropped() {
    let mut fx = fixture();
    fx.set_env("FAKE_TERRAFORM_FAIL", "plan");
    fx.project
        .env
        .insert("FAKE_TERRAFORM_ADDRESS".into(), secret("ref/addr"));
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let err = plan(&fx.cfg, &job(&dir), &Canonical("{}".into()), &resolved).unwrap_err();
    assert_eq!(err.category, "plan_failed");
    assert!(err.addresses.is_empty(), "{:?}", err.addresses);
}

#[test]
fn a_planned_address_holding_a_secret_refuses_the_plan() {
    let mut fx = fixture();
    let show = fx.path("show.json");
    fs::write(
        &show,
        r#"{"resource_changes":[{"address":"null_resource.value-of-ref/token","change":{"actions":["create"]}}]}"#,
    )
    .unwrap();
    fx.set_env("FAKE_TERRAFORM_SHOW", &show.display().to_string());
    no_sandbox();
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let err = plan(&fx.cfg, &job(&dir), &Canonical("{}".into()), &resolved).unwrap_err();
    assert_eq!(err.category, "plan_address_refused");
    assert!(err.addresses.is_empty());
    assert!(!fx.path("state/projects/web/plans/7.tfplan").exists());
}

#[test]
fn apply_failure_addresses_holding_a_secret_are_dropped_before_the_journal() {
    let mut fx = fixture();
    fx.project
        .env
        .insert("FAKE_TERRAFORM_ADDRESS".into(), secret("ref/addr"));
    let (_, journal, copy, sha) = planned(&fx);
    fx.set_env("FAKE_TERRAFORM_FAIL", "apply");
    let resolved = resolve(&fx.cfg, &fx.project).unwrap();
    let dir = fx.job_dir();
    let err = apply(&fx.cfg, &job(&dir), &copy, &sha, &resolved, &journal).unwrap_err();
    assert_eq!(err.category, "apply_failed");
    assert!(err.addresses.is_empty(), "{:?}", err.addresses);
    match journal.unfinished().unwrap() {
        Some(crate::runner::journal::Unfinished::Reporting { failure, .. }) => {
            assert!(failure.unwrap().addresses.is_empty());
        }
        other => panic!("{other:?}"),
    }
}
