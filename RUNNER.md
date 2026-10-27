<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->
# shoephone-runner {{VERSION}}

The runner is the single-purpose host that holds Terraform credentials. It
polls the shoephone daemon for jobs, reviews the agent's bundle in a
credential-free worker, plans and applies only what a person approved on
their phone, and reports digests back. Full Terraform output stays on the
runner. Agents do not run it; the operator does.

## Verbs

- `shoephone-runner [--config <file>] run`: the poll loop.
- `shoephone-runner review-worker <job-dir>`: the credential-free review
  step, started by `run`. Reads `request.json`, writes `review.json`.
- `shoephone-runner [--json] diff-digest <baseline-digest|none>
  <baseline-checkout|-> <candidate-checkout> <project-path>`: the operator's
  check of a trust review whose diff was too large to show.
- `shoephone-runner --skill`: print this document. `--version` prints the
  version.

`--config` defaults to `/etc/shoephone-runner/shoephone-runner.toml`. An
example with placeholder values is `contrib/runner/shoephone-runner.toml.example`.

`run` is not implemented yet; it exits 3.

### review-worker

`request.json` holds `baseline_dir` (null for a first trust), `candidate_dir`,
`project`, `policy_version`, `project_path`, `schema_file`, `variables` (the
runner-supplied variable names only) and the archive header modes that
`unpack` returned: `candidate_modes`, and `baseline_modes` when there is a
baseline. A missing field is a bad request (exit 3). `review.json` holds the
scope, the diff (absent when over 256 KiB), the verification command and the
warnings, or a `failure`. A refused review (including `no_changes`, a
candidate equal to the baseline) exits 30.

### diff-digest

Recomputes the execution input of each checkout from the files on disk (modes
from the permission bits, normalized to 0644 or 0755), refuses unless the
baseline checkout's digest equals `<baseline-digest>` (use `none` and `-` for
a first trust), and prints two lines on stdout, `candidate <digest>` and
`diff <digest>`; with `--json`, `{"candidate": .., "diff": ..}`. Both must
equal the digests on the approve page. Exit 0 on success; 30 with a message on
stderr when the baseline does not match or an input is refused; 2 on usage.

Both checkouts must be clean exports of the revisions, made with `git
worktree add` or `git archive | tar x`: no `.terraform/` directory and no
untracked files, since every file under the project and its modules is part
of the digest. A `.git` directory at the checkout root is ignored.

## Config

One TOML file, unknown fields refused. Top level: `name`, `daemon`, `key`,
`state_dir`, `log_dir`, `log_days` (default 30), `terraform`, `plugin_dir`,
`bwrap`, `review_user`, `terraform_user`, `secret_command`, `secret_env`,
`terraform_timeout_minutes` (default 60). Each
`[projects.<name>]` has `path`, `terraform_version`, `schema_file` (default
`shoephone-schema.toml`) and the tables `backend_config`, `env` and
`variables`. Project names match `^[A-Za-z0-9._-]{1,64}$`; paths are
relative with no `..`.

Every value in those tables is `{ value = "..." }` or `{ secret = "ref" }`.
`secret_command` is run with the reference appended as its last argument, in
an environment holding only `PATH=/usr/bin:/bin` and the runner variables
named in `secret_env` (default empty), with no stdin and a 30 s limit; its
stdout, at most 64 KiB with one trailing newline removed, is the secret.
Runner-supplied `variables` must not overlap the project's schema; that is
checked when the project is trusted.

## State

Under `state_dir/projects/<name>/`:

- `trusted/`: the unpacked trusted tree.
- `trusted.json`: `{ digest, schema }`.
- `applied.json`: `{ manifest, status }`, status `applied` or `uncertain`.
- `journal.json`: `{ job, phase, result }`, phase `claimed`, `applying` or
  `done`.
- `plans/<job>.tfplan`: root's copy of a job's saved plan, taken as soon as
  `terraform plan` writes it. That copy is what is hashed, shown, approved
  and applied (mounted read-only over the job directory's plan file), and
  it is deleted when the job ends.

Every write is atomic: a 0600 temp file, fsync, rename, fsync of the
directory.

## Terraform runs

Terraform runs as `terraform_user` inside bubblewrap, which sees only the
job directory (read-write), the Terraform binary, `plugin_dir`, `/usr`, the
`/lib` directories, and `/etc/ssl`, `/etc/pki` and `/etc/resolv.conf` where
present (a missing `/etc/ssl` or `/etc/resolv.conf` is warned about at
startup). Its environment is only the project's values, `TF_IN_AUTOMATION`,
`TF_INPUT`, `HOME` (the job directory), an empty `TF_CLI_CONFIG_FILE` and
`TF_CLI_ARGS_init`. A command running longer than
`terraform_timeout_minutes` is killed, with category `terraform_timeout`.
Full output goes to `log_dir/<project>/<job>.log` (0600, directories 0700),
which only the operator reads; logs older than `log_days` are pruned at
startup.

## Builds

A deployed build must never enable the `test-hooks` feature. That feature
lets this repository's tests run Terraform without the sandbox, and a
`shoephone-runner` built with it refuses to start (exit 3) unless
`SHOEPHONE_RUNNER_ALLOW_TEST_HOOKS=1`, which only the integration tests set.
`cargo build --release` does not enable it.

## Exit codes

Bands follow the house contract: under 100 is portable.

- 0: success.
- 2: usage error.
- 3: config missing or invalid, a bad `review-worker` request, a `test-hooks`
  build started without the test variable, or the verb is not implemented yet.
- 30: a review or `diff-digest` was refused.
