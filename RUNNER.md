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

### run

Startup: probe the sandbox (warnings on stderr), prune old logs, remove
every job directory and plan copy an earlier run left behind, then act on
whatever `journal.json` left open, before the first poll:

- a claimed apply, or one still `applying`, is reported `outcome_unknown`
  (the baseline is marked `uncertain`);
- a claimed trust is reported `apply_failed` with category
  `runner_restarted`, and a half-installed trust is put back;
- a result journaled but not acknowledged is sent again.

Startup does not finish until the daemon has every one of these (it retries
with backoff). An unreadable journal stops the runner (exit 3) until the
operator checks the project by hand.

The loop polls every 2 s, backing off to 30 s while the daemon cannot be
reached, and handles one job at a time. Every request is signed with the
runner key over a fresh nonce and the current time; a `stale_signature`
refusal is retried with a new signature. The daemon URL must be `https://`
(rustls with the platform verifier, so a private CA in the system trust
store works); plain `http://` is refused unless the host is `127.0.0.1`,
`::1` or `localhost`.

Every claim is journaled before it is sent, and every result before
`finish` is sent. A `finish` that fails transiently is retried on each pass,
before any new poll, until the daemon has it or refuses it for good; a
refusal of a retry whose first copy did arrive (the job status already shows
that result) counts as delivered. If the daemon no longer knows the job (it
restarted), an `applied` or `apply_failed` result is sent again as
`outcome_unknown`, which the daemon records for a job it forgot, so the
ledger still has a line for it. A transient failure fetching an archive,
or sending a refusal, is retried for up to 60 s; an archive still out of
reach ends the job `plan_failed` with category `archive_unavailable`. If the
daemon never hears back about a claimed job, it records the outcome as
unknown after its `claim_ttl` (default 3 h). Keep `terraform_timeout_minutes`
well under the daemon's `claim_ttl` (default 180 minutes): the daemon has no
way to tell a long apply from a lost runner, and an apply still running when
the claim lapses is recorded as an unknown outcome. The executor writes the
apply's result into the journal as `reporting` the moment Terraform returns,
so a crash before `finish` is sent is re-sent at the next start.

- **Trust.** The baseline is the daemon's trusted record, which must match
  the local `trusted.json` and `trusted/` tree (otherwise the job is refused
  `baseline_mismatch`; `shoephoned untrust` clears it). The archive is
  unpacked into `state_dir/jobs/<id>/candidate`, the baseline's execution
  input is copied beside it, the directory is handed to `review_user`, and
  `review-worker` runs as that user with no credentials and an environment
  of only `PATH`. The root process then unpacks the archive itself and
  repeats the review against `trusted/`; unless the candidate, diff and
  schema digests, the three counts and `schema_changed` all equal the
  worker's, and the worker's diff text hashes to that digest, the job is
  refused `review_inconsistent`. The worker's diff text and warnings are
  what the approver is shown. On approval root unpacks and reviews the
  archive once more, against the trusted tree as it is then, installs only
  the execution input as `trusted/` (leaving `install.json` and the previous
  tree as `trusted.prev/` until the daemon has the result), writes
  `trusted.json`, and reports `trusted`; if the daemon refuses it, the
  previous trust is put back. A `trusted` result the daemon already holds
  (its reply was lost, or the daemon restarted after recording it, so its
  trust record names this job) is accepted again with no new ledger line,
  and the runner keeps the trust.

  This is a deliberate deviation from the design, which has the root
  process never parse repository content: root parses the tar archive, the
  HCL that names local modules, and the text diff. Without that, a
  compromised review worker could forge the diff the operator approves.
  The parsers are memory-safe Rust with the same size, file-count and time
  limits as the worker's unpack.
- **Apply.** Refused `no_trusted_revision` unless the daemon's record, the
  local `trusted.json` and a fresh digest of `trusted/` agree, and the
  schema file still hashes to the recorded schema digest. The manifest is
  validated against that schema; Terraform gets only its canonical text.
  The execution input is copied from `trusted/` into
  `state_dir/jobs/<id>/checkout`, handed to `terraform_user`, and planned.
  A plan that deletes or replaces anything without `--allow-destroy` is
  refused `destroy_not_requested` with those addresses. Otherwise the
  scope (counts, destructive flag and address text from one plan summary)
  and the display (canonical manifest, the `applied.json` baseline, the
  address text) are submitted. The daemon refuses the job `untrusted` at
  submit, approval or claim when the scope's revision and schema are not
  what the project is trusted at then, so a `shoephoned untrust` stops an
  apply that has not started. On approval the job is claimed, the local
  trusted tree is checked again against the approved revision and schema
  (`apply_failed` with category `untrusted` otherwise) and the pinned
  context is recomputed; a change fails the job `apply_failed` with
  category `context_changed` before anything runs. The scope the claim
  returns must equal the one submitted, field for field (`scope_mismatch`
  otherwise). `applied.json` is
  marked `uncertain` (keeping the last applied manifest) before Terraform
  starts and set to `applied` with the new manifest only on success. A
  `terraform_timeout` or a Terraform killed by a signal
  (`terraform_crashed`) is reported `outcome_unknown`; any other failure
  `apply_failed`.

A job's directory and root-only plan copy are removed when it ends, however
it ends: applied, failed, refused, declined, timed out or killed (noticed
when the daemon's job status says it is over). An approval the runner has
no plan for (it restarted after submitting) is claimed and failed with
`plan_lost`, so nothing is applied from it.

`state_dir/jobs` is created 0711 so each worker user can reach its own 0700
job directory; `state_dir` itself must therefore be traversable (0711 or
0755) by `review_user` and `terraform_user`.

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
- `trusted.json`: `{ digest, schema, modes }`, `modes` holding the archive
  header mode of each file of the trusted tree, which the digest covers.
- `applied.json`: `{ manifest, status }`, status `applied` or `uncertain`.
- `journal.json`: `{ job, phase, result, kind, failure }`, phase `claimed`
  (written before the claim is sent; `kind` is `trust` or `apply`),
  `applying` (Terraform apply started), `reporting` (the `result` and
  `failure` to send in `finish`, not yet acknowledged) or `done`.
- `install.json`, `trusted.prev/`, `trusted.prev.json`: present only while a
  newly installed trust waits for the daemon to record it.
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
- 3: config missing or invalid, an unreadable runner key or apply journal,
  a bad `review-worker` request, or a `test-hooks` build started without the
  test variable.
- 30: a review or `diff-digest` was refused.
