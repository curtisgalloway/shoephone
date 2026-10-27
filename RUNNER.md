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
  step, started by `run`.
- `shoephone-runner --skill`: print this document. `--version` prints the
  version.

`--config` defaults to `/etc/shoephone-runner/shoephone-runner.toml`. An
example with placeholder values is `contrib/runner/shoephone-runner.toml.example`.

`run` and `review-worker` are not implemented yet; they exit 3.

## Config

One TOML file, unknown fields refused. Top level: `name`, `daemon`, `key`,
`state_dir`, `log_dir`, `log_days` (default 30), `terraform`, `plugin_dir`,
`bwrap`, `review_user`, `terraform_user`, `secret_command`. Each
`[projects.<name>]` has `path`, `terraform_version`, `schema_file` (default
`shoephone-schema.toml`) and the tables `backend_config`, `env` and
`variables`. Project names match `^[A-Za-z0-9._-]{1,64}$`; paths are
relative with no `..`.

Every value in those tables is `{ value = "..." }` or `{ secret = "ref" }`.
`secret_command` is run with the reference appended as its last argument; its
stdout, trimmed, is the secret. Runner-supplied `variables` must not overlap
the project's schema; that is checked when the project is trusted.

## State

Under `state_dir/projects/<name>/`:

- `trusted/`: the unpacked trusted tree.
- `trusted.json`: `{ digest, schema }`.
- `applied.json`: `{ manifest, status }`, status `applied` or `uncertain`.
- `journal.json`: `{ job, phase, result }`, phase `claimed`, `applying` or
  `done`.

Every write is atomic: a 0600 temp file, fsync, rename, fsync of the
directory.

## Exit codes

Bands follow the house contract: under 100 is portable.

- 0: success.
- 2: usage error.
- 3: config missing or invalid, or the verb is not implemented yet.
