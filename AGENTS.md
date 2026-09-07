<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# shoephone

Phone-approved, short-lived SSH certificates for coding agents. The name is
from Get Smart: the approver is literally a phone, the agency is CONTROL, and
the Chief says yes or no.

## What this is

A two-tier access model for an agent that operates machines:

- **Safe tier:** a promptless, read-only account per host, constrained by the
  host (sudoers), not by the client. Not this repo's code; this repo only
  assumes it exists.
- **Dangerous tier:** a local admin account reachable **only** by an SSH
  certificate from a CA this daemon holds. The agent requests one, a person
  approves it from their phone by signing the enforced scope plus a
  single-use nonce, and the daemon signs a short certificate bound to that
  host, that key, and a phone-approved window.

Three pieces live here:

| Piece | What it is |
|---|---|
| `shoephoned` | The grant daemon. Holds the SSH user CA, enforces the window, the per-host principal, the rate cap and the nonce. Runs on a host the agent cannot reach. |
| `shoephone` | The grant CLI an agent session runs. Requests, waits, loads key + cert into the session ssh-agent, prints the match code. |
| the approve page | What the person sees. A web page over a private network first; a native app, or a hardware security key on that page, later. |

## Conventions

- **Rust**, edition 2024, `cargo fmt` and `cargo clippy -- -D warnings` clean.
  Follow the official Rust style guide and API guidelines.
- **Apache 2.0**, SPDX two-line header on every source file, including
  Markdown instruction files. In a file with YAML frontmatter the header goes
  after the frontmatter.
- **CLI contract:** exit codes follow the bands in `src/exit.rs` (under 100
  portable, 100-124 this tool's own). `--skill` prints `SKILL.md`, compiled
  in with `include_str!` so it cannot drift from the binary. `--json` is a
  single document on stdout, diagnostics on stderr. Never prompt when stdin
  is not a TTY.
- **Tool-specific exit codes (100-124):** none yet. Record each one here as
  it is invented so the next session extends the list instead of renumbering.
- **Generic by construction.** No real hostnames, vault names, addresses, or
  secrets in this repo, ever. The estate-specific deployment lives in the
  operator's private infrastructure repo, which points here.
- **American spellings** throughout.

## Security invariants (do not relax these in code)

- The daemon treats every byte from the CLI as untrusted. The scope shown to
  the approver is the daemon's enforced scope, never the request's prose.
- The approver's signature covers the enforced scope **and** the nonce. A
  signature over the nonce alone is rejected.
- No certificate outlives the approved window. Renewals inside the window go
  only to the public key that was approved.
- The rate cap is global per CA and per approver, never keyed on anything the
  requester chooses. A decline costs a cooldown.
- The daemon never holds a credential to any host it signs for. Revocation is
  a kill switch that closes the window, bounded by one certificate TTL.
- Every issuance, renewal, decline, and kill is reported to the approver's
  device. The daemon's own logs are not the audit trail.

## Verification

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

CI runs the same steps, then runs the binary with stdout piped, stdin closed
and `NO_COLOR=1`, asserting on exit codes, because those four conditions are
an agent's environment.
