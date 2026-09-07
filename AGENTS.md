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
- **Tool-specific exit codes (100-124):** none. Every outcome so far fits
  the portable bands; see `SKILL.md` for the mapping. Record any new one
  here so the next session extends the list instead of renumbering.
- **Generic by construction.** No real hostnames, vault names, addresses, or
  secrets in this repo, ever. The estate-specific deployment lives in the
  operator's private infrastructure repo, which points here.
- **American spellings** throughout.

## Decisions (2026-09-06)

Settled with the operator before the first line of daemon code. Change them
here first, then in the code.

| Question | Decision |
|---|---|
| Approver binding, first ceremony | WebAuthn with a hardware security key on the web page, via `webauthn-rs` (scored 6.4, MPL-2.0, brings the `openssl` crate). The library generates its own random challenge, so the daemon binds it server-side: when the ceremony starts it snapshots the pending request's id, nonce and enforced scope, and only that snapshot reaches `Grants::approve` after the assertion verifies. `Scope::bytes_to_sign` stays for a future app that signs bytes it displayed. No synced passkeys. |
| Windows and certificates | 60 min default window, 4 h maximum, 15 min certificates, 5 min pending timeout. Defaults live in `grant::Policy`. |
| Certificate signing | The `ssh-key` crate (default features off; ed25519, std, getrandom), CA key unencrypted in a root-only file. No `ssh-keygen` subprocess. Certificates carry one principal, the grant's serial, key id `shoephone:<host>:<serial>`, and only the `permit-pty` extension. |
| Rate cap | One pending request at a time; 6 accepted requests per rolling hour, keyed per approver across every requester. |
| Decline cooldown | 5 min base, doubling per consecutive strike, capped at 60 min. A timeout counts like a decline. Strikes reset only on approval. Rule lives in `Grants::cooldown_after`. |
| HTTP stack | axum on tokio, plain HTTP on a loopback or private address. TLS comes from a reverse proxy in front; `rp_origin` must be what the phone actually loads, over https. |
| Persistence | Enrolled approver devices on disk, root-only. Windows, nonces and counters in memory; a restart fails closed. |
| Notifications and ledger | Content-free push to an ntfy-style topic the operator runs (`[notify]` in the config: url, optional bearer token, optional click URL), sent only for a new request, never retried; the page fetches details from the daemon. Ledger is an append-only file on the daemon plus the page's history view until an app exists. |
| Build order inside this repo | 1. `grant` state machine with tests (done). 2. `ca` signing (done, verified with `ssh-keygen -L`). 3. axum surface, approve page, WebAuthn enroll and approve, ledger file (done; the key tap itself is untested until a phone reaches a deployed daemon). 4. CLI verbs `request`, `renew`, `disavow`, `status`, `doctor` (done, exercised end to end against a live daemon and ssh-agent). 5. Content-free push (done; fixed body and headers, verified against a fake receiver that the host never appears). Next is deployment, which lives in the operator's infrastructure repo. |
| CLI HTTP client | `ureq` with rustls and the platform verifier, so a private CA in the machine's trust store works. Blocking; the CLI has no async. |
| Session key | One ed25519 keypair per user, unencrypted, mode 0600, in `$XDG_STATE_HOME/shoephone` (default `~/.local/state/shoephone`). Certificates land beside it as `-cert.pub` and both go into ssh-agent via `ssh-add -t` for the certificate's remaining life. |
| Test hook | Cargo feature `test-hooks` adds `POST /api/test/approve`, enabled only through the dev-dependency on the crate itself. A deployed build must be built without it. |
| Agent-side endpoints are unauthenticated | `request`, poll, `issue`, `kill` and `decline` take no credential. Requests are rate-capped; a certificate is only ever issued to the approved public key, which is public anyway; a stranger's kill or decline fails closed and costs the requester a cooldown. Everything that opens a window needs the security key. Reaffirmed after the 2026-09-06 outside review: gating decline on the key would make the cheap verdict expensive, and the only thing it protects is the requester from itself. |
| Kill also declines | `kill <host>` closes every window for the host and declines a request still pending for it, with the usual cooldown, so a tap a moment later cannot reopen what was just closed. Found by the 2026-09-06 review. |
| Two windows per host | A second request for a host with an open window is allowed (a new window is a new approval). `issue` selects on host and key together, so each approved key gets its own window's certificate. |
| Enrollment channel | `shoephoned enroll --name <device>` at the console writes the SHA-256 of a one-time code into the root-only state dir; the page's enroll form consumes it within 10 minutes or 5 wrong guesses. The agent never sees the code. |

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
