<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# shoephone

Phone-approved, short-lived SSH certificates for coding agents. The name is
from Get Smart: the approver is a phone, the agency is CONTROL, and the Chief
says yes or no.

## What this is

A two-tier access model for an agent that operates machines:

- **Safe tier:** a promptless, read-only account on each host, limited by
  sudoers on the host rather than by the client. Not in this repo; shoephone
  assumes it exists.
- **Dangerous tier:** an admin account reachable **only** with an SSH
  certificate from this daemon's CA. The agent requests one; a person approves
  on their phone by signing the enforced scope plus a single-use nonce; the
  daemon signs a short certificate bound to that host, that key, and the
  approved window.

| Piece | What it is |
|---|---|
| `shoephoned` | The daemon. Holds the SSH user CA and enforces the window, the per-host principal, the rate cap and the nonce. Runs on a host the agent cannot reach. |
| `shoephone` | The CLI an agent session runs. Requests, prints the match code, waits, and loads key and certificate into ssh-agent. |
| the approver | The iOS app in `shoephone-app`, or a hardware security key on the daemon's web approve page. Both speak WebAuthn. |

## Conventions

- **Rust**, edition 2024, clean under `cargo fmt` and
  `cargo clippy -- -D warnings`. Follow the official Rust style guide and API
  guidelines.
- **Apache 2.0.** Two-line SPDX header on every file, Markdown included. In a
  file with YAML frontmatter, the header goes after the frontmatter.
- **CLI contract.** Exit codes follow the bands in `src/exit.rs`: under 100 is
  portable, 100-124 belongs to this tool. `--skill` prints the root
  `SKILL.md`, compiled in with `include_str!` so it cannot drift. `--json` is
  one document on stdout; diagnostics go to stderr. Never prompt when stdin
  is not a TTY.
- **Tool-specific exit codes (100-124):** none yet. Every outcome fits the
  portable bands (see `SKILL.md`). Record any new code here so the next
  session extends the list instead of renumbering.
- **Generic by construction.** No real hostnames, vault names, addresses or
  secrets in this repo, ever. The estate-specific deployment lives in the
  operator's private infrastructure repo.
- **American spellings.**

## Decisions

Settled with the operator on 2026-09-06, before the first line of daemon
code, and amended since. Change a decision here first, then in the code.

| Question | Decision |
|---|---|
| Approver binding | WebAuthn through `webauthn-rs` (scored 6.4, MPL-2.0, pulls in the `openssl` crate). The library picks its own random challenge, so the daemon binds it server-side: starting a ceremony snapshots the pending request's id, nonce and enforced scope, and only that snapshot reaches `Grants::approve` after the assertion verifies. First authenticator: a hardware security key on the web page. The iOS app is a second one, needing no daemon changes. No synced passkeys. |
| Windows and certificates | 60 min default window, 4 h maximum, 15 min certificates, 5 min pending timeout. Defaults live in `grant::Policy`. |
| Certificate signing | The `ssh-key` crate (default features off; ed25519, std, getrandom). CA key unencrypted in a root-only file. No `ssh-keygen` subprocess. A certificate carries one principal, the grant's serial, key id `shoephone:<host>:<serial>`, and only the `permit-pty` extension. |
| Rate cap | One pending request at a time. 6 accepted requests per rolling hour, counted per approver across every requester. |
| Decline cooldown | 5 min, doubling per consecutive strike, capped at 60 min. A timeout counts as a decline. Only an approval resets the strikes. See `Grants::cooldown_after`. |
| HTTP stack | axum on tokio, plain HTTP on a loopback or private address. A reverse proxy provides TLS. `rp_origin` must be exactly what the phone loads, over https. |
| Persistence | Enrolled devices on disk, root-only. Windows, nonces and counters in memory, so a restart fails closed. |
| Notifications | Content-free push for three events: a request is waiting, a window opened, a window was killed. Declines, timeouts and issues stay silent. Two channels: an ntfy-style topic (`[notify]`) and APNs straight to the app (`[apns]`). Never retried. Each device receives only the kinds it registered for. By default that includes opened windows, so an approval on one device is visible on the others. |
| Ledger | An append-only file on the daemon, which the app and the web page show as history. |
| CLI HTTP client | `ureq` with rustls and the platform verifier, so a private CA in the machine's trust store works. Blocking; the CLI has no async. |
| Session keys | One ed25519 keypair per host, unencrypted, mode 0600, in `$XDG_STATE_HOME/shoephone/hosts/<host>/` (default `~/.local/state/shoephone`). The certificate lands beside it as `-cert.pub`; both go into ssh-agent with `ssh-add -t` for the certificate's remaining life. |
| Test hook | The Cargo feature `test-hooks` adds `POST /api/test/approve`. Only the crate's dev-dependency on itself turns it on. A deployed build must not have it. |
| Unauthenticated agent-side endpoints | `request`, poll, `issue`, `kill` and `decline` take no credential. Requests are rate-capped; a certificate only ever goes to the approved public key, which is public anyway; a stranger's kill or decline fails closed and costs the requester a cooldown. Everything that opens a window needs the approver's key. Reaffirmed after the 2026-09-06 outside review: gating decline on the key would make the cheap answer expensive, and would protect only the requester from itself. |
| Kill also declines | `kill <host>` closes every window for the host and declines any request still pending for it, with the usual cooldown, so a tap a moment later cannot reopen what was just closed. From the 2026-09-06 review. |
| Two windows per host | Allowed: a second request for a host with an open window is a new approval. `issue` selects on host and key together, so each approved key gets its own window's certificate. |
| Enrollment | `shoephoned enroll --name <device>`, at the console, stores the SHA-256 of a one-time code in the root-only state dir and prints the code and a QR. The app or the web page consumes it within 10 minutes or 5 wrong guesses. The agent never sees the code. A name already enrolled is refused; `forget` works by handle, because a name identifies nobody. |
| Build status | Grant state machine, CA signing, HTTP surface with WebAuthn and ledger, the five CLI verbs, and both push channels are done and tested. Deployment lives in the operator's infrastructure repo. |

## Security invariants

Do not relax these in code.

- The daemon treats every byte from the CLI as untrusted. The approver sees
  the daemon's enforced scope, never the request's prose.
- The approver's signature covers the enforced scope **and** the nonce. A
  signature over the nonce alone is rejected.
- No certificate outlives the approved window. Renewals inside the window go
  only to the public key that was approved.
- The rate cap is per CA and per approver, never keyed on anything the
  requester chooses. A decline costs a cooldown.
- The daemon never holds a credential to any host it signs for. Revocation is
  a kill switch that closes the window, so no new login works after one
  certificate lifetime. It does not end a session already open; that is a
  host-side limit.
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
and `NO_COLOR=1`, and asserts on exit codes. Those four conditions are an
agent's environment.
