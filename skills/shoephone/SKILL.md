---
name: shoephone
description: Explains the shoephone system — phone-approved, short-lived SSH certificates for coding agents — and how to drive all three sides of it: requesting a window from an agent session, deploying and enrolling as the operator, and working on this repository. Use when asked how shoephone works, when an agent session needs admin on a host beyond its read-only tier, when deploying or enrolling shoephoned, or when a request, enrollment, approval or certificate is failing and the cause is not obvious.
---
<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# shoephone

Phone-approved, short-lived SSH certificates for coding agents. An agent asks
for admin on one host; a person approves it from their phone; a daemon signs a
certificate valid only on that host, only for the key that asked, and only
until a window the person saw closes.

The name is from Get Smart: the approver is a phone, the agency is CONTROL.

## Why it exists

An agent that operates machines needs two kinds of access, and merging them
ruins both:

- **Safe tier** — reading logs, status, disk, containers. Promptless, or every
  prompt becomes noise and gets rubber-stamped. A read-only Unix account per
  host, constrained by sudoers. **Not this repo's code**; shoephone assumes it
  exists.
- **Dangerous tier** — admin. One meaningful ceremony per session, performable
  from anywhere, on a device the agent cannot touch. That is shoephone.

Two things the ceremony has to beat: *approval fatigue* (a prompt for every
command carries no signal) and *location-bound approval* (a tap on the desk's
key agent is impossible when the operator is driving the session from a phone).

## The pieces

| Piece | Where it runs | What it holds |
|---|---|---|
| `shoephoned` | the failsafe host — a small machine outside the hypervisor's failure domain, with **no agent account of any tier** | the SSH user CA, the enrolled approver devices, the window/nonce/rate state, the ledger |
| `shoephone` | the agent's own machine | one ed25519 session key per host, and the certificates issued against it |
| the approver | the operator's phone — the [shoephone-app](https://github.com/curtisgalloway/shoephone-app) iOS app, key in the Secure Enclave behind Face ID | the only credential that can open a window |
| the approve page | served by the daemon, for a hardware security key instead of the app | nothing |
| sshd | every host in `[principals]` | the CA public key and one principal |

The design, including the three perimeters that must be closed *before* any of
this is worth deploying, is in `docs/DESIGN.md`. The estate-specific deployment
(real hostnames, accounts, tuned sudoers) lives in the operator's private
infrastructure repo — **never in this repo**, which is generic by construction.

## How one grant works

1. The session runs `shoephone request <host> --reason "..."`. The CLI sends
   the host, the reason, the session public key, and a link back to the
   session; it prints a **match code** and waits.
2. The daemon rate-checks the request, mints a single-use nonce, and sends a
   **content-free** push (ntfy topic and/or APNs). The push carries no detail;
   the phone fetches what is pending when opened.
3. The phone shows the daemon's **enforced scope** — host, principal, window —
   plus the match code, the requesting hostname, the key fingerprint, and the
   agent's reason. The reason, the requesting machine's name and the session
   link are agent-authored, untrusted, and shown as prose; the scope beside
   them is the daemon's own and is what gets signed.
4. The operator compares the match code with the terminal in front of them and
   approves. The device signs *the enforced scope plus the nonce*.
5. The daemon verifies the signature, opens the window (default 60 minutes),
   and signs a short certificate (default 15 minutes) carrying exactly one
   principal — `<account>:<host>` — the grant's serial, key id
   `shoephone:<host>:<serial>`, and only `permit-pty`.
6. The CLI writes the certificate beside that host's session key and `ssh-add -t`s
   both for the certificate's remaining life. `ssh <account>@<host>` works.
7. `shoephone renew <host>` gets the next certificate silently inside the
   window — no second tap, same key only. `disavow` closes the window early.

Decline or timeout issues nothing, and costs the requester a cooldown.

## The rules that make it worth anything

Do not relax these in code; each one closes a hole a review found.

- **The approver signs the scope, not just the nonce.** A channel that lies
  about scope produces a signature the daemon rejects. A captured approval
  cannot be replayed onto another request.
- **The phone signs a window; the daemon signs certificates inside it.** No
  certificate outlives the window, and every certificate in the window goes to
  the public key that was approved. A new window is a new approval.
- **One principal per host.** `AuthorizedKeysFile none` plus a per-host
  principal means the host shown on the phone is the host the grant unlocks,
  and no static key can drift in beside the certificate.
- **No synced credentials.** The daemon refuses any credential the
  authenticator reports backup-eligible — every iCloud/1Password passkey —
  because a synced credential also exists on the machine the agent runs on.
  (`allow_synced_credentials = true` is a stopgap; the daemon names every such
  device at startup.)
- **Caps are server-side and never keyed on anything the requester chooses.**
  6 accepted requests per rolling hour per approver; one pending request at a
  time; a decline costs 5 minutes, doubling per strike to 60.

Two more worth knowing: the daemon **never holds a credential to any host it
signs for**, and the kill switch closes a window rather than revoking a
certificate — it bounds the next login, not a session already open (that is a
host-side limit).

## Using it from an agent session

```bash
export SHOEPHONE_DAEMON=https://approve.example.internal   # or ~/.config/shoephone/config.toml
shoephone doctor                # what is missing, before guessing
shoephone request web01 --reason "rotate the TLS cert; needs a service restart"
ssh agent-admin@web01 sudo systemctl restart something
shoephone renew web01           # next certificate, inside the window, no tap
shoephone disavow web01         # close the window early
```

`shoephone --skill` prints the CLI's own contract — every verb, flag, the JSON
shapes, and the full exit-code table — compiled into the binary from the repo
root `SKILL.md`, so it cannot drift. Read that before parsing output.

Five behaviors that trip agents, in the order they bite:

1. **`--reason` is for a person.** One or two sentences: the task, why it needs
   admin on that host, roughly what you will run. A request with no reason is
   refused before anyone is asked.
2. **Exit 12 is a verdict, not a failure.** Declined or timed out. Do not
   retry; the person saw it and chose. Exit 11 means no window exists yet,
   exit 23 means cooldown or hourly cap, exit 20 means another request is
   pending, exit 22 means the outcome is unknown — check `status` first.
3. **One host per request.** A window is bound to one host and one key.
4. **Never paraphrase the match code.** Print it for the person to compare; it
   is not an input, not a secret, and it is the one control a prompt-injected
   agent cannot influence from the inside.
5. **`agent = false`** in `~/.config/shoephone/config.toml` when the machine's
   ssh-agent refuses foreign keys (the 1Password agent does). The certificate
   then sits beside the session key and ssh finds it through a `Match user`
   stanza — see the troubleshooting table.

## Operating the daemon

```bash
cargo build --release                 # never --features test-hooks for a deployed daemon
install -m 0755 target/release/shoephoned /usr/local/bin/
install -d -m 0700 /etc/shoephone
install -m 0600 shoephoned.toml /etc/shoephone/shoephoned.toml   # the default path
shoephoned init-ca > user_ca.pub      # 0600, refuses to overwrite
systemctl enable --now shoephoned     # unit in contrib/systemd/
```

`shoephoned [--config <file>] (serve | init-ca | enroll --name <device> |
devices | forget (--name <device> | --id <handle>))`.

Config (`/etc/shoephone/shoephoned.toml`, root-only — it holds push tokens):
`listen` (loopback; TLS comes from a reverse proxy), `state_dir`, `ca_key`,
`rp_id` + `rp_origin` (**exactly** what the phone loads, over https),
`[principals]` mapping host to `account:host`, and optional `[policy]`,
`[notify]` (ntfy), `[apns]` (direct APNs with an ES256 token), `[access]`
(a Cloudflare Access service token, carried to the app in the enrollment QR).

Four invariants and one clock:

- CA key and state dir are root-only; the config too.
- The daemon speaks plain HTTP on loopback; a reverse proxy terminates TLS.
  WebAuthn refuses anything else.
- `rp_origin`/`rp_id` mismatch fails **every** enrollment and approval.
- A restart fails closed: enrolled devices survive, open windows and pending
  requests do not.
- The daemon and every host it signs for must keep clocks synced. Certificates
  carry absolute times: a slow host honors a certificate past the approved
  window, a fast one rejects it early.

**Enrollment is human-only**, at the host's console, never over a session an
agent could see:

```bash
shoephoned enroll --name phone    # one-time code, 10 minutes or 5 wrong guesses
shoephoned devices                # names, age, and whether push is registered
shoephoned forget --id <handle>   # by handle; a name identifies nobody
```

It prints a QR (`shoephone://enroll?daemon=<rp_origin>&code=<code>`) on stderr
and the bare code on stdout. Scan it in the app and pass Face ID; the app is
its own WebAuthn client and needs no browser. A hardware key instead: open
`rp_origin` in a browser, enter the code, tap. An iPhone passkey made in Safari
will never work — iOS only makes synced ones.

Each host then trusts the CA, scoped to the one account:

```
Match User agent-admin
    TrustedUserCAKeys /etc/ssh/shoephone_user_ca.pub
    AuthorizedPrincipalsFile /etc/ssh/principals/%u
    AuthorizedKeysFile none
```

with `/etc/ssh/principals/agent-admin` containing exactly that host's principal.

## When something fails

| Symptom | Cause | Fix |
|---|---|---|
| exit 10, "agent refused operation" on every request | the machine's ssh-agent refuses keys it did not create (1Password) | `agent = false`, then a `Match user <account>` stanza with `IdentityFile ~/.local/state/shoephone/hosts/<host>/session_ed25519`, `IdentitiesOnly yes`, `IdentityAgent none` — one `IdentityFile` line per host, kept short or sshd hits `MaxAuthTries` |
| every enrollment and approval fails | `rp_origin`/`rp_id` is not what the phone actually loads | make them the exact https origin and its hostname |
| the credential is refused at enrollment | it is a synced passkey | use the app or a hardware key; `allow_synced_credentials` only as a stopgap |
| no push arrives | device enrolled before its push secret existed, or `[apns]`/`[notify]` absent | `shoephoned devices` says "push token but no secret: re-enroll"; do that at the console |
| sshd refuses the certificate | wrong principal file, missing `Match User` block, or clock skew | compare `ssh-keygen -L -f <cert>` against `/etc/ssh/principals/<account>` |
| exit 11 right after a daemon restart | windows live in memory and fail closed | request again |
| exit 22 | the daemon may have acted; outcome unknown | `shoephone status` before retrying |

## Working on this repo

| File | What it owns |
|---|---|
| `src/grant.rs` | the state machine: windows, nonces, rate cap, cooldown, kill. Policy defaults live here |
| `src/ca.rs` | certificate signing with the `ssh-key` crate; no `ssh-keygen` subprocess |
| `src/server.rs` | axum surface, approve page, WebAuthn enroll and approve, ledger |
| `src/api.rs`, `src/client.rs` | the wire types, and the CLI's blocking view of them |
| `src/session.rs`, `src/store.rs` | per-host session keys; devices, enroll codes, ledger on disk |
| `src/notify.rs` | content-free push: ntfy topic and APNs |
| `src/exit.rs` | the exit-code vocabulary, and `include_str!` of the root `SKILL.md` |

Routes: `/api/{status,request,request/{id},issue,kill,pending,decline,ledger}`,
`/api/approve/{start,finish}`, `/api/enroll/{start,finish}`,
`/api/push/register`. The agent-side endpoints take no credential on purpose —
everything that *opens* a window needs the approver's key.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Three repo rules that are easy to break: **generic by construction** (no real
hostnames, vaults or addresses, ever — that is what the private infra repo is
for), **SPDX two-line header on every file** including Markdown (after the
frontmatter), and **`--features test-hooks` adds `POST /api/test/approve`** for
the test suite only — a deployed daemon built with it can self-approve.

`AGENTS.md` records the settled decisions and the security invariants; change
them there first, then in the code.

## What this deliberately does not do

It does not make the agent's machine trustworthy — it assumes compromise to the
extent of the agent's own privileges and asks only that it not extend further.
It does not end an ssh session that is already open. It does not protect a
target whose privileged credential sits in a vault the agent's unattended token
can read, or an infrastructure repo whose apply step the agent can reach: those
are Perimeters 1 and 2 in `docs/DESIGN.md`, and skipping them makes everything
here decorative.
