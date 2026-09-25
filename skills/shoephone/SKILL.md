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
for admin on one host, a person approves on their phone, and a daemon signs a
certificate that works only on that host, only for the key that asked, and
only until the approved time runs out.

The name is from Get Smart: the approver is a phone, the agency is CONTROL.

## Why it exists

An agent needs two kinds of access. The **safe tier** reads logs, status and
disk with no prompts, through a read-only account on each host limited by
sudoers (**not in this repo**; shoephone assumes it). The **dangerous tier**
is admin, and costs one deliberate approval per session on a device the
agent cannot touch. That is shoephone.

## The pieces

| Piece | Runs on | Holds |
|---|---|---|
| `shoephoned` | the failsafe host: a small machine outside the hypervisor's failure domain, with **no agent account of any tier** | the SSH user CA, enrolled approver devices, window/nonce/rate state, the ledger |
| `shoephone` | the agent's machine | one ed25519 session key per host, and the certificates issued to it |
| the approver | the operator's phone: the [shoephone-app](https://github.com/curtisgalloway/shoephone-app) iOS app, key in the Secure Enclave behind Face ID | the only credential that can open a window |
| the approve page | served by the daemon, for a hardware security key instead of the app | nothing |
| sshd | every host in `[principals]` | the CA public key and one principal |

`docs/DESIGN.md` has the full design, including the three perimeters to close
*before* deploying. The estate's real deployment (hostnames, accounts, tuned
sudoers) lives in the operator's private infrastructure repo, **never here**.

## How one grant works

1. The session runs `shoephone request <host> --reason "..."`. The CLI sends
   the host, the reason, its public key for that host, and a link back to the
   session. It prints a **match code** and waits.
2. The daemon checks the rate limits, mints a single-use nonce, and sends a
   **content-free** push (ntfy and/or APNs). The phone fetches the details
   when opened.
3. The phone shows the daemon's **enforced scope** (host, principal, window)
   with the match code, the requesting hostname, the key fingerprint and the
   agent's reason. The reason, hostname and session link come from the agent
   and are untrusted. The scope is the daemon's, and it is what gets signed.
4. The operator checks the match code against the terminal and approves. The
   device signs *the enforced scope plus the nonce*.
5. The daemon verifies the signature, opens the window (default 60 minutes),
   and signs a certificate (default 15 minutes) with exactly one principal,
   `<account>:<host>`, key id `shoephone:<host>:<serial>`, and only
   `permit-pty`.
6. The CLI writes the certificate beside the host's session key and loads
   both with `ssh-add -t`. `ssh <account>@<host>` works.
7. `shoephone renew <host>` gets the next certificate inside the window
   without a second approval, for the same key only. `disavow` closes the
   window early.

A decline or timeout issues nothing and costs the requester a cooldown.

## The rules that make it worth anything

Do not relax these in code. Each closes a hole a review found.

- **The approver signs the scope, not just the nonce.** A channel that lies
  about scope produces a signature the daemon rejects, and an approval cannot
  be replayed onto another request.
- **The phone signs a window; the daemon signs certificates inside it.** No
  certificate outlives the window, and all of them go to the approved key. A
  new window needs a new approval.
- **One principal per host.** With `AuthorizedKeysFile none` and a per-host
  principal, the host on the phone is the host the approval unlocks, and no
  static key can be added beside the certificate.
- **No synced credentials.** The daemon refuses any credential the
  authenticator reports as backup-eligible (every iCloud or 1Password
  passkey), because a synced credential also exists on the agent's machine.
  `allow_synced_credentials = true` is a stopgap; the daemon lists every such
  device at startup.
- **Limits are enforced by the server and never keyed on anything the
  requester chooses.** 6 accepted requests per rolling hour per approver; one
  pending request at a time; a decline costs 5 minutes, doubling per repeat
  up to 60.

Also: the daemon **never holds a credential to any host it signs for**, and
the kill switch closes a window rather than revoking a certificate. It stops
the next login, not a session already open; that is a host-side limit.

## Using it from an agent session

```bash
export SHOEPHONE_DAEMON=https://approve.example.internal   # or ~/.config/shoephone/config.toml
shoephone doctor                # checks everything a request needs
shoephone request web01 --reason "rotate the TLS cert; needs a service restart"
ssh agent-admin@web01 sudo systemctl restart something
shoephone renew web01           # next certificate inside the window, no approval
shoephone disavow web01         # close the window early
```

`shoephone --skill` prints the CLI's own contract: every command and flag,
the JSON shapes, and the full exit-code table. It is compiled into the binary
from the repo root's `SKILL.md`, so it matches the build. Read it before
parsing output.

Five things that trip agents, in the order they come up:

1. **`--reason` is for a person.** One or two sentences: the task, why it
   needs admin on that host, roughly what you will run. A request without one
   is refused before anyone is asked.
2. **Exit 12 is a verdict, not a failure.** Declined or timed out; do not
   retry. Exit 11: no window yet. Exit 23: cooldown or hourly cap. Exit 20:
   another request is pending. Exit 22: outcome unknown, so run `status`
   first.
3. **One host per request.** A window covers one host and one key.
4. **Never paraphrase the match code.** Show it for the person to compare. It
   is not an input or a secret, and it is the one control a prompt-injected
   agent cannot influence from the inside.
5. **`agent = false`** in `~/.config/shoephone/config.toml` when the
   machine's ssh-agent refuses foreign keys (the 1Password agent does). The
   certificate then stays beside the session key and ssh finds it through a
   `Match user` stanza; see the troubleshooting table.

## Operating the daemon

```bash
cargo build --release                 # never --features test-hooks for a deployed daemon
install -m 0755 target/release/shoephoned /usr/local/bin/
install -d -m 0700 /etc/shoephone
install -m 0600 shoephoned.toml /etc/shoephone/shoephoned.toml   # the default path
shoephoned init-ca > user_ca.pub      # key at 0600; refuses to overwrite
systemctl enable --now shoephoned     # unit in contrib/systemd/
```

Usage: `shoephoned [--config <file>] (serve | init-ca | enroll --name
<device> | devices | forget (--name <device> | --id <handle>))`.

The config, `/etc/shoephone/shoephoned.toml`, is root-only because it holds
push tokens. Keys: `listen`, `state_dir`, `ca_key`, `rp_id`, `rp_origin`,
`[principals]` (host to `account:host`), and optional `[policy]`,
`[notify]` (ntfy), `[apns]` and `[access]` (a Cloudflare Access token the
enrollment QR carries to the app). The README documents each.

What must hold:

- The CA key, state dir and config are root-only.
- The daemon speaks plain HTTP on loopback; a reverse proxy adds the TLS
  WebAuthn requires.
- `rp_origin` and `rp_id` are **exactly** the https origin the phone loads
  and its hostname, or every enrollment and approval fails.
- A restart keeps enrolled devices and drops windows and pending requests.
- Clocks are synced everywhere. A host running slow honors a certificate past
  the approved window.

**Enrollment is human-only**, at the host's console, never in a session an
agent can see:

```bash
shoephoned enroll --name phone    # one-time code: 10 minutes or 5 wrong guesses
shoephoned devices                # names, age, and whether push is registered
shoephoned forget --id <handle>   # by handle; a name identifies nobody
```

`enroll` prints a QR (`shoephone://enroll?daemon=<rp_origin>&code=<code>`)
on stderr and the bare code on stdout. Scan it in the app and pass Face ID;
the app is its own WebAuthn client and needs no browser. With a hardware key
instead, open `rp_origin` in a browser, enter the code, and tap. A passkey
made in Safari on an iPhone never works, because iOS makes only synced ones.

Each host then trusts the CA for the one account:

```
Match User agent-admin
    TrustedUserCAKeys /etc/ssh/shoephone_user_ca.pub
    AuthorizedPrincipalsFile /etc/ssh/principals/%u
    AuthorizedKeysFile none
```

with `/etc/ssh/principals/agent-admin` containing exactly that host's
principal.

## When something fails

| Symptom | Cause | Fix |
|---|---|---|
| exit 10, "agent refused operation" on every request | the ssh-agent refuses keys it did not create (1Password) | `agent = false`, then a `Match user <account>` stanza with `IdentityFile ~/.local/state/shoephone/hosts/<host>/session_ed25519`, `IdentitiesOnly yes`, `IdentityAgent none`; one `IdentityFile` per host, few enough that sshd's `MaxAuthTries` is not reached |
| every enrollment and approval fails | `rp_origin`/`rp_id` is not what the phone actually loads | set them to the exact https origin and its hostname |
| the credential is refused at enrollment | it is a synced passkey | use the app or a hardware key; `allow_synced_credentials` only as a stopgap |
| no push arrives | the device enrolled before its push secret existed, or neither `[apns]` nor `[notify]` is set | `shoephoned devices` says "push token but no secret: re-enroll"; do that at the console |
| sshd refuses the certificate | wrong principals file, missing `Match User` block, or clock skew | compare `ssh-keygen -L -f <cert>` with `/etc/ssh/principals/<account>` |
| exit 11 right after a daemon restart | windows live in memory and fail closed | request again |
| exit 22 | the daemon may have acted; outcome unknown | `shoephone status` before retrying |

## Working on this repo

| File | What it owns |
|---|---|
| `src/grant.rs` | the state machine: windows, nonces, rate cap, cooldown, kill. Policy defaults live here |
| `src/ca.rs` | certificate signing with the `ssh-key` crate; no `ssh-keygen` subprocess |
| `src/server.rs` | the axum routes, approve page, WebAuthn enroll and approve, ledger |
| `src/api.rs`, `src/client.rs` | the wire types, and the CLI's blocking client for them |
| `src/session.rs`, `src/store.rs` | per-host session keys; devices, enroll codes and ledger on disk |
| `src/notify.rs` | content-free push: ntfy topic and APNs |
| `src/exit.rs` | the exit-code vocabulary, and `include_str!` of the root `SKILL.md` |

Routes: `/api/{status,request,request/{id},issue,kill,pending,decline,ledger}`,
`/api/approve/{start,finish}`, `/api/enroll/{start,finish}`,
`/api/push/register`. The agent-side endpoints take no credential on purpose;
everything that *opens* a window needs the approver's key.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Three rules that are easy to break:

- **Generic by construction.** No real hostnames, vaults or addresses, ever;
  they belong in the private infrastructure repo.
- **SPDX two-line header on every file,** Markdown included, after any
  frontmatter.
- **`--features test-hooks` adds `POST /api/test/approve`** for the test
  suite. A deployed daemon built with it can approve its own requests.

`AGENTS.md` records the settled decisions and security invariants. Change
them there first, then in the code.

## What this deliberately does not do

It does not make the agent's machine trustworthy, and it does not end an ssh
session already open. It cannot protect a host whose admin credential sits
in a vault the agent's unattended token can read, or an infrastructure repo
whose apply step the agent can reach (Perimeters 1 and 2 in
`docs/DESIGN.md`).
