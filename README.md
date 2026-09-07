<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# shoephone

Phone-approved, short-lived SSH certificates for coding agents.

An agent that operates machines needs two kinds of access. Most of what it
does is reading: logs, status, disk, containers. That should be promptless,
or every prompt becomes noise and gets rubber-stamped. A little of what it
does is dangerous, and that should cost one meaningful ceremony a person can
perform from anywhere, on a device the agent cannot touch.

shoephone is the dangerous half. The agent runs `shoephone` to ask for admin
on one host. A daemon on a host the agent cannot reach shows the person the
enforced scope on their phone, together with a short match code the agent's
terminal also printed. The person compares the codes and approves by signing
that scope plus a single-use nonce. The daemon signs an SSH certificate that
is valid only on that host, only for the key that asked, and only until a
window the person saw closes. The agent's ssh-agent picks it up and the
session continues. Decline or timeout, and nothing is issued.

The name is from Get Smart. The approver is a phone; the agency is CONTROL.

## Status

The daemon exists and has not yet been deployed. `shoephoned` holds the
user CA, enforces the window, per-host principals, rate cap, cooldown and
single-use nonce, serves the approve page, enrolls a hardware security key
through WebAuthn, and appends every outcome to a ledger. The CLI still has
only `doctor`. The design is in [docs/DESIGN.md](docs/DESIGN.md), which also
covers the three things to close *before* deploying any of this (an
unattended secrets token that can read admin credentials, the
infrastructure repository as the trusted computing base, and backup servers
that accept deletes with no credential). Remaining, in order:

1. `shoephone` verbs: request, renew, disavow, and a `doctor` that says why a
   request cannot succeed before you make it.
2. A content-free push to the phone when a request arrives.
3. The full loop on cellular, then decide whether the web ceremony holds up
   or a native app is needed.

## Running the daemon

```bash
shoephoned --config shoephoned.toml init-ca      # once; prints the TrustedUserCAKeys line
shoephoned --config shoephoned.toml enroll --name phone   # at the console; prints a code
shoephoned --config shoephoned.toml serve
```

A minimal config:

```toml
listen = "127.0.0.1:7391"          # put a TLS reverse proxy in front
state_dir = "/var/lib/shoephone"   # root-only
ca_key = "/var/lib/shoephone/user_ca"
rp_id = "approve.example.internal"
rp_origin = "https://approve.example.internal"

[principals]
web01 = "agent-admin:web01"
```

## Building

```bash
cargo build --release
target/release/shoephone --skill    # the agent-facing document
```

## License

Apache 2.0. See [LICENSE](LICENSE).
