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

Built, not yet deployed. `shoephoned` holds the user CA, enforces the
window, per-host principals, rate cap, cooldown and single-use nonce,
serves the approve page, enrolls a hardware security key through WebAuthn,
and appends every outcome to a ledger. `shoephone` requests, waits, loads
the certificate into ssh-agent, renews inside the window, disavows, and
has a `doctor` that says why a request cannot succeed before you make it.
The full loop runs against a live daemon in tests; the security-key tap
itself has not been tried from a phone yet. The design is in
[docs/DESIGN.md](docs/DESIGN.md), which also covers the three things to
close *before* deploying any of this (an unattended secrets token that can
read admin credentials, the infrastructure repository as the trusted
computing base, and backup servers that accept deletes with no
credential). A content-free push to an ntfy-style topic tells the phone a request is
waiting. What remains is deployment: the failsafe host behind TLS, a key
enrolled at its console, the loop run on cellular, and then the decision
whether the web ceremony holds up or a native app is needed.

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

[notify]                            # optional: content-free push on each request
url = "https://ntfy.example.internal/shoephone"
click = "https://approve.example.internal"
```

## Using the CLI

```bash
export SHOEPHONE_DAEMON=https://approve.example.internal   # or ~/.config/shoephone/config.toml
shoephone doctor                # what is missing, before guessing
shoephone request web01         # prints a match code, waits for the phone, loads the cert
ssh agent-admin@web01 sudo systemctl restart something
shoephone renew web01           # next 15 minutes, no second tap, inside the window
shoephone disavow web01         # close the window early
```

`shoephone --skill` prints the agent-facing document with the full exit
code table.

## Building

```bash
cargo build --release           # never with --features test-hooks for a deployed daemon
target/release/shoephone --skill
```

## License

Apache 2.0. See [LICENSE](LICENSE).
