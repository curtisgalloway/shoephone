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

Scaffold. The daemon, the CLI verbs, and the approve page do not exist yet.
The design they will implement is written: [docs/DESIGN.md](docs/DESIGN.md),
which also covers the three things to close *before* deploying any of this
(an unattended secrets token that can read admin credentials, the
infrastructure repository as the trusted computing base, and backup servers
that accept deletes with no credential). The pieces will land in this order:

1. `shoephoned` with a web approve page: enforced scope, nonce, window,
   per-host principals, global rate cap, kill switch, notification ledger.
2. `shoephone` verbs: request, renew, disavow, and a `doctor` that says why a
   request cannot succeed before you make it.
3. A native approver app, or a hardware security key on the web page,
   whichever ceremony holds up in daily use.

## Building

```bash
cargo build --release
target/release/shoephone --skill    # the agent-facing document
```

## License

Apache 2.0. See [LICENSE](LICENSE).
