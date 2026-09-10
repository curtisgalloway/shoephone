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

Deployed. `shoephoned` holds the user CA, enforces the window, per-host
principals, rate cap, cooldown and single-use nonce, serves the approve
page, enrolls approver devices through WebAuthn, refuses any credential
that syncs, and appends every outcome to a ledger. `shoephone` requests,
waits, loads the certificate into ssh-agent, renews inside the window,
disavows, and has a `doctor` that says why a request cannot succeed before
you make it. The approver is the companion iOS app,
[shoephone-app](https://github.com/curtisgalloway/shoephone-app), whose
key lives in the phone's Secure Enclave behind Face ID; the web approve
page remains for a hardware security key. The design is in
[docs/DESIGN.md](docs/DESIGN.md), which also covers the three things to
close *before* deploying any of this (an unattended secrets token that can
read admin credentials, the infrastructure repository as the trusted
computing base, and backup servers that accept deletes with no
credential). A content-free push to an ntfy-style topic can tell the phone
that a request is waiting, a window opened, or a window was killed.

## Deploying the daemon

`shoephoned` belongs on the failsafe host described in the design: a small
machine outside the hypervisor's failure domain, with no agent account of
any tier, where admin is human-only. Four things are invariants; the rest
is ordinary service setup.

- The state directory and the CA key are root-only. `init-ca` creates the
  key at mode 0600 and refuses to overwrite one that exists.
- The config file holds the push token, so it is root-only too.
- The daemon speaks plain HTTP on loopback. A TLS reverse proxy in front
  serves the approve page to the phone; WebAuthn refuses anything else.
- `rp_origin` is the exact https origin the phone loads, and `rp_id` is
  its hostname. A mismatch fails every enrollment and approval.

### 1. Build and install

```bash
cargo build --release           # never with --features test-hooks for a deployed daemon
install -m 0755 target/release/shoephoned /usr/local/bin/
install -d -m 0700 /etc/shoephone
install -m 0600 shoephoned.toml /etc/shoephone/shoephoned.toml
```

That path is the daemon's default; `--config <file>` points it elsewhere.

`webauthn-rs` links the `openssl` crate, so the host needs libssl.

### 2. Configure

```toml
listen = "127.0.0.1:7391"          # the reverse proxy is the only client
state_dir = "/var/lib/shoephone"   # root-only; the systemd unit creates it 0700
ca_key = "/var/lib/shoephone/user_ca"
rp_id = "approve.example.internal"
rp_origin = "https://approve.example.internal"

[principals]
web01 = "agent-admin:web01"

[notify]                            # optional: content-free push to the phone
url = "https://ntfy.example.internal/shoephone"
token = "..."                       # if the topic is protected
click = "https://approve.example.internal"
```

The daemon refuses any credential the authenticator reports as
backup-eligible, which is every synced passkey (iCloud Keychain, 1Password
and the like): a synced credential also exists on the machine the agent
runs on, which is exactly what the approver must not be. Enrollment and
every approval check the flag, so a credential that turns synced later
stops working. `allow_synced_credentials = true` at the top level admits
them as a stopgap while a device-bound authenticator is on its way; the
daemon names every such device at startup.

`[policy]` overrides the window, certificate and cooldown durations in
minutes; the defaults are a 60 minute window (4 hours at most), 15 minute
certificates, a 5 minute pending timeout, 6 requests an hour, and a 5
minute cooldown after a decline that doubles to a 60 minute cap.

### 3. Create the CA and run the service

```bash
shoephoned init-ca > user_ca.pub
cp contrib/systemd/shoephoned.service /etc/systemd/system/
systemctl enable --now shoephoned
journalctl -u shoephoned -f
```

The unit in [contrib/systemd/shoephoned.service](contrib/systemd/shoephoned.service)
runs the daemon as root, because the key and state directory are
root-only, and then removes every capability, makes the filesystem
read-only except for the state directory, and filters system calls.
It restarts on a crash only. A restart fails closed: enrolled devices
survive, open windows and pending requests do not.

### 4. Put TLS in front

Any reverse proxy works; with Caddy the whole configuration is:

```
approve.example.internal {
    reverse_proxy 127.0.0.1:7391
}
```

Reach it from a certificate the phone trusts. A private CA in the phone's
trust store is fine; the CLI uses the machine's trust store through the
platform verifier, so the same private CA works there.

### 5. Enroll the approver

At the host's console, never over a session the agent could see:

```bash
shoephoned enroll --name phone
```

It prints a one-time code that is good for ten minutes or five wrong
guesses. In the Shoephone app on the phone, enter the code and pass Face
ID; the app is its own WebAuthn client and authenticator and needs no
browser. For a hardware security key instead, open `rp_origin` in a
browser, enter the code, and tap the key. An iPhone passkey made through
Safari will not work: iOS only makes synced ones, and the daemon refuses
them. Enrolling a second device is the same again with a different name;
every enrolled device is pushed when a window opens or is killed, so an
approval from one is visible on the others.

### 6. Trust the CA on each host

For every host in `[principals]`, in `sshd_config`, scoped to the one
user so no other account ever consults the CA:

```
Match User agent-admin
    TrustedUserCAKeys /etc/ssh/shoephone_user_ca.pub
    AuthorizedPrincipalsFile /etc/ssh/principals/%u
    AuthorizedKeysFile none
```

with `/etc/ssh/principals/agent-admin` containing exactly that host's
principal from the table, for example `agent-admin:web01`. A certificate
for any other host carries a different principal and is refused, and
`AuthorizedKeysFile none` means no static key can drift in beside it.

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
