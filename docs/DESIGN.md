<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# shoephone: design

**Status:** design, converged after two adversarial security reviews. The
daemon and CLI in this repository implement it piece by piece; nothing here
is theoretical for its own sake, and every rule below exists because a
review found the hole it closes. This document is the generic form of a
design written for one specific estate; the estate-specific deployment
(hostnames, which secrets moved where, the tuned sudoers list) lives in that
operator's private infrastructure repository and is not needed to adopt the
model.

## Terms

- **Coding agent, or agent:** a program (Claude Code, or any harness like
  it) that runs shell commands on the operator's behalf, including `ssh` to
  other machines. It can be confused, and it can be prompt-injected by
  content it reads. Every rule here assumes both.
- **Operator:** the human who owns the machines and approves things.
- **SSH certificate:** a public key plus metadata (principals, validity
  window, serial) signed by a certificate authority. sshd accepts it in
  place of an `authorized_keys` entry when it trusts the CA.
- **CA, certificate authority:** the private key that signs certificates.
  Here there are two, one for user certificates and one for host keys.
- **Principal:** a name inside a certificate that sshd matches against a
  per-user list. It is how a certificate is scoped to one host.
- **sudoers:** the file that says which commands a Unix user may run as
  root without a password. It is the enforcement floor of the safe tier.
- **Window:** the span of time the operator approved, shown to them on the
  phone and signed by them. Certificates are issued inside it and never
  outlive it.
- **Nonce:** a single-use random value bound to one pending request, so a
  captured approval cannot be replayed for another.
- **Kill switch:** the daemon-side action that closes a window early.
- **Failsafe host:** the small machine that runs the daemon and holds the
  CA. It sits outside the failure domains it is meant to help with.

## Problem

An agent that operates machines usually does so with the operator's own
SSH key, behind whatever approval the operator's key agent provides. Two
failures follow.

1. **Approval fatigue.** Every command prompts, so every prompt is
   approved, so prompts carry no signal. A confused or injected agent gets
   rubber-stamped like everything else.
2. **Location-bound ceremony.** The approval is a physical tap on the
   desktop's key agent. That is friction at the desk and impossible when
   the operator is driving the session from a phone.

The goal is to restore meaning to approvals: safe operations promptless,
dangerous operations gated by one meaningful ceremony per session, approvable
from anywhere. The secondary goal is a real server-side enforcement floor,
so policy holds even against an agent that is confused or lied to.

## Scope

In scope: operator and admin work on machines the agent does not develop
on. Virtual machines, hypervisors, the backup server, network gear, and the
failsafe host itself.

Out of scope: pair-programming hosts, where the agent works as the
operator, on the operator's files, with the operator's key. That
relationship is unchanged. It is still worth knowing what a root shell on
such a host can reach, which is the subject of the next section.

## Read this first: SSH tiering is not the perimeter

The first review's biggest finding was that treating SSH access as the
security boundary is the design's largest trap. Three perimeters sit
underneath it, and every one must be closed or the phone ceremony is
theater. Close them before building anything else.

### Perimeter 1: the unattended secrets token

The agent process usually holds a secrets-manager token that reads a vault
unattended, with no human in the loop, because that is how it fetches API
keys. If that vault also holds the hypervisor's admin credential, the
infrastructure tool's state-database password, or the network controller's
API key, the agent does not need a certificate at all. It reads the
credential and drives the API directly: destroy VMs, exec into guests,
delete backups.

Any target whose privileged credential lives in a vault the unattended
token can read is unprotected by everything else in this document.

The fix is **vault splitting.** The unattended token may read only a
vault where nothing grants write or admin anywhere on disclosure.
Privileged secrets move to a vault the token cannot read, released only
through a human step. Once the safe tier below exists, the unattended
token barely needs to read anything, so the split costs little friction.

Two corollaries the second review added:

- **Count every unattended path, not just the agent's own token.** Machines
  that fetch runtime secrets at boot from a secrets-connector service hold
  a second token that reads a second vault. Root on any such machine equals
  read of that whole vault. If the agent has root on one of them, that
  vault needs the same audit.
- **A personal vault behind biometric unlock is an ambient-unlock path.**
  The secrets CLI stays authorized for a while after one fingerprint, and an
  agent session running during that window can read through it. Decide
  explicitly whether that is acceptable (used only from the operator's own
  shell, never from an agent session, with the re-auth interval set short)
  or route those secrets through the daemon too, minting short-lived API
  tokens on the same phone approval it uses for SSH certificates.

### Perimeter 2: the infrastructure repository is the trusted computing base

The entire server-side floor (the agent's Unix users, the sshd CA trust,
the principals files, every sudoers allowlist) is defined in files in a
repository the agent edits, and is pushed to hosts by an apply step. An
injected agent that appends its own CA public key or an `authorized_keys`
line to the template and reaches the apply step owns the trust anchor on
every current and future host, bypassing the daemon entirely.

Therefore the apply step, and any change to a trust-anchor file, is a
dangerous-tier operation: it requires the human approval path or
out-of-band review that the agent is not part of. This is the rule most
adopters will want to skip, because it is inconvenient. Skipping it makes
everything below decorative.

### Perimeter 3: writes that need no credential at all

A control that authenticates the actor is only as strong as the weakest
unauthenticated write path to the same asset. Before scoring the design,
enumerate every network service that accepts a destructive write with no
credential. Two common ones:

- **The backup server.** A restic REST server run with `--no-auth`, or
  without `--append-only`, lets any host that can reach it delete every
  snapshot and pack. The repository password is not needed; it only
  encrypts content. This is the most irreversible action in most estates
  and it costs nothing. Run the server append-only with one credential per
  client host, pin each client to its own repository, and move retention
  (forget and prune) to a job on the backup server that works against the
  repository directories directly:

  ```yaml
  restic-server:
    image: restic/rest-server
    environment:
      - OPTIONS=--append-only --private-repos   # .htpasswd in the data dir
    volumes:
      - /backups/restic:/data

  restic-prune:
    image: restic/restic
    secrets: [restic_password]
    volumes:
      - /backups/restic:/data
      - ./prune.sh:/prune.sh:ro
    entrypoint: ["/bin/sh", "-c", "echo '0 13 * * * /bin/sh /prune.sh' > /etc/crontabs/root && crond -f"]
  ```

  Verify it rather than assume it: an unauthenticated read should return
  401, a `DELETE` of a key, data, or snapshot object 403, and a `DELETE` of
  a lock 200, because lock deletion is what lets a client's backup clean
  up after itself.
- **The log store.** A log aggregator with an unauthenticated push
  endpoint and a delete API is not an append-only audit sink, whatever the
  diagram says. See the ledger in the dangerous tier below.

## The model: two tiers, one principal per platform

The unit of identity is an agent principal on every platform, realized
natively: a Unix user on Linux hosts, a read-only API token on the
hypervisor, a read-only account on the network controller, a local user on
the NAS. Users do not encode operations, so the safe/dangerous split lives
in sudoers plus account separation, not in identity alone.

### Safe tier: read-only, promptless, always available

- **Account:** a local `agent` user on each Linux host, provisioned by the
  base image or cloud-init. Groups: `adm` and `systemd-journal`. Never the
  `docker` group; the docker socket is root-equivalent through
  `docker run -v /:/host`.
- **The read surface is not nothing.** Those groups grant the full journal
  and `/var/log`, including whatever a service printed to stdout, which is
  where secrets leak. Read-only is not harmless: reads are how lateral
  movement is fueled. Safe-tier read on a hypervisor is materially higher
  value than on a leaf VM and is an accepted exposure, noted so it is a
  decision rather than an accident. After rolling the tier out, list what
  the account can actually read and grep it for anything token-shaped.
- **Sudo:** a short allowlist of exact read-only invocations in
  `/etc/sudoers.d/agent`, grown only from observed friction. A starting
  point:

  ```
  agent ALL=(root) NOPASSWD: /usr/bin/docker ps, \
      /usr/bin/docker ps -a, \
      /usr/bin/docker logs *, \
      /usr/sbin/zfs list, /usr/sbin/zpool status
  ```

  Most reads (`journalctl`, `systemctl status`, `df`, `ip`, `ss`) need no
  sudo given the groups.
- **Sudoers pitfalls.** Wildcards match whitespace, so never allowlist a
  command whose arguments can name an output file or spawn a shell. Prefer
  exact strings. `docker logs *` is acceptable because `docker logs` has no
  write, exec, or volume primitive, but it is an information-leak surface.
- **Denylist, the real risk being drift:** `docker exec`, `docker run`,
  `docker cp`, `docker inspect` (leaks container environment), any guest
  exec on the hypervisor, anything taking `-v` or `--volume`, any
  file-output flag, and any `--format` or `--template` on privileged
  output. If a need pushes toward one of these, it belongs in the dangerous
  tier, not a widened safe entry. If exact-match docker entries chafe, the
  alternative is a read-only docker socket proxy that exposes GET endpoints
  only, never the `docker` group.
- **Key:** a dedicated keypair with the private half on disk on the agent's
  machine, no passphrase, no agent, no secrets manager. Client config:

  ```
  Match host "*.example.internal" user agent
      IdentityFile ~/.ssh/agent_safe
      IdentitiesOnly yes
      IdentityAgent none
  ```

  **Why on-disk is acceptable, with eyes open.** The key unlocks only a
  read-only, sudoers-constrained account. It is broader than the secrets
  token on some axes (at rest around the clock, captured by machine
  backups, readable by any process running as the user, not centrally
  revocable), so the claim is narrower than "strictly less exposure": an
  attacker who can read this key can already read the token from the
  agent's process environment, so on the machine-compromise threat it adds
  little marginal exposure, and it buys the promptless tier that makes the
  model usable. Rotate it on any compromise suspicion, and keep it out of
  any backup that leaves the machine.
- **Harness side: allowlist a wrapper, never a raw `ssh` prefix.** Making
  safe operations promptless means telling the agent harness not to prompt
  for them. The obvious allowlist, `ssh agent@*`, is a local
  code-execution bypass: ssh accepts options after the host, so
  `ssh agent@host -o ProxyCommand='...'` runs arbitrary commands on the
  agent's own machine with no prompt, as do `LocalCommand`, `-F`, and `-i`
  pointing at agent-written files. Ship a small wrapper that builds the ssh
  argument list itself with fixed options and validates the host, and
  allowlist only that. The harness layer remains a UX layer, not an
  enforcement layer, but a UX layer must not open a hole of its own.
- **Revocation:** remove one public-key line per host, or lock the account.

### Dangerous tier: session-granted, short-lived, host-scoped certificates

No static admin keypair exists, ever. Escalation is a certificate signed by
the user CA on the failsafe host, requested per session and approved from
the operator's phone.

- **Account:** a local `agent-admin` user on each host, passwordless sudo
  `ALL`, no password, no static `authorized_keys`. Reachable only via a
  certificate.
- **Host trust, scoped to the one user:**

  ```
  Match User agent-admin
      TrustedUserCAKeys /etc/ssh/agent_ca.pub
      AuthorizedPrincipalsFile /etc/ssh/principals/%u
      AuthorizedKeysFile none
  ```

  `AuthorizedKeysFile none` means the only door is a certificate carrying
  this host's principal; no static key can drift in. Other users never
  consult the CA. A global `TrustedUserCAKeys` was the first draft, and it
  would have let a certificate for principal `admin` work if the daemon's
  principal check ever slipped.
- **Per-host principals from day one.** Each host's
  `/etc/ssh/principals/agent-admin` lists only that host's principal, for
  example `agent-admin:web01`. A certificate signed for it is valid only
  on that host, so the host shown in the approval is the host the grant
  unlocks, not cosmetic. An estate-wide principal made the notification's
  host field a lie and hollowed out the tap.
- **The phone signs a window, not a certificate.** The enforced scope shown
  and signed is "admin on `web01` until HH:MM", default 60 minutes, server
  maximum a few hours. Inside the window the daemon issues short
  certificates (10 to 15 minutes) on silent re-request, no certificate
  outlives the window, and a new window is a new approval. The first draft
  said "15-minute certificates with silent renewal while the session stays
  approved" and also "one signature per approval". Those contradict: the
  phone would sign 15 minutes and the daemon would renew forever on a
  bearer token the agent holds, so the effective grant was open-ended and
  the displayed scope untrue.
- **Renewals are bound to the key that was approved.** The request carries
  the session's public key; every certificate in the window is issued to
  that key only, so a renewal cannot be handed to a different key.
- **Revocation is a kill switch, not a revocation list.** The daemon
  exposes "end session", which closes the window; worst-case latency is one
  certificate TTL. A `RevokedKeys` list on every host was the earlier
  answer and carries a lockout trap: if the option is set and the file is
  unreadable, sshd refuses public-key authentication for all users,
  including the static recovery accounts. Distributing it by push also
  means the daemon holds a credential to every host, which inverts custody
  rule 4. If sub-TTL revocation is ever needed, ship an empty valid list in
  the base image, have hosts pull it on a timer, and write it atomically.
- **Grant flow.** The session runs the grant CLI, which submits the request
  (host, public key) to the daemon and prints a short match code. The
  daemon notifies the phone with a content-free push. The operator opens
  the approve page or app, which fetches the pending request from the
  daemon and shows the enforced scope, the match code, the requesting
  hostname, and the key fingerprint. The operator checks the code against
  the terminal in front of them and approves; their device signs the
  enforced scope plus nonce; the daemon verifies the signature and issues a
  host-scoped certificate; the CLI loads key and certificate into the
  session's ssh-agent. Decline or timeout issues nothing.
- **The approval must be cryptographically bound to the operator's device.**
  The daemon verifies a signature from a key that exists only there, not
  merely that an HTTP call arrived at its approve endpoint. Without this
  the agent's own machine, on the same network as the daemon, can call the
  endpoint and self-approve. The signature covers the enforced scope as
  displayed plus a single-use nonce bound to the specific request, so a
  channel that lies about scope yields a signature the daemon rejects, and
  a captured approval cannot be replayed.
- **The push carries no authority.** Notification payloads are content-free;
  the device fetches pending requests and their enforced scope from the
  daemon directly. A forged or replayed push at worst opens the page onto an
  empty list.
- **The match code binds the approval to the session the operator is
  looking at.** Any process on the agent's machine can file a request at a
  plausible moment, and host plus window alone cannot distinguish "my
  session" from a rogue one. Borrowed from the OAuth device flow, and it is
  the one control in the flow a prompt-injected agent cannot influence from
  the inside.
- **Server-side caps, not client promises.** The daemon enforces the
  maximum window, the fixed per-host principal set, and a global request
  rate cap regardless of what the request says. The cap is per CA and per
  approver, never keyed on anything the requester chooses, because a
  per-session cap was bypassed by minting sessions. A decline costs a
  cooldown that grows on repeat. Without a cap an agent can fire requests
  at plausible moments and ride approval habituation, which is how fatigue
  creeps back in. The approver sees the daemon's enforced scope, never the
  request's prose; request text is agent-authored and untrusted.
- **Expiry is enforced by sshd on every host.** Nothing to clean up, nothing
  long-lived to leak.
- **The audit ledger lives on the phone.** Every issuance, renewal, decline,
  and kill produces a notification to the operator's device, which keeps
  that history. The daemon's own logs are worthless if the daemon is
  compromised, and a log aggregator with an unauthenticated push endpoint
  and a delete API is not append-only. The aggregator stays as the
  searchable copy, not the authoritative one.

### An SSH host CA too

Since a CA exists anyway, also run a host CA: sign each host's host key and
put a single `@cert-authority *.example.internal <hostca.pub>` line in the
agent machine's root-owned `/etc/ssh/ssh_known_hosts`, not the
agent-writable per-user file. This kills first-use trust and means a
compromised host cannot impersonate a peer. New hosts need no known-hosts
churn. Separate keypair from the user CA.

### Why this shape

- **A separate user, not just separate keys:** attribution (journal and sudo
  logs distinguish agent from human), revocation, and a server-side
  enforcement point that holds against a confused or injected agent.
  Client-side prompts only protect against an agent that honestly describes
  itself.
- **A CA over a static admin key:** remote approval structurally requires a
  third party that releases a credential on a tap. Once that daemon exists,
  signing short certificates costs the same as releasing a static key, with
  strictly better properties: host-enforced expiry, host-scoped principals,
  nothing long-lived in flight.
- **Ambient-unlock grant paths are forbidden.** Any grant that works
  whenever the desktop's key agent happens to be unlocked lets the agent
  self-escalate during the unlock window. The verdict must originate from a
  device only the operator holds and be verified as such.

## Key custody invariants

1. The CA private keys must not exist anywhere an agent-held credential can
   read: not in any vault the unattended token reads, not on any machine
   the agent has a shell on. They live root-only on the failsafe host, with
   a backup in a vault the agent cannot read.
2. The same rule applies to any future escalation material and to the
   privileged secrets moved out in Perimeter 1.
3. The safe-tier private key is deliberately unprotected on disk; see the
   eyes-open note above. Do not back it up anywhere that leaves the machine.
4. **The failsafe host accepts no agent account of any tier.** It holds the
   CA; an agent with any foothold on it, even the constrained safe tier, is
   one sudoers-drift or key-permission mistake away from signing its own
   certificates forever. Admin on the failsafe host is human-only. The
   approver must not be reachable by the thing it approves.
5. The infrastructure repository and its apply step are part of the
   trusted computing base (Perimeter 2). Changes to trust-anchor files are
   dangerous-tier or out-of-band reviewed, never performed by the safe tier
   or the unattended token.
6. The audit ledger lives off the failsafe host, on the operator's device.

## The failsafe host

The dangerous tier is needed disproportionately during incidents, and
incidents are mostly on the hypervisor side, so the approval path must live
outside that failure domain or it deadlocks against its own purpose:
hypervisor down, no certificates, no escalation to fix the hypervisor. A
NAS was considered for the role and rejected: vendor-skinned, lags upstream,
updates on the vendor's schedule, cannot be rebuilt from a repository. The
NAS stays the data plane; the control plane is a small box the operator
fully controls.

- **Hardware:** a small machine with a TPM 2.0, and the least-experimented-on
  machine in the house. Verify the TPM exists before committing to the
  disk-encryption story.
- **Substrate:** a stable Linux plus Docker Compose, nothing else. Not a
  cluster node (clustering couples it to the failure domain it must stand
  outside). Reproducibility comes from everything being in a repository
  plus a netboot or preseed install recipe.
- **CA key at rest: TPM-sealed full-disk encryption.** The disk is LUKS
  with the key sealed to the TPM, so the box boots unattended yet physical
  theft does not yield the CA key: the sealed key will not release on a
  different machine or an altered boot chain. This closes the "headless
  signer cannot passphrase-protect its key" gap.
- **Tenant admission test,** to resist scope creep: a service runs here only
  if it is needed during incidents, independent of the domains it watches,
  and low-churn. "Critical" is not the test. The moment this box
  accumulates interesting workloads it stops being a failsafe.
- **Dead-man monitoring:** a failsafe that dies silently is worse than none.
  The box pings an external dead-man check so the alert for "the watcher is
  dead" depends on nothing in the house. It goes on the UPS.
- **Degradation:** every failure of this host degrades to "no escalations
  until it is back". The safe tier has no dependency on it by construction.
- **Failover pair (optional):** two identical boxes with a floating VIP,
  each deployed independently, CA keys copied once at setup and TPM-sealed
  on each. Stateless by design, so the dumbest HA tool wins. Split-brain is
  harmless only because approval is device-bound: both nodes require the
  same signature. A cold spare plus a rehearsed rebuild runbook is the
  minimal alternative.

## The approver

The device-binding requirement needs a credential that exists only on the
operator's device. Three ways to get one, in the order they should be
built:

1. **A web approve page over a private network, first.** The daemon serves
   it; the operator's phone reaches it over a VPN. This is the MVP: the
   enforced scope, nonce, window, match code, and caps are all server-side,
   so it delivers most of the security value with no app. Device binding
   comes from the transport (a client certificate installed on the phone)
   or from the next item.
2. **A hardware security key on that page.** WebAuthn with a security key
   tapped on the phone is device-bound, does not sync through a cloud
   keychain (the reason synced passkeys are rejected: the credential
   materializes on the machine the agent shares), works in the phone's
   browser, and needs no app. The assertion signs a challenge derived from
   the enforced scope plus nonce, so the binding is the same as an
   app's.
3. **A native app with a hardware-backed signing key,** if the ceremony from
   1 and 2 does not hold up in daily use. Hardware-bound, non-exportable,
   biometric-gated per signature, and a purpose-built approve screen keeps
   the ceremony good enough to survive; ceremony rot from bad UX is how the
   original prompts died. Push notifications come directly from the daemon
   through the platform's push service. It is also the long pole: app
   review of an app whose backend is a private host is a real rejection
   risk, and store distribution is the only one whose builds do not expire
   mid-incident. Decide after living with 1 and 2.

Whichever path, two rules hold:

- **Enrollment is human-only.** The device's public key is registered with
  the daemon through a one-time code minted at the failsafe host's
  console. The agent is never in this loop; registration authority is
  escalation material.
- **Test the full approve loop on cellular early.** If it fails half the
  time, the ceremony rots exactly the way the old prompts did.

## Reachability and failure modes

The approval response path usually sits inside the home router and ISP
failure domain even though the failsafe host sits outside the hypervisor's.
A router or ISP outage deadlocks approvals. Accept this: the design fails
closed (no approval, no escalation), which is the correct direction. The
physically-present fallback is a human-only console on the failsafe host
that can mint an emergency certificate.

A held-in-reserve upgrade if the VPN UX disappoints: expose the approve API
publicly through an outbound-only tunnel service, so there is no inbound
port on the home network. This is safe only because the verdict signature
covers scope plus nonce: the tunnel provider terminates TLS, and a stolen
tunnel credential would let an attacker impersonate the origin, so either
party can at worst deny service or show the device a request it cannot
honestly sign, never forge or scope-lie an approval. It still needs the
failsafe host's own internet, so it does not fix the ISP-down case.

## Non-Linux platforms

| Platform | Safe tier | Dangerous tier |
|---|---|---|
| Hypervisor | `agent` user as on VMs, plus optionally a read-only API token | `agent-admin` via host-scoped certificate; or short-lived API tokens minted by the daemon on the same approval |
| Network controller | an existing read-only account | the write API key, moved out of the token-readable vault, used only with an explicit confirmation flag and a harness prompt |
| NAS | a read-mostly local user | stays human-only; it is the data plane |

## Future hook: a server-side classifier

The sudoers allowlist is the classifier, the boring deterministic one. If a
smarter one is ever wanted, the insertion point is a `ForceCommand` wrapper
on the safe-tier account: every incoming command passes through one script
that logs it (valuable on day one, even dumb) and checks policy. Nothing in
the two-tier design changes when that arrives. A classifier you cannot
predict is a classifier you will fight.

## Build order

0. **Close the perimeters.** In order: make the backup server append-only
   with per-client credentials (Perimeter 3, first because it is the
   largest irreversible action and needs no credential today); split the
   vaults so the unattended token reads nothing that grants write or admin
   (Perimeter 1); audit every other unattended path with the same test.
   Nothing else ships first.
1. **Safe tier.** Keypair on disk; `agent` user, groups, sudoers with the
   denylist discipline, and public key in the base image; the ssh `Match`
   block; the wrapper and its harness allowlist; measure and record the
   read surface.
2. **Failsafe host.** The box, TPM-sealed LUKS, no agent account, external
   dead-man check, UPS. Stand up the host CA and lay the `@cert-authority`
   line into the root-owned known-hosts file.
3. **Dangerous tier, web ceremony.** User CA (custody rules); the daemon;
   the approve page; match code; window plus short certificates bound to
   the approved key; global rate cap and decline cooldown; kill switch;
   ledger to the device; per-host principals and the `Match User` block in
   the base image; the grant CLI; the full loop tested on cellular. Make
   the apply step and trust-anchor edits dangerous-tier.
4. **Better ceremony,** a hardware security key or a native app, decided
   after living with step 3.
5. **Optional:** the failover pair, or the cold spare plus runbook.

## What this deliberately does not do

- It does not make the agent's own machine trustworthy. Everything here
  assumes that machine is compromised to the extent of the agent's own
  privileges, and asks only that compromise not extend further.
- It does not classify commands at the safe tier beyond sudoers. Read
  access is coarse on purpose; a finer policy engine is a future hook, not
  a day-one dependency.
- It does not replace the operator's own access. Humans keep their own keys
  and their own accounts; the agent principals exist alongside them, which
  is what makes attribution and revocation clean.
