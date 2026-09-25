<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# shoephone: design

**Status:** settled after two adversarial security reviews; every rule here
closes a hole one of them found. The daemon and CLI in this repository
implement it. This is the generic form of a design written for one estate,
whose specifics (hostnames, secret locations, the tuned sudoers list) live in
that operator's private infrastructure repository.

## Terms

- **Agent:** a program such as Claude Code that runs shell commands for the
  operator, including `ssh`. It can be confused, and it can be
  prompt-injected by content it reads. Every rule here assumes both.
- **Operator:** the person who owns the machines and approves requests.
- **SSH certificate:** a public key plus principals, a validity period and a
  serial, signed by a certificate authority. sshd accepts it in place of an
  `authorized_keys` entry when it trusts the CA.
- **CA (certificate authority):** the private key that signs certificates.
  There are two: one for user certificates, one for host keys.
- **Principal:** a name in a certificate that sshd matches against a
  per-user list. It limits a certificate to one host.
- **sudoers:** the file listing which commands a user may run as root.
- **Window:** the time span the operator approved on the phone. Certificates
  are issued inside it and never outlive it.
- **Nonce:** a single-use random value tied to one request, so an approval
  cannot be replayed for another.
- **Kill switch:** the daemon action that closes a window early.
- **Failsafe host:** the small machine that runs the daemon and holds the CA,
  outside the failure domains it helps with.

## Problem

Agents usually operate machines with the operator's own SSH key, behind
whatever confirmation the key agent asks for. Two things go wrong:

1. **Approval fatigue.** Every command prompts, so every prompt gets
   approved, so a confused or injected agent is waved through with the rest.
2. **Approval is tied to a desk.** The confirmation is a tap on the desktop's
   key agent, which is impossible when the operator drives the session from a
   phone.

The goal: no prompts for safe operations, one deliberate approval per session
for dangerous ones, possible from anywhere, and enforcement on the server so
policy holds even against a confused or deceived agent.

**In scope:** admin work on machines the agent does not develop on: VMs,
hypervisors, the backup server, network gear, the failsafe host.
**Out of scope:** hosts where the agent pair-programs as the operator with
the operator's key.

## First: SSH access is not the perimeter

The first review's biggest finding. Three other paths reach the same
machines, and if any is open the phone approval is theater. Close all three
before building anything else.

### Perimeter 1: the unattended secrets token

The agent usually holds a secrets-manager token that reads a vault with no
person involved. If that vault also holds the hypervisor's admin credential,
the infrastructure tool's database password, or the network controller's API
key, the agent needs no certificate. It reads the credential and destroys
VMs, runs commands in guests, or deletes backups directly.

**Fix: split the vaults.** The unattended token may read only secrets that
grant no write or admin access if disclosed. Privileged secrets move to a
vault released only through a human step. Once the safe tier exists, the
token needs very little, so the split is cheap.

The second review added two cases:

- **Other unattended tokens count too.** A machine that fetches secrets at
  boot holds a second token for a second vault, so root on that machine reads
  that whole vault. Audit it the same way.
- **A biometric-unlocked personal vault stays open for a while.** After one
  fingerprint, the secrets CLI stays authorized, and an agent session running
  then can read through it. Either accept that explicitly (only the
  operator's own shell uses it, with a short re-auth interval) or have the
  daemon mint short-lived API tokens on the same phone approval.

### Perimeter 2: the infrastructure repository

Everything the server enforces (the agent's users, sshd's CA trust, the
principals files, the sudoers allowlists) is defined in a repository the
agent edits and pushed out by an apply step. An injected agent that adds its
own CA key or an `authorized_keys` line to a template, and reaches the apply
step, owns every current and future host without touching the daemon.

So the apply step, and any change to a trust-anchor file, is a
dangerous-tier operation that needs the phone approval or a review the agent
takes no part in. This is the rule adopters most want to skip. Skipping it
makes everything below decorative.

### Perimeter 3: writes that need no credential

A control that authenticates the actor is only as strong as the weakest
unauthenticated path to the same asset. List every service that accepts a
destructive write with no credential. Two common ones:

- **The backup server.** A restic REST server run with `--no-auth`, or
  without `--append-only`, lets any host that reaches it delete every
  snapshot; the repository password only encrypts content. This is usually
  the most irreversible action in the estate, and it is free. Run the server
  append-only with one credential per client, pin each client to its own
  repository, and run retention on the backup server itself:

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

  Then test it: an unauthenticated read should get 401, a `DELETE` of a key,
  data or snapshot object 403, and a `DELETE` of a lock 200, because clients
  must be able to clear their own locks.
- **The log store.** An aggregator with an unauthenticated push endpoint and
  a delete API is not an append-only audit trail. See the ledger below.

## The model: two tiers

The agent gets its own identity on every platform, in native form: a Unix
user on Linux, read-only API tokens or accounts on the hypervisor, network
controller and NAS. The identity does not decide which operations are
allowed; sudoers and separate accounts do.

### Safe tier: read-only, no prompts

- **Account:** a local `agent` user on each Linux host, from the base image,
  in groups `adm` and `systemd-journal`. Never `docker`: the docker socket is
  root through `docker run -v /:/host`.
- **Read-only is not harmless.** Those groups read the whole journal and
  `/var/log`, where services leak secrets, and reads feed lateral movement.
  Read access to a hypervisor is worth far more than to a leaf VM; accept it
  as a decision. After rollout, grep what the account can read for anything
  that looks like a token.
- **Sudo:** a short allowlist of exact read-only commands in
  `/etc/sudoers.d/agent`, grown only when real work hits a wall. Most reads
  (`journalctl`, `systemctl status`, `df`, `ip`, `ss`) need no sudo. A start:

  ```
  agent ALL=(root) NOPASSWD: /usr/bin/docker ps, \
      /usr/bin/docker ps -a, \
      /usr/bin/docker logs *, \
      /usr/sbin/zfs list, /usr/sbin/zpool status
  ```

  A sudoers wildcard also matches spaces, so never allowlist a command whose
  arguments can name an output file or start a shell. `docker logs *` is
  acceptable because `docker logs` cannot write, exec or mount.
- **Never allow** `docker exec`, `run`, `cp` or `inspect` (it shows
  environment variables), guest exec on the hypervisor, `-v`/`--volume`, any
  flag that writes a file, or `--format`/`--template` on privileged output.
  The risk is these creeping in; a need for one belongs in the dangerous
  tier. If exact docker entries chafe, use a read-only docker socket proxy
  (GET endpoints only), never the `docker` group.
- **Key:** a dedicated keypair on disk on the agent's machine, with no
  passphrase, no ssh-agent and no secrets manager:

  ```
  Match host "*.example.internal" user agent
      IdentityFile ~/.ssh/agent_safe
      IdentitiesOnly yes
      IdentityAgent none
  ```

  An unprotected key is acceptable because it opens only a read-only,
  sudoers-limited account, and anyone who can read it can already read the
  secrets token from the agent's environment. It is more exposed in some ways
  (always on disk, in machine backups, readable by the user's processes, not
  centrally revocable), so rotate it on any suspicion and keep it out of
  backups that leave the machine.
- **In the agent harness, allowlist a wrapper, not `ssh agent@*`.** ssh takes
  options after the host, so `ssh agent@host -o ProxyCommand='...'` runs any
  command on the agent's own machine, as do `LocalCommand`, `-F`, and `-i`
  pointed at agent-written files. Ship a small wrapper that builds the ssh
  command with fixed options and checks the host, and allowlist only that.
  The harness is a convenience layer, but it must not open a hole.
- **Revocation:** remove one public-key line per host, or lock the account.

### Dangerous tier: short-lived certificates, one host each

There is no static admin key. Admin access is a certificate from the user CA
on the failsafe host, requested per session and approved on the phone:

1. The session's CLI sends the host and its public key to the daemon and
   prints a short match code.
2. The daemon sends the phone a content-free push. The phone fetches the
   request and shows the enforced scope, the match code, the requesting
   hostname and the key fingerprint.
3. The operator checks the code against the terminal and approves. The
   device signs the scope plus the nonce.
4. The daemon verifies the signature and issues a certificate for that host,
   which the CLI loads into ssh-agent. A decline or timeout issues nothing.

- **Account:** a local `agent-admin` user on each host with passwordless
  `sudo ALL`, no password, and no `authorized_keys`.
- **Host trust, for that one user only:**

  ```
  Match User agent-admin
      TrustedUserCAKeys /etc/ssh/agent_ca.pub
      AuthorizedPrincipalsFile /etc/ssh/principals/%u
      AuthorizedKeysFile none
  ```

  The only way in is a certificate carrying this host's principal. Other
  users never consult the CA. (A global `TrustedUserCAKeys`, the first
  draft, would have let a certificate for principal `admin` work anywhere the
  daemon's principal check slipped.)
- **One principal per host.** Each host's `/etc/ssh/principals/agent-admin`
  lists only its own principal, such as `agent-admin:web01`, so the host
  shown on the phone is the host the approval unlocks. An estate-wide
  principal would make that field decoration.
- **The phone signs a window; the daemon signs certificates inside it.** The
  phone signs "admin on `web01` until HH:MM" (60 minutes by default, a few
  hours at most). Inside it, the daemon issues 10- to 15-minute certificates
  on request, all to the approved key, none outliving the window. A new window
  needs a new approval. (The first draft approved one 15-minute certificate
  and renewed it indefinitely, so the phone's scope was untrue.)
- **The approval is a signature from the operator's device,** not just an
  HTTP call to an approve endpoint, which the agent's own machine could make.
  It covers the displayed scope plus the request's nonce, so a channel that
  lies about scope yields a signature the daemon rejects, and a captured
  approval cannot be replayed.
- **The match code ties the approval to the operator's session.** Any process
  on the agent's machine can file a request at a plausible moment, and host
  plus window cannot tell the operator's session from a rogue one. The code,
  borrowed from the OAuth device flow, is the one control a prompt-injected
  agent cannot influence from the inside.
- **Pushes carry no content and no authority.** The device fetches pending
  requests from the daemon. A forged push at worst opens an empty list.
- **Limits live on the server.** The daemon enforces the maximum window, the
  per-host principals and a rate cap whatever the request says. The cap is
  per CA and per approver, never keyed on anything the requester picks (a
  per-session cap was bypassed by opening sessions). Declines cost a growing
  cooldown. Without a cap, an agent can keep asking until habit approves it.
  The scope the approver signs is the daemon's own, never the request's text,
  which the agent wrote.
- **sshd enforces expiry.** Nothing to clean up, nothing long-lived to leak.
- **Revocation is a kill switch.** It closes the window, so no new
  certificates are issued and existing ones expire within one lifetime. sshd
  checks a certificate only at login, so a session already open continues;
  capping that is a host setting (an idle timeout or session limit), not the
  daemon's job.

  A `RevokedKeys` list was the earlier plan and was dropped: if the option is
  set and the file is unreadable, sshd refuses key login for every user,
  including recovery accounts, and pushing the list would give the daemon a
  credential to every host (breaking custody rule 4). If faster revocation of
  new logins is ever needed, ship an empty list in the base image, have hosts
  pull updates on a timer, and write it atomically.
- **The audit ledger lives on the phone.** Every issuance, renewal, decline
  and kill is reported to the operator's device. The daemon's logs are
  worthless if the daemon is compromised, and a log aggregator that accepts
  unauthenticated pushes and deletes is not append-only; it is the searchable
  copy, not the authoritative one.

### An SSH host CA as well

Sign each host's host key with a separate host CA, and put one
`@cert-authority *.example.internal <hostca.pub>` line in the agent machine's
root-owned `/etc/ssh/ssh_known_hosts` (not the per-user file the agent can
write). This ends trust-on-first-use, stops a compromised host from
impersonating another, and means new hosts need no known-hosts changes.

### Why this shape

- **A separate user, not just a separate key:** logs tell agent from human,
  revocation is clean, and enforcement is on the server, where it holds
  against a confused or injected agent. Client-side prompts stop only an
  agent that describes itself honestly.
- **A CA, not a static admin key:** remote approval needs a party that hands
  out a credential when the phone says yes. Given that, signing a short
  certificate costs no more than releasing a static key, and hosts enforce
  its expiry and scope.
- **No approval that works whenever something is unlocked.** If a grant
  succeeds while the desktop's key agent is unlocked, the agent can approve
  itself during that time. The yes must come from a device only the operator
  holds.

## Key custody rules

1. The CA private keys never exist where an agent-held credential can reach:
   not in a vault the unattended token reads, not on a machine the agent has
   a shell on. They live root-only on the failsafe host, backed up to a vault
   the agent cannot read.
2. The same applies to future escalation material and to the privileged
   secrets moved out in Perimeter 1.
3. The safe-tier key is deliberately unprotected on disk. Never back it up
   off the machine.
4. **The failsafe host has no agent account of any tier.** An agent with any
   foothold there is one sudoers mistake away from signing its own
   certificates forever. Admin on it is human-only. The approver must not be
   reachable by what it approves.
5. The infrastructure repository and its apply step are trusted (Perimeter
   2). Trust-anchor changes go through the dangerous tier or an out-of-band
   review.
6. The audit ledger lives off the failsafe host, on the operator's device.

## The failsafe host

Admin access is needed most during incidents, and most incidents are on the
hypervisor side. An approval path that depended on the hypervisor would fail
exactly when needed, so the daemon runs outside it. A NAS was rejected for
the job: vendor-customized, updated on the vendor's schedule, and not
rebuildable from a repository.

- **Hardware:** a small machine with a TPM 2.0 (confirm it exists), and the
  one least experimented on in the house.
- **Software:** a stable Linux with Docker Compose, nothing more. Not a
  cluster node, since that ties it to the failure domain it must stand
  outside. Rebuildable from a repository plus a netboot or preseed install.
- **CA key at rest:** LUKS with the key sealed to the TPM. The box boots
  unattended, but a stolen disk, or an altered boot chain, unseals nothing.
- **What else may run here:** only services needed during incidents,
  independent of what they watch, and rarely changed. "Critical" is not the
  test; a box that collects workloads stops being a failsafe.
- **Dead-man monitoring:** the box pings an external service, so the alert
  that it died depends on nothing in the house. It is on the UPS.
- **Failure means "no escalations until it is back".** The safe tier does not
  depend on it.
- **Optional failover pair:** two identical boxes behind a floating address,
  CA keys copied once and sealed on each. The daemon shares no state, so the
  simplest HA tool works, and split-brain is harmless because both nodes need
  the same device signature. The minimal alternative is a cold spare and a
  rehearsed rebuild.

## The approver

Device binding needs a credential that exists only on the operator's device.
Three ways, in the order to build them:

1. **A web approve page over a VPN.** The scope, nonce, window, match code and
   limits are all enforced by the server, so this delivers most of the value.
   Device binding comes from a client certificate on the phone, or from:
2. **A hardware security key on that page.** WebAuthn with a security key is
   bound to the device, never syncs, and needs no app. (Synced passkeys are
   rejected because the credential also appears on the agent's machine.) The
   key signs a challenge derived from the scope and nonce.
3. **A native app with a hardware-backed key,** if 1 and 2 prove clumsy. The
   key cannot be exported and needs biometrics for every signature, and a
   purpose-built screen keeps approval pleasant enough to survive; bad UX is
   how the original prompts died. It is the slowest path: app review may
   reject an app whose backend is a private host, and only store builds do not
   expire mid-incident.

shoephone has 2 and 3: the daemon's page accepts a hardware key, and the iOS
app `shoephone-app` keeps its key in the Secure Enclave behind Face ID.

Two rules hold for every approver:

- **Enrollment is human-only,** through a one-time code minted at the
  failsafe host's console. Registering an approver is escalation material.
- **Test approval on cellular early.** If it fails half the time, approvals
  rot the way the old prompts did.

## Reachability

The approval path usually still runs through the home router and ISP, so an
outage there blocks approvals. That fails closed, which is the right
direction. The in-person fallback is the failsafe host's console, which can
mint an emergency certificate.

If the VPN proves clumsy, expose the approve API through an outbound-only
tunnel service. This is safe only because the signature covers scope and
nonce: the tunnel provider, or anyone with a stolen tunnel credential, can at
worst block approvals or show a request the phone will not sign, never forge
one. It does not help when the ISP is down.

## Non-Linux platforms

| Platform | Safe tier | Dangerous tier |
|---|---|---|
| Hypervisor | `agent` user as on VMs, optionally plus a read-only API token | `agent-admin` via a host-scoped certificate, or short-lived API tokens the daemon mints on the same approval |
| Network controller | an existing read-only account | the write API key, moved out of the token-readable vault, used only with an explicit confirmation flag and a harness prompt |
| NAS | a read-mostly local user | human-only; it is the data plane |

## Later: a command filter

The sudoers allowlist is the command filter: boring and predictable. A
smarter one would go in a `ForceCommand` wrapper on the safe-tier account,
logging every command (useful from day one) and checking it. Nothing else
changes. A filter you cannot predict is one you will fight.

## Build order

0. **Close the perimeters:** the backup server append-only with per-client
   credentials first (irreversible, and free today), then the vault split,
   then every other unattended path. Nothing else ships first.
1. **Safe tier:** the key, the `agent` user and groups, sudoers, the ssh
   `Match` block, the wrapper and its allowlist. Record what the account can
   read.
2. **Failsafe host:** TPM-sealed LUKS, no agent account, dead-man check, UPS,
   the host CA and its `@cert-authority` line.
3. **Dangerous tier with the web page:** the user CA, the daemon, the page,
   the match code, windows and short certificates, the rate cap and
   cooldown, the kill switch, the ledger, per-host principals and the
   `Match User` block, the CLI, tested on cellular. Make the apply step and
   trust-anchor edits dangerous-tier.
4. **A better approver,** a hardware key or an app, after living with step 3.
5. **Optional:** a failover pair, or a cold spare and a rebuild runbook.

## What this deliberately does not do

- It does not make the agent's machine trustworthy. It assumes that machine
  is compromised as far as the agent's privileges reach, and stops it there.
- It does not filter safe-tier commands beyond sudoers.
- It does not replace the operator's own keys and accounts; the agent's sit
  beside them.
- It does not approve from an Apple Watch. watchOS has no biometric check
  (`LAPolicyDeviceOwnerAuthenticationWithBiometrics` is unavailable there),
  and wrist detection proves only that the watch stayed on a wrist since
  unlock. A wrist tap is exactly the reflexive gesture the tiers exist to
  avoid, and a watch screen would truncate the host, window and reason. The
  watch still shows the "request waiting" notification; approval happens on
  the phone.
