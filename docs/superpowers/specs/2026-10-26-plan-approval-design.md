<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# Plan approval: one phone tap applies one Terraform plan

Status: design, 2026-10-26. Not built. Decisions marked **(operator)** were
made by the operator on 2026-10-26; decisions marked **(builder's call)** are
the author's defaults and may be changed in review.

## Terms

- **Plan** — the output of `terraform plan -out FILE`: a saved, exact list of
  the changes Terraform would make. `terraform apply FILE` applies that list
  and nothing else, and refuses if the state changed since the plan was made.
- **Runner** — a new, single-purpose host (or guest) that holds the
  credentials Terraform needs and is the only place Terraform runs. It is not
  the daemon's host and has no agent account.
- **Project** — one Terraform root module the runner knows by name, with its
  working directory, credentials and allowed providers fixed in the runner's
  own configuration, not in the repository.
- **Provider** — a Terraform plugin binary (Proxmox, Cloudflare, 1Password)
  that talks to an API. It runs with the credentials loaded.
- **Bundle** — a `git bundle` of one commit, which the CLI uploads so the
  runner can check out exactly that commit without the agent pushing.
- **Enforced scope** — what the approver's signature covers. Today it is
  host, principal and window; for an apply grant it is project, commit and
  plan digest (below).

The rest of shoephone's vocabulary is in [DESIGN.md](../../DESIGN.md) → Terms.

## Why

An agent session can prepare a Terraform change but cannot apply it: the
credentials Terraform needs (hypervisor API, DNS provider, the secrets store
Terraform reads from, the state database) sit in a store no agent identity
can read, by design. So every apply is a command handed to the operator to
paste. The operator wants the agent to apply after one phone approval, for
any Terraform project, not only the first consumer.

shoephone's existing grant, an SSH certificate for a time window, is the wrong
shape for this. If the agent gets a shell on a host that holds Terraform's
credentials, it can read them during the window and keep them afterwards, so
the window bounds nothing. And DESIGN.md's Perimeter 2 already says an apply
needs human approval of the change, not of a time slot.

## Goals

1. One phone approval applies one specific, already-computed plan.
2. The agent never holds, and cannot read, any credential Terraform uses.
3. Generic: any Terraform project the runner is configured for, with no
   per-project code in shoephone.
4. What the approver sees is computed by the runner, not described by the
   agent.
5. Every step reaches the approver's devices and the ledger, as every SSH
   grant event does today.

## Non-goals

- Ansible, or anything else over SSH. The existing SSH grant covers that.
- Reviewing the change's *intent*. The approver sees what will change; the
  runner's policy check (below) is what keeps agent-written code from
  leaking credentials, whether or not the approver reads the diff.
- Running Terraform on the agent's machine with borrowed credentials.
- Minting short-lived provider tokens. Rejected **(operator)**: it cannot
  cover every credential Terraform reads, and it would put credentials in the
  daemon.

## Anti-goals (this fails even if it works)

- Any path where a credential reaches the agent: in plan output, in an error
  message, in a log the agent can read, or through a network request from
  agent-written code.
- Any approval whose screen text came from the agent rather than the runner.
- The daemon holding a credential to anything it gates.
- An approval that applies something other than the plan shown.

## Decisions

| Question | Decision |
|---|---|
| What an approval authorizes | **(operator)** One saved plan, identified by its digest, for one commit of one project. Not a window. |
| Plan-time code | **(operator)** The runner refuses configurations that can run code or reach the network at plan time, and its firewall allows only the APIs the project needs. See Policy check. |
| Where Terraform runs | **(operator)** A new dedicated runner. Nothing else runs there and no agent account exists on it. Root on it means every credential it holds. |
| How the runner gets credentials | **(operator)** Its own secrets-store identity (in the reference deployment, a new 1Password service account) that can read the privileged store, token root-only on the runner. The agent's identity never gains that store. |
| How code reaches the runner | **(builder's call)** The CLI uploads a bundle of HEAD through the daemon. The agent does not have to push, which in several projects needs the operator anyway. The runner checks the bundle's commit id matches the request. |
| Who talks to whom | **(builder's call)** The runner has no inbound ports. It polls the daemon over HTTPS, authenticating with its own ed25519 key named in the daemon's config. The agent talks only to the daemon. |
| Where credentials come from per project | **(builder's call)** Runner configuration only. The repository's own `.env` or wrapper scripts are never read or run: they are agent-editable. |
| Rate cap, cooldown, kill | **(builder's call)** Shared with SSH grants: same per-approver hourly cap, same decline cooldown, `kill <project>` cancels a pending apply. |
| Apply-time leakage | **(operator)** A sensitivity check on the saved plan: a value Terraform tags as sensitive may land only in the project's listed secret destinations. See Sensitivity check. |
| What the agent sees on failure | **(operator)** Terraform's own diagnostics, which already redact sensitive values, behind the runner's masking of every value it resolved. |
| Secrets-store reach | **(operator)** One runner identity reading the whole privileged store. The sensitivity check, not item scoping, keeps looked-up values from leaving. |
| Approvals per apply | **(operator)** One. The runner plans as soon as the agent asks; plan start is recorded and pushed passively. |

## How it works

```
agent CLI ──request + bundle──▶ daemon ◀──poll (signed)── runner
                                  │                          │
                                  │◀── plan summary + digest ┤  checkout, policy check,
                                  │                          │  terraform plan -out
  phone ◀── push: apply waiting ──┤                          │
  phone ── WebAuthn(scope+nonce)─▶│                          │
                                  │── approved(job, digest) ▶│  terraform apply <saved plan>
agent CLI ◀── result ─────────────┤◀── result ───────────────┤
```

1. **Request.** In the project's checkout the agent runs
   `shoephone apply <project> --reason "..."`. The CLI refuses a dirty tree
   (so what is applied is a commit), bundles HEAD, and sends project, commit
   id, reason and bundle to the daemon. The daemon checks the project name
   against its configured list, the rate cap and the cooldown, exactly as for
   a host, and stores the job as pending. It prints a match code, as today.
2. **Plan.** The runner's poll returns the job and the daemon records
   `plan started` (ledger, passive push): credentials are in use from here
   on, before any approval. The runner unpacks the bundle
   into a fresh directory, checks the commit id, runs the policy check, runs
   `terraform init` (no downloads, see below) and `terraform plan -out`, then
   `terraform show -json` on the saved plan, and runs the sensitivity check
   on that JSON (refusal: exit 30, nothing shown to the approver). From the
   JSON it builds the
   **plan summary**: counts of create, update, replace and delete, and the
   list of resource addresses with their action. It posts the summary and the
   SHA-256 of the saved plan file to the daemon, and keeps the file.
3. **Approve.** The daemon pushes "apply waiting" to the approver's devices.
   The enforced scope is `project`, `commit`, `plan_digest`, the counts and
   the address list, as the runner reported them. The approver's WebAuthn
   signature covers that scope and a nonce, through the same server-side
   ceremony snapshot used for SSH grants. The screen shows deletes and
   replacements first and in a warning style.
4. **Apply.** On approval the runner's next poll returns
   `approved(job, plan_digest)`. The runner re-hashes its saved file, refuses
   on a mismatch, and runs `terraform apply` on it. Terraform itself refuses
   a plan whose state has moved on.
5. **Result.** The runner posts success or failure and a sanitized log (see
   What the agent sees). The daemon records it in the ledger, pushes it to
   the devices, and returns it to the waiting CLI.

A job that is not approved within the pending timeout (5 minutes) is a
timeout, counted as a decline, and the runner deletes its saved plan.

## Policy check (runs before `terraform init`)

The repository is agent-written, and Terraform evaluates it with the
credentials loaded. The check refuses, with exit 30, any configuration that:

- uses a resource or data-source **type** not in the project's allowlist.
  The allowlist names types (`proxmox_virtual_environment_vm`,
  `onepassword_item`), not whole providers, because any data source on an
  allowed provider makes API calls with agent-chosen arguments.
  `data "external"`, `data "http"` and `terraform_remote_state` (which reads
  other projects' state with the runner's backend credentials) are never
  allowed;
- contains a `provider` block. The runner writes provider configuration
  itself, as an override file, so the repository cannot redirect an
  endpoint or feed one provider's credential from another's data source;
- calls a provider-defined function (`provider::...`);
- has a `provisioner` block of any kind (`local-exec`, `remote-exec`, `file`);
- calls `nonsensitive(...)` (which can lift a secret into plan output);
- calls `file`, `filebase64`, `templatefile`, `fileset` or similar with a
  path that is not a literal inside the module directory;
- contains a symbolic link anywhere in the checkout;
- sources a module from anywhere but a relative local path;
- declares a backend other than the one in the runner's project config, or
  sets backend options the runner did not provide.

Providers come from a plugin directory on the runner (`-plugin-dir`), pinned
by hash, so `init` never downloads one and a new provider cannot be slipped
in through `.terraform.lock.hcl`.

The runner's egress firewall allows only the endpoints in the project's
config (hypervisor API, DNS API, secrets store, state database) and the
daemon. Even a check that misses something then has nowhere to send it.

**(builder's call)** The check parses HCL with a real parser (the `hcl-edit`
or `hcl-rs` crate), not with regular expressions, and walks every
expression, so a banned function inside a nested block is still found.
JSON-syntax `.tf.json` files are refused.

## Sensitivity check (runs on the saved plan, before the approver sees it)

The policy check limits which constructs the code may use; it cannot follow
where a value goes. At apply time, agent code using only allowed types could
copy a secret into something the agent can later read: a DNS TXT record, a
VM description, a store item in an agent-readable vault.

Terraform already tracks this. A value from a sensitive source (a provider
attribute its schema marks sensitive, a `sensitive = true` variable) stays
tagged through expressions and functions, `base64encode` and `substr`
included, and `terraform show -json` reports the tag per attribute in
`after_sensitive`. `nonsensitive()` is the only way to drop the tag, and the
policy check bans it.

So the runner refuses, with exit 30, any plan in which a sensitive value
appears in an attribute that is not on the project's **secret destinations**
list. Each entry is a resource type, an attribute path, and optionally fixed
values for sibling attributes, for example "a VM's cloud-init user data", or
"`onepassword_item.password`, only when `vault` is the privileged store's
id". The same rule covers outputs: a sensitive output is refused unless
listed.

Two limits the builder must handle:

- **Untagged secret fields.** A provider schema can forget to mark a secret
  field sensitive. Before a provider type goes on an allowlist, its schema
  (`terraform providers schema -json`) is reviewed, and the runner's project
  config can mark extra attributes as sensitive, which the runner enforces
  itself.
- **Secrets that are not Terraform values.** Credentials the runner injects
  as provider configuration never enter the plan. Ones it passes as
  variables are declared `sensitive = true` by the runner's override file,
  whatever the repository says.

## What the agent sees

The CLI returns the plan summary (actions and addresses), Terraform's own
diagnostics on failure **(operator)**, and the apply result. It never returns
the raw plan or the state. Terraform already prints `(sensitive value)` in
place of tagged values in diagnostics; behind that, the runner masks every
value it resolved for the job, in plain, base64 and hex form. The remaining
exposure is a provider error that echoes an untagged API response; that is
accepted.

Resource addresses are agent-chosen and can carry a value through a
`for_each` key. The sensitivity check covers tagged values (Terraform
refuses sensitive `for_each` keys outright); untagged ones are not secrets.

## Command line

```bash
shoephone apply <project> --reason "..."   # request, wait, apply on approval
shoephone status                           # also lists pending apply jobs
shoephone kill <project>                   # cancel a pending apply (daemon side)
```

Exit codes use the existing bands: 0 applied; 12 declined or timed out; 20
another request pending; 23 cooldown or cap; 30 unknown project or a policy
refusal (the request must change). Two new tool-specific codes
**(builder's call)**, to be recorded in AGENTS.md: **100** the plan failed
(Terraform error; nothing was shown to the approver), **101** the apply
failed after approval (state may be partly changed; read the result before
retrying).

## Daemon changes

- A second grant kind, `apply`, beside the SSH window, in the same state
  machine: pending → planned → approved/declined/timed out → applied/failed.
  The approver's cap counts both kinds.
- Config: `[runners.<name>]` with the runner's public key, and
  `[projects.<name>]` naming which runner serves it.
- Endpoints for the runner (poll, post plan, post result), each request
  signed with the runner's key. The agent-side endpoints stay
  unauthenticated as today; the bundle upload has a size cap.
- Ledger and push: new events `apply requested`, `plan started`,
  `plan refused` (a policy or sensitivity refusal, or a Terraform error),
  `apply waiting` (the one that interrupts), `applied`, `apply failed`, plus
  the existing declined and timed out. Every event before `apply waiting` is
  passive. `server::push_for` stays an exhaustive match.
- The daemon holds no credential: it relays bundles and summaries only.

## The runner

A separate binary, `shoephone-runner`, in this repository, split across two
unprivileged users so that Terraform can never read the secrets token:

- **The resolver** (`shoephone-runner` itself) holds the token, talks to the
  daemon, runs both checks, resolves the project's secret references, and
  starts Terraform with the resolved values in its environment and the
  generated override files beside the checkout.
- **The Terraform user** owns only the job directory, cannot read the token,
  the runner's config, or other jobs' directories, and is the only identity
  the egress firewall lets reach the project's APIs. Terraform runs under a
  filesystem sandbox (`bubblewrap` or systemd's `ProtectSystem`/`ReadWritePaths`;
  builder's call) that exposes the job directory, the plugin directory and
  nothing of the runner's own state.

The token reaches every privileged credential, not one project's, so this
split matters more than any single policy rule.

Configuration per project: name, path inside the repository, Terraform
version, backend config, provider configuration (written as the override
file), the secret references it resolves, the type allowlist, the secret
destinations, extra sensitive attributes, and the egress list. Each job runs
in a fresh directory that is deleted afterward.

## Approver changes

The web approve page and the iOS app (`shoephone-app`) render the new scope
kind: project, short commit id, counts, the address list with destructive
actions first, and the agent's reason labeled as the agent's. The binding is
daemon-side, so the app needs display changes only.

## Security invariants this keeps

- The approver sees scope computed by a trusted party (the runner), never the
  request's prose as scope.
- The signature covers the scope and a nonce.
- Rate cap and cooldown are per approver, not per requester.
- The daemon holds no credential to what it gates.
- Every event reaches the approver's devices.

New invariant, for AGENTS.md: **an apply grant applies only the saved plan
whose digest the approver signed, and the runner never executes anything
from the repository except Terraform configuration that passed the policy
check.**

## Left to the deployment (operator's infrastructure repo)

The runner guest, its firewall, its secrets identity and which store items it
may read, the provider plugin directory, the project list (the first two are
the first consumer's Terraform and the infrastructure repo's own), and the
amendment to the vault-split design that records the new identity.

## Accepted risks

- Plan-time code runs with credentials before any approval. Guarded by the
  policy check, the process split, the sandbox and the egress firewall, and
  recorded as `plan started`.
- A provider bug or an untagged secret field the schema review missed.
- One runner identity reads the whole privileged store, so a compromise of
  the runner's resolver is a compromise of every credential in it.
- A few bits per run leak through counts and success or failure.

## Open questions

None. The builder review of 2026-10-26 raised six; the operator answered
four (apply-time leakage, diagnostics, store reach, approvals per apply) and
the rest are settled above as builder's calls (process split, provider
blocks and type allowlist, plan start as an audit event).
