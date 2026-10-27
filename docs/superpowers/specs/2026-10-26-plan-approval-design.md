<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# Plan approval: an agent applies Terraform after one phone tap

Status: built, 2026-10-26. Revised the same day after an outside review (see
Review history); corrected afterward to match what was built (see Changes
during the build). Decisions marked **(operator)** were made by the
operator; **(builder's call)** marks the author's defaults, open to change in
review.

## Terms

- **Plan**: the output of `terraform plan -out FILE`. It is a saved, exact
  list of changes. `terraform apply FILE` applies that list and nothing else,
  and refuses if the state has changed since the plan was made.
- **Runner**: a new single-purpose host that holds the credentials Terraform
  needs and is the only place Terraform runs. It is not the daemon's host and
  has no agent account.
- **Project**: one Terraform root module that the runner knows by name.
- **Trusted revision**: the one commit of a project that the operator has
  reviewed and authorized to run with credentials. Each project has at most
  one at a time.
- **Execution input**: every file the runner gives Terraform for a project:
  `.tf` files, local modules, templates, cloud-init assets, any file the
  configuration reads, the dependency lock file, and file modes.
- **Manifest**: the values the agent supplies for an apply. It holds data
  only, never code, and is checked against the schema.
- **Schema**: the declared agent-settable variables, each with a type and a
  constraint. It is part of the trusted revision, so the operator authorizes
  it together with the code.
- **Protected credential**: a secret the runner uses to act: hypervisor,
  DNS, secrets store, state database. It must never reach the agent.
- **Released secret**: a runtime secret the trusted code deliberately places
  on a machine the agent may administer, such as a service token in a VM's
  cloud-init. Placing it there discloses it to that machine's administrators.
- **Archive**: a gzip tar from `git archive` of HEAD (tracked files, no
  history), which the CLI uploads so that the agent does not have to push.

The rest of shoephone's vocabulary is in [DESIGN.md](../../DESIGN.md) → Terms.

## Why

An agent session can prepare a Terraform change but cannot apply it. The
credentials Terraform needs are in a store no agent identity can read, by
design, so every apply is a command handed to the operator to paste. The
operator wants the agent to apply after a phone approval, for any Terraform
project.

Two shapes were rejected:

- **An SSH window to a host that holds the credentials.** The agent could
  read the credentials during the window and keep them afterward.
- **Running agent-written Terraform beside the credentials, guarded by
  automated checks.** The first version of this design did that. An outside
  review found four independent ways for agent code to leak a credential
  past every check (Review history). Terraform evaluates code with the
  credentials loaded, and no syntax filter is a boundary against that.

The rule this design follows instead: **the agent supplies data, never code,
to anything that holds credentials.** Code runs with credentials only after
the operator has reviewed it.

## Goals

1. One phone approval applies one specific, already-computed plan.
2. The agent never holds or reads a protected credential.
3. Generic: any Terraform project the runner is configured for, with no
   per-project code in shoephone.
4. Everything the approver sees is computed by the runner, not described by
   the agent.
5. Every step reaches the approver's devices and the ledger.

## Non-goals

- Ansible, or anything else over SSH. The existing SSH grant covers that.
- Running unreviewed agent-written code with credentials, in any form.
- Releasing a secret onto a host as its own action. Deferred; see Later.

## Anti-goals (this fails even if it works)

- A protected credential reaching the agent through plan output, an error
  message, a log, the ledger, an address, or a network request.
- An approval whose screen text came from the agent rather than the runner.
- The daemon holding a credential to anything it gates.
- An approval that applies something other than the plan shown.
- A trust approval that becomes a reflex. It must stay rare and look
  different from an apply approval.

## Decisions

| Question | Decision |
|---|---|
| What authorizes code | **(operator)** A *trust* approval. The operator reads the full diff of the execution input against the current trusted revision and signs its digest. The reading happens on the approve page for small diffs, and elsewhere for large ones. |
| What authorizes a change | **(operator)** An *apply* approval of one saved plan, by digest, computed from the trusted revision and a validated manifest. |
| Agent-written code | **(operator)** Never runs with credentials until a trust approval covers it. |
| Errors the agent sees | **(operator)** Runner-defined categories, resource addresses from the trusted code, and messages the runner explicitly vetted. Never Terraform's or a provider's own text: even its one-line summary can carry a raw API error. |
| Full errors | **(operator)** Stay on the runner. The operator reads them over their own SSH session. They never pass through the daemon. |
| Secret-install action | **(operator)** Deferred until after v1. |
| Where Terraform runs | **(operator)** A dedicated runner with no agent account. Root on it means every credential it holds. **(builder's call)** Its only inbound service is SSH for the operator: the operator's own key, not trusted from shoephone's user CA, and a firewall that admits only the operator's machines. The runner reaches the daemon by polling it. |
| Runner credentials | **(operator)** Its own secrets-store identity, which can read the privileged store. The token is readable by root only. The agent's identity never gains that store. |
| Approvals per apply | **(operator)** One. Planning starts as soon as the agent asks; plan start is recorded and pushed silently. |
| Delete and replace | **(builder's call)** Refused unless the request asks for them. When the runner's plan contains either, the phone shows a distinct, warning-style approval. The runner decides the classification from the plan and binds it into the scope. |
| Concurrency | **(builder's call)** One active job across all projects in v1. |
| Rate cap, cooldown, kill | **(builder's call)** Shared with SSH grants and counted per approver. |

## Trust: authorizing code

```bash
shoephone trust <project> --reason "..."
```

1. The CLI refuses uncommitted changes to tracked files, archives HEAD and
   uploads it with the reason.
2. A **credential-free review worker** on the runner unpacks the archive. It
   computes the full diff of the execution input against the current trusted
   revision, or the full content if this is the first one, and records any
   change to the schema. It also lists the warnings described below. It
   never runs Terraform on the candidate.
3. The trust scope is: project, baseline revision digest, candidate digest,
   diff digest, schema digest, and trust-policy version. The approve page
   shows the diff in full when it fits under a size limit. When it does not,
   the page shows only the digests and a command for the operator to run in
   their own checkout, which prints the same diff digest. The page never
   shows a truncated diff. The phone shows a short summary (files changed,
   lines added and removed, schema changed or not) in a style unlike an
   apply approval.
4. On approval the candidate becomes the one trusted revision, and the
   previous one stops being runnable. A trust review whose baseline has
   changed since it was computed is refused as stale. `shoephoned untrust
   <project>`, at the daemon's console, leaves a project with none.

**The reviewer's obligation**, printed at the top of every trust review:

> For every manifest the schema accepts, protected credentials may reach only
> their provider authentication and the approved destinations, and nothing
> the agent can see (results, addresses, which actions run) may reveal them.

That obligation is about what agent-settable values can steer, not only
about their types. Examples of trusted code that would fail it: an
agent-settable item id fed to a secrets-store lookup; an agent-settable file
path given to a resource that reads local files; an agent-settable pattern
matched against a secret; `count` or a condition that compares a secret with
an agent-settable value; an agent-settable VM or disk id that could select
the runner itself.

Non-local module sources are refused outright in v1, not flagged: Terraform
would download them at execution time, outside the reviewed digest. A later
version could instead vendor their exact contents into the execution input.

The review worker flags constructs that make the obligation hard to meet:
provisioners, `external` and `http` data sources, `import` blocks,
`nonsensitive()`, provider-defined functions, symlinks,
and any schema variable that reaches a secrets-store selector, a file path,
`count`, `for_each` or a condition. These are warnings for the reviewer, not
a boundary. **(builder's call)**

## Apply: authorizing a change

```bash
shoephone apply <project> --manifest FILE --reason "..." [--allow-destroy]
```

1. **Request.** The CLI sends the project, the manifest and the reason. The
   daemon checks the project, the rate cap and the cooldown, and stores a
   pending job.
2. **Validate.** The runner checks the manifest against the trusted
   revision's schema. It refuses unknown variables, duplicate keys, implicit
   type coercion, values outside their constraint, and oversized
   collections. Each agent-settable variable must be given, unless the
   schema states its default. Constraints favor choosing from an
   operator-owned map (an image name, a size class) over free strings. The
   manifest becomes the only source of agent-settable values. The runner
   refuses a checkout containing `terraform.tfvars`, `terraform.tfvars.json`,
   `*.auto.tfvars` or `*.auto.tfvars.json`, and it clears `TF_VAR_*` from the
   environment, except for values it supplies itself from the project's
   config. The schema's variables and the runner-supplied variables must not
   overlap. Both the trust review and each apply check this.
3. **Plan.** The daemon records `plan started`, with a silent push. The
   worker runs `terraform plan -out` at the trusted revision with the
   manifest, then runs `terraform show -json` and builds the summary: the
   variable diff against the last *successfully applied* manifest, counts of
   create, update, replace and delete, and the address list. Replace means
   either action order. If the plan contains delete or replace and the
   request did not ask for them, the job stops with exit 30. After a failed
   or unknown-outcome apply, the summary says the baseline is uncertain
   instead of showing a clean diff.
4. **Approve.** The daemon pushes `apply waiting`. The scope is: project,
   trusted revision digest, schema digest, manifest digest, **baseline
   manifest digest and baseline status** (`applied` or `uncertain`), plan
   digest, the destructive classification, the counts and the address
   list. The signature covers the scope and a nonce, through the existing
   server-side ceremony snapshot. The approver clients receive both
   manifests, check each against its signed digest, and compute the
   variable diff themselves. That way the diff on screen follows from
   signed fields and is not a separate claim. The screen shows that diff
   first, then deletes and replaces.
5. **Apply.** The runner claims the approval once (atomically, with a durable
   record written before Terraform starts), re-hashes the saved plan, and
   applies it.
6. **Result.** The result is applied, failed, or *outcome unknown* (the
   runner restarted mid-apply). It goes to the ledger, the devices and the
   CLI. Nothing is retried automatically.

The agent receives: the variable diff, the counts and addresses, the
classification, the result, and on failure a category plus vetted messages.

## Protocol rules

- **Frozen scope.** The daemon accepts a plan only from the runner assigned
  to the job, in the expected state. Once an approval ceremony starts,
  neither the digest nor the summary can change. A new plan needs a new
  approval.
- **Signed runner messages.** Each message is signed with the runner's key
  over protocol version, method, path, body digest, job id and a freshness
  value (timestamp plus nonce, checked by the daemon), so a captured message
  cannot be replayed.
- **Single-use approvals.** A poll never hands out the same executable
  approval twice. The claim is a state transition.
- **Cancellation.** `kill <project>` stops a pending or planning job, drops
  any late plan report, and voids an approval that has not been claimed. An
  apply that has already started runs to its end; there is no rollback.
- **Timeouts.** These are separate: planning (default 10 minutes), approval
  (5 minutes from `apply waiting`), and maximum plan age before the claim.
  The existing pending timer starts when a request is created, which is too
  early for this.
- **Pinned context.** A pending approval is void if the runner's policy, its
  provider binaries, the backend identity or the project config changed
  after the plan was made.
- **Bounded input.** The archive is limited in compressed size, unpacked size,
  file count, path length (255 characters) and processing time. The runner refuses
  `.terraform/`, state files, plan files and a root `.git` inside it.

## The runner

`shoephone-runner`, a separate binary in this repository. Its parts, each a
separate Unix user:

- **The resolver** holds the secrets token, talks to the daemon, and starts
  the other two. It resolves the project's secret references and passes the
  values to the Terraform worker's environment. It also re-reviews every
  trust itself (see Changes during the build).
- **The review worker** has no credentials. It unpacks archives, computes
  trust diffs and validates manifests.
- **The Terraform worker** owns only the job directory. It cannot read the
  token, the runner's config, or other jobs, and it runs in a filesystem
  sandbox that exposes only the job directory and the plugin directory.

Providers come from a plugin directory pinned by hash, so `init` downloads
nothing. The egress firewall allows only the project's endpoints (HTTPS, or
SSH where a provider uploads files that way) and the daemon. With trusted
code these are defense in depth, not the boundary. There are no pre-plan
hooks.

Full Terraform output stays in a root-only log directory on the runner, kept
for a set number of days. The operator reads it over their own SSH session.

Terraform sees only the execution-input files: the trusted tree and every
run contain nothing else, so a read outside them fails the plan.

Per-project configuration: name, path in the repository, Terraform version,
backend, the secret references it resolves, the endpoints, and the Terraform
variables it supplies itself.

## Daemon changes

- Two new grant kinds, `trust` and `apply`, in the same state machine as SSH
  grants. They share the approver's cap and cooldown, and only one request
  of any kind is pending at a time.
- Config: `[runners.<name>]` (the runner's public key) and
  `[projects.<name>]` (which runner serves the project).
- Signed runner endpoints: poll, post review, post plan, claim, post result.
  The agent-side endpoints stay unauthenticated as they are today, with a
  size cap on archives.
- Ledger and push: `trust requested`, `trust waiting`, `trusted`,
  `apply requested`, `plan started`, `plan refused`, `apply waiting`,
  `applied`, `apply failed`, `outcome unknown`, plus the existing declined
  and timed out. Only the two `waiting` events interrupt. `server::push_for`
  stays an exhaustive match.
- The ledger and `/api/pending` have no read authentication today. So
  nothing that could hold a credential may go into them: categories and
  digests only. Full output stays on the runner.
- The daemon holds no credential. It relays archives, manifests, summaries
  and digests only.

## Approver changes

These are more than display changes. The approve page (`assets/approve.html`)
and the iOS app rebuild the scope bytes themselves and check them against the
challenge hash. Both need a versioned encoding for the trust and apply
scopes, a verification path for each, and the screens described above, so
that a trust approval looks unlike an apply approval.

## Command line

```bash
shoephone trust <project> --reason "..."
shoephone apply <project> --manifest FILE --reason "..." [--allow-destroy]
shoephone status        # also lists trust and apply jobs
```

Exit codes use the existing bands: 0 done; 12 declined or timed out; 20
another request pending; 23 cooldown or cap; 30 unknown project, manifest
refused, no trusted revision, or an unrequested delete or replace. New
tool-specific codes **(builder's call)**, to be recorded in AGENTS.md: **100**
plan failed; **101** apply failed after approval (state may be partly
changed); **102** outcome unknown (check before doing anything else).

## Security invariants this adds

For AGENTS.md:

- Terraform runs with credentials only at a project's one trusted revision,
  and only with a manifest that passed that revision's schema.
- An apply grant applies only the saved plan whose digest the approver
  signed, at most once.
- Nothing that can hold a credential is returned to the agent or written to
  the daemon's ledger.

## Later: releasing a secret onto a host

The first consumer has a playbook that copies two privileged items into
root-only files on a VM and restarts the services that use them, at first
build and on rotation. It could become an operator-defined runner action
that the agent requests by name and the operator approves with one tap.
Deferred **(operator)**. The conditions, so they are not lost:

- A secret installed on a host the agent administers is disclosed to the
  agent. File mode 0600 does not stop root. The action is a release, and
  only items meant for that host may be named. Never a protected credential.
- An immutable definition: item and field, host identity, path, owner and
  mode, the exact restart. The approval is bound to the definition's
  digest, not its name.
- No agent-supplied arguments. Strict host-key checking and no agent
  forwarding. Installs that do not follow symlinks. Remote output treated
  as untrusted. Stated semantics for partial failure.

## Left to the deployment (operator's infrastructure repo)

The runner guest and its firewall, its secrets identity, the plugin
directory, the project list, the first trust review of each project, and the
amendment to the vault-split design that records the new identity.

## Accepted risks

- Plan-time code runs with credentials before the apply approval. It is
  trusted code with validated input, and `plan started` records it.
- The reviewer misses something in a trust review. The obligation statement,
  the warnings, and the rule against truncated diffs are the mitigation.
- One runner identity reads the whole privileged store, so a compromise of
  the resolver is a compromise of every credential in it.
- A few bits per run leak through counts and success or failure.

## Review history

- **Builder check, 2026-10-26.** Six gaps in the first version: the process
  split, provider blocks, type allowlists, plan start as an audit event,
  apply-time leakage, and diagnostics. Answered at the time. Most are moot
  now that agent code does not run with credentials.
- **Outside review (Codex), 2026-10-26.** The first version ran agent-written
  HCL behind a policy check, a sensitivity-tag check, and static tracing of
  where each secret came from. Bypasses found, each confirmed against
  Terraform and provider source:
  a malformed `regex()` echoes its pattern, an encoded secret, in the
  diagnostic; Terraform accepts a sensitive `count` and drops the tag, so
  addresses spell out a secret; `proxmox_virtual_environment_file.source_file`
  reads a local path in the provider, past any `file()` ban; an `import`
  block can launder a privileged value into `random_password.result`, and a
  permitted data-source address can be pointed at any item. The review also
  supplied the protocol rules above and the "more than display changes"
  correction. The operator then chose trusted code with data-only applies,
  full errors kept on the runner, and deferral of the secret action. On the
  confirm round Codex objected to one blocking gap: the displayed variable
  diff was not bound into the signed scope. It is now derived by the clients
  from both signed manifest digests. Three builder-level items were also
  fixed: non-local modules refused, the `.json` tfvars variants refused, and
  operator SSH ingress specified.

## Changes during the build

Each item is a place where the built system differs from the text above, and
why.

- **Archive, not bundle.** The upload is a gzip tar from `git archive` of
  HEAD. A tar has no object graph to bound and carries no history. `trust`
  refuses only tracked changes, since untracked files never reach the archive,
  and refuses an archive over 16 MiB compressed.
- **Execution input is all Terraform sees.** The trusted tree and every
  Terraform run hold only the execution-input files (the project directory and
  its local module directories), so a read outside them fails the plan
  instead of running unreviewed content. A file the configuration reads must
  live in a module directory.
- **Archive limits.** Paths are limited to 255 characters, and a root `.git`
  entry is refused, since `git archive` never emits one.
- **Exact variable comparison.** The approve page compares each variable's raw
  canonical text, never a reparsed number, so an unchanged value cannot look
  changed. Integers beyond 2^53-1 and non-finite numbers are refused in a
  manifest.
- **Trust diff format.** Files are separated by `diff --git` lines, and a path
  with a space, double quote or backslash is quoted in git's C-style form on
  every header line.
- **Operator verification command.** The command is `shoephone-runner
  diff-digest <baseline-digest|none> <baseline-checkout|-> <candidate-checkout>
  <project-path>`, run on clean exports. A digest alone cannot rebuild the
  baseline tree, so the command takes the baseline checkout and refuses unless
  it matches the digest.
- **Root parses repository content.** The design had the resolver never parse
  repository content. As built, root unpacks each trust archive itself, scans
  the HCL for local modules and recomputes the diff, and refuses
  `review_inconsistent` on any mismatch with the review worker, both at
  submit and again at install. This is a deliberate deviation: otherwise a
  compromised worker could forge the diff the operator approves. The parsers
  are memory-safe Rust under the same size, file-count and time limits.
- **Authenticated daemon channel.** The runner refuses a daemon URL that is
  not `https://`, except loopback, because it acts on the daemon's replies.
- **Claim lapse.** A claimed job the daemon never hears from is recorded as
  `outcome_unknown` after `claim_ttl` (default 3 hours), which frees the
  one-job slot. The runner journals every claim and result and re-sends them
  at startup.
- **Outputs count like resources.** Output changes appear as `output.<name>`
  addresses and count toward the totals and the destructive flag, so one
  counting rule serves the runner, the daemon and the page. Removing an
  output needs `--allow-destroy`.
- **Unknown plan actions refuse.** A plan action list the runner does not
  recognize fails the plan (`plan_unknown_action`) rather than passing unseen.
- **Reviewer warnings are shown, unsigned.** The warnings appear on the trust
  screen, labeled as unsigned runner findings and capped at 200, because they
  are advisory and not part of the signed scope.
- **Test-hooks start guard.** Both binaries built with `test-hooks` refuse to
  start unless an explicit variable is set, so a deployed build cannot carry
  the test routes or the no-sandbox path by accident.
