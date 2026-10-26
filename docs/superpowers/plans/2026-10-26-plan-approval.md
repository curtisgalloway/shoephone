<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# Plan Approval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An agent session applies Terraform after one phone approval, without ever holding a credential. Terraform code runs only at a revision the operator trusted, with a data-only manifest.

**Architecture:** Two new grant kinds, `trust` and `apply`, live in a new pure state machine (`src/job.rs`). It shares the rate cap, the cooldown and the one-pending slot with SSH grants through a `Gate` extracted from `Grants`. A new binary, `shoephone-runner`, polls the daemon with signed requests. It reviews uploaded trees in a credential-free worker, plans and applies in a sandboxed Terraform worker, and keeps credentials in a root resolver that never parses repository content. The approve page and the iOS app check versioned scope bytes, as they already do for SSH scopes.

**Tech Stack:** Rust 2024; axum and tokio (daemon); ureq (CLI and runner client); ssh-key (ed25519 signing for runner messages, already a dependency); `tar` and `flate2` (archive unpack); an HCL parser chosen in Task 11; `similar` (unified diffs); bubblewrap on the runner host.

**Spec:** `docs/superpowers/specs/2026-10-26-plan-approval-design.md` (approved 2026-10-26, commit `4ee81ef`). Read it before any task. Section names below refer to it.

## Global Constraints

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` are clean after every task. Fix warnings; never label one pre-existing.
- Two-line SPDX header on every new file (`// SPDX-FileCopyrightText: 2026 Curtis Galloway` / `// SPDX-License-Identifier: Apache-2.0`), Markdown included.
- No real hostnames, vault names, addresses or secrets anywhere in the repo, fixtures and examples included.
- American spellings.
- Exit codes: under 100 portable (`src/exit.rs`); new codes **100** plan failed, **101** apply failed after approval, **102** outcome unknown. Record each in AGENTS.md under "Tool-specific exit codes".
- Defaults (spec "Protocol rules"): planning timeout **10 min**, approval timeout **5 min from `apply waiting`/`trust waiting`**, maximum plan age before claim **15 min**, one active job across all projects.
- Bundle bounds (builder's call within spec "Bounded input"): **16 MiB** compressed upload, **64 MiB** unpacked, **10,000** files, **60 s** unpack-and-review time.
- `server::push_for` and every `match` on `Event` or `JobEvent` stay exhaustive, with no `_` arm.
- Nothing that can hold a credential goes into the ledger, `/api/pending`, `/api/job/{id}`, or any reply to the agent: categories, digests, addresses and runner-authored strings only.
- Every new dependency gets a `dep-quality` check before it goes into `Cargo.toml`, with the score recorded in the commit message.
- Commit per task: `git add <files>` by name, never `-a`; author `4055365+curtisgalloway@users.noreply.github.com` via `git -c user.email=...`; message ends with the session's Co-Authored-By line.

## Review Focus

1. **Daemon restart while a job is applying.** The runner's journal says the job started and has no result, and the daemon has forgotten the job. Expected: the runner reports `outcome_unknown` for that id, the daemon ledgers it and pushes it, and nothing retries. Owner: Task 15 test `journal_reports_started_job_as_unknown` and Task 7 test `unknown_job_result_is_ledgered_as_outcome_unknown`.
2. **A second tap on an already-claimed approval** (the page is refreshed, or two devices approve). Expected: the second assertion is refused with `NoSuchRequest`, and the runner sees the job exactly once. Owner: Task 3 test `approve_twice_is_refused` and Task 7 test `claim_is_single_use`.
3. **A manifest with a key the schema does not declare, a duplicate key, or `"1"` where a number is expected.** Expected: exit 30 naming the variable, before Terraform starts. Owner: Task 12 tests.
4. **A trust request whose baseline moves** because another trust was approved while this one was being reviewed. Expected: approve is refused as stale, and the CLI exits 30 with "baseline changed". Owner: Task 3 test `trust_with_stale_baseline_is_refused`.
5. **A huge trust diff.** Expected: the page shows only digests and the verification command, never a truncated diff, and the phone summary still shows the file and line counts. Owner: Task 13 test `oversized_diff_is_marked_external` and Task 9 page check.

---

## Phase A — daemon core (pure, no I/O)

### Task 1: Extract the shared gate from `Grants`

**Files:**
- Create: `src/gate.rs`
- Modify: `src/grant.rs` (fields `accepted`, `cooldown_until`, `strikes`, the `pending.is_some()` busy check, `cooldown_after`, `strike_at`), `src/lib.rs`, `src/server.rs` (construction)

**Interfaces:**
- Produces:
  - `pub struct Gate` with `pub fn new() -> Gate`
  - `pub fn admit(&mut self, now: SystemTime, policy: &Policy, occupant: Occupant) -> Result<(), Refusal>`, which checks busy, then cooldown, then the cap (the same order as today), records the acceptance, and occupies the slot
  - `pub fn release(&mut self, occupant: Occupant)`
  - `pub fn strike_at(&mut self, at: SystemTime, policy: &Policy)` and `pub fn approved(&mut self)` (resets strikes and cooldown)
  - `pub fn tick(&mut self, now: SystemTime)` (drops acceptances older than an hour)
  - `pub fn busy(&self) -> Option<Occupant>`
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Occupant { Ssh(u64), Job(u64) }`
  - `Grants` now owns `gate: Gate` and exposes `pub fn gate_mut(&mut self) -> &mut Gate` and `pub fn allocate_id(&mut self) -> u64` (the existing `take_id`, made public for job ids, so ids and serials share one counter).

- [ ] **Step 1:** Move the existing cooldown, cap and busy tests in `grant.rs` that only exercise those rules into `gate.rs` as `Gate` tests, unchanged in their assertions (5, 10, 20, 40, 60-minute cooldowns; the 6-per-hour cap; `Busy` while occupied). Add `job_occupant_blocks_ssh_request`: `gate.admit(t, &p, Occupant::Job(1))` followed by `grants.request(...)` returns `Err(Refusal::Busy)`.
- [ ] **Step 2:** Run `cargo test gate::`. Expect the moved tests to fail to compile.
- [ ] **Step 3:** Implement `Gate`. Make `Grants::request`, `approve`, `decline`, `kill` and `tick` call it. `Grants::tick` releases `Occupant::Ssh(id)` when it times a request out.
- [ ] **Step 4:** Run `cargo test`. Every existing test passes unchanged, apart from the moves.
- [ ] **Step 5:** Commit: "Extract the rate cap, cooldown and pending slot into Gate".

### Task 2: Trust and apply scopes, their signed bytes, and shared vectors

**Files:**
- Create: `src/scope.rs`, `tests/fixtures/job-scope-vectors.json`, `tests/job_vectors.rs`
- Modify: `src/grant.rs` (`bound_challenge` delegates to `challenge_of`), `src/lib.rs`

**Interfaces:**
- Produces:
  - `pub fn challenge_of(bytes: &[u8]) -> [u8; 32]` (SHA-256)
  - `pub struct TrustScope { pub project: String, pub baseline: Option<String>, pub candidate: String, pub diff: String, pub schema: String, pub policy_version: u32, pub files_changed: u32, pub lines_added: u32, pub lines_removed: u32, pub schema_changed: bool }`. Digests are lowercase hex SHA-256.
  - `pub enum BaselineStatus { None, Applied, Uncertain }`, encoded `none` / `applied` / `uncertain`
  - `pub struct Counts { pub create: u32, pub update: u32, pub replace: u32, pub delete: u32 }`
  - `pub struct ApplyScope { pub project: String, pub revision: String, pub schema: String, pub manifest: String, pub baseline_manifest: Option<String>, pub baseline_status: BaselineStatus, pub plan: String, pub destructive: bool, pub counts: Counts, pub addresses: String }`. `addresses` is the digest of the address text defined below.
  - `impl TrustScope { pub fn bytes_to_sign(&self, nonce: &str) -> Vec<u8> }` and the same on `ApplyScope`
  - `pub fn address_text(changes: &[(Action, String)]) -> String`, where `pub enum Action { Create, Update, Replace, Delete }`. One `"{action} {address}\n"` line per change, in the order given. Action words: `create`, `update`, `replace`, `delete`.

The exact formats. Each field is newline-free by construction, and `none` stands for an absent digest:

```
shoephone-trust-v1\nproject=P\nbaseline=D|none\ncandidate=D\ndiff=D\nschema=D\npolicy=N\nfiles=N\nadded=N\nremoved=N\nschema_changed=0|1\nnonce=X\n
shoephone-apply-v1\nproject=P\nrevision=D\nschema=D\nmanifest=D\nbaseline_manifest=D|none\nbaseline_status=S\nplan=D\ndestructive=0|1\ncreate=N\nupdate=N\nreplace=N\ndelete=N\naddresses=D\nnonce=X\n
```

- [ ] **Step 1:** Write `tests/fixtures/job-scope-vectors.json`, mirroring `bound-challenge-vectors.json`'s layout. It holds at least four vectors: a first trust (`baseline` none), a later trust, an apply with `baseline_status` `none`, and an apply that is `uncertain` and destructive. Each records the fields, the nonce, `bytes_to_sign`, `challenge_sha256_hex` and `challenge_base64url`. Compute the expected values once with `printf '...' | shasum -a 256` and paste them in.
- [ ] **Step 2:** Write `tests/job_vectors.rs`: `every_job_vector_matches_this_daemons_derivation` and `job_vectors_are_distinct`, mirroring `tests/vectors.rs`. Add `address_text_is_one_line_per_change` as a unit test in `scope.rs`.
- [ ] **Step 3:** Run `cargo test --test job_vectors`. Expect a compile failure.
- [ ] **Step 4:** Implement `src/scope.rs`.
- [ ] **Step 5:** Run `cargo test`. Expect PASS. The existing SSH vectors still pass.
- [ ] **Step 6:** Commit: "Versioned trust and apply scopes, with shared vectors for the app".

### Task 3: The job state machine

**Files:**
- Create: `src/job.rs`
- Modify: `src/grant.rs` (`Policy` gains `plan_timeout: Duration` = 10 min, `approval_ttl: Duration` = 5 min, `max_plan_age: Duration` = 15 min), `src/config.rs` (`PolicyConfig` gains the three, in minutes), `src/lib.rs`

**Interfaces:**
- Consumes: `Gate`, `Occupant`, `TrustScope`, `ApplyScope`, `Grants::allocate_id`
- Produces:
  - `pub enum JobKind { Trust { archive_sha256: String }, Apply { manifest: String, allow_destroy: bool } }`. For an apply, `manifest` is the agent's raw JSON text, stored as bytes.
  - `pub enum JobState { Queued, Working { runner: String }, Waiting { scope: JobScope, nonce: String, since: SystemTime }, Approved { scope: JobScope }, Claimed, Done(JobResult) }`
  - `pub enum JobScope { Trust(TrustScope), Apply(ApplyScope) }`
  - `pub enum JobResult { Trusted, Applied, Refused(Failure), PlanFailed(Failure), ApplyFailed(Failure), OutcomeUnknown, Declined, TimedOut, Killed }`
  - `pub struct Failure { pub category: String, pub addresses: Vec<String>, pub detail: Option<String> }`. `detail` is runner-authored text only.
  - `pub struct Job { pub id: u64, pub project: String, pub kind: JobKind, pub state: JobState, pub reason: String, pub created: SystemTime, pub match_code: String }`
  - `pub struct Jobs`, with `pub fn new(projects: BTreeMap<String, String>) -> Jobs` (project to runner name)
  - `pub fn request(&mut self, now, gate: &mut Gate, policy: &Policy, entropy: &mut dyn Entropy, id: u64, project: &str, kind: JobKind, reason: &str) -> Result<Job, Refusal>`, which refuses `UnknownProject`, `NoReason`, `Busy` (also when a job is active in any non-`Done` state), `Cooldown` and `RateCapped`
  - `pub fn poll(&mut self, now, runner: &str) -> Option<Job>`, which moves a `Queued` job for that runner to `Working` and returns it, or returns an `Approved` job without changing it
  - `pub fn submit(&mut self, now, runner: &str, id: u64, scope: JobScope, entropy: &mut dyn Entropy) -> Result<(), Refusal>`, which is accepted only from `Working` by the assigned runner and moves the job to `Waiting` with a fresh nonce. A second submit is refused with `ScopeFrozen`.
  - `pub fn refuse(&mut self, now, runner: &str, id: u64, result: JobResult) -> Result<(), Refusal>`, accepted from `Working` only, for `Refused` and `PlanFailed`
  - `pub fn approve(&mut self, now, gate: &mut Gate, id: u64, nonce: &str, scope: &JobScope) -> Result<(), Refusal>`, which compares the nonce in constant time and the scope by equality, moves the job to `Approved`, calls `gate.approved()`, and releases the slot. For an apply it also refuses when `since` is older than `max_plan_age`.
  - `pub fn decline(&mut self, now, gate: &mut Gate, policy: &Policy, id: u64) -> Result<(), Refusal>`, which strikes
  - `pub fn claim(&mut self, now, runner: &str, id: u64) -> Result<JobScope, Refusal>`: `Approved` to `Claimed` once; the second call is refused with `AlreadyClaimed`
  - `pub fn finish(&mut self, now, runner: &str, id: u64, result: JobResult) -> Result<(), Refusal>`, accepted from `Claimed`, or with `OutcomeUnknown` for an id this instance does not know (recorded as a bare event)
  - `pub fn kill(&mut self, now, gate: &mut Gate, policy: &Policy, project: &str) -> Result<(), Refusal>`. `Queued`, `Working`, `Waiting` and `Approved` go to `Killed`, with a strike when the job was awaiting a verdict. `Claimed` is left alone. A later `submit`, `refuse` or `claim` for a killed id is refused.
  - `pub fn tick(&mut self, now, gate: &mut Gate, policy: &Policy)`: `Queued` or `Working` past `plan_timeout` from `created` becomes `PlanFailed(category "plan_timeout")`, with no strike. `Waiting` past `approval_ttl` from `since` becomes `TimedOut`, with a strike. An `Approved` job older than `max_plan_age` without a claim becomes `TimedOut`, with no strike.
  - `pub fn job(&mut self, now, id: u64) -> Option<&Job>`, `pub fn waiting(&mut self, now) -> Option<&Job>`, `pub fn take_events(&mut self) -> Vec<JobEvent>`
  - `pub enum JobEvent { Requested{id,project,kind,reason,at}, Started{id,project,at}, Waiting{id,project,at}, Approved{id,project,at}, Refused{id,project,category,at}, Applied{id,project,at}, Trusted{id,project,at}, ApplyFailed{id,project,at}, OutcomeUnknown{id,project,at}, Declined{id,project,at}, TimedOut{id,project,at}, Killed{id,project,at} }`, where `kind` is `"trust"` or `"apply"`
  - `Refusal` gains `UnknownProject`, `ScopeFrozen`, `AlreadyClaimed`, `WrongRunner`, `StaleBaseline` and `PlanTooOld`, each with a `Display` line.
- `Jobs` clamps `now` to its own high-water mark, as `Grants::tick` does.

- [ ] **Step 1:** Write the unit tests in `job.rs`, each asserting the state and the events drained:
  - `request_occupies_the_gate`
  - `unknown_project_is_refused`
  - `poll_assigns_only_to_the_projects_runner`
  - `submit_moves_to_waiting_with_fresh_nonce`
  - `second_submit_is_scope_frozen`
  - `approve_with_wrong_nonce_is_refused`
  - `approve_with_changed_scope_is_refused`
  - `approve_twice_is_refused` (the second call returns `NoSuchRequest`)
  - `claim_is_single_use`
  - `kill_voids_unclaimed_approval`
  - `kill_leaves_claimed_job_running`
  - `late_submit_after_kill_is_refused`
  - `planning_timeout_is_plan_failed_without_strike`
  - `approval_timeout_strikes`
  - `approved_but_unclaimed_expires_at_max_plan_age`
  - `apply_plan_older_than_max_age_cannot_be_approved`
  - `finish_unknown_id_with_outcome_unknown_is_recorded`
  - `ssh_request_blocks_job_request`
  - `trust_with_stale_baseline_is_refused`. This last one is driven through `approve` with a `TrustScope` whose `baseline` differs from a `current_trusted` value that `Jobs` holds via `pub fn set_trusted(&mut self, project: &str, digest: Option<String>)`. It refuses with `StaleBaseline`.
- [ ] **Step 2:** Run `cargo test job::`. Expect a compile failure.
- [ ] **Step 3:** Implement `src/job.rs`.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Job state machine for trust and apply grants".

### Task 4: The durable trust registry

**Files:**
- Modify: `src/store.rs` (`trusted.json` in `state_dir`, root-only, mode 0600, written atomically like `save_devices`), `src/bin/shoephoned.rs` (`untrust <project>` console verb), and the `LedgerEntry` `From<&JobEvent>` impl in `src/store.rs`

**Interfaces:**
- Produces:
  - `pub struct TrustRecord { pub project: String, pub digest: String, pub schema: String, pub job: u64, pub at: u64 }`
  - `Store::load_trusted(&self) -> Result<Vec<TrustRecord>, String>`, `Store::save_trusted(&self, records: &[TrustRecord]) -> Result<(), String>`
  - `impl From<&JobEvent> for LedgerEntry`, with `host` set to the project name, `kind` set to `trust_requested`, `trust_waiting`, `trusted`, `apply_requested`, `plan_started`, `plan_refused`, `apply_waiting`, `applied`, `apply_failed` or `outcome_unknown`, plus `declined`, `timed_out` and `killed` as today. `reason` appears on the `*_requested` lines only. The `category` goes in a new optional `category` field.

- [ ] **Step 1:** Tests in `store.rs`:
  - `trusted_round_trips`
  - `trusted_file_is_0600`
  - `untrust_removes_only_that_project`
  - `job_events_map_to_ledger_kinds`, which covers every `JobEvent` variant, so a new variant fails it
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement. `shoephoned untrust <project>` edits `trusted.json` and prints the removed digest. It exits 1 (`Empty`) when there was nothing to remove.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Durable trust registry and ledger lines for job events".

## Phase B — daemon HTTP

### Task 5: Runner identity and signed requests

**Files:**
- Create: `src/runner_auth.rs`
- Modify: `src/config.rs` (`[runners.<name>] public_key = "ssh-ed25519 ..."` and `[projects.<name>] runner = "<name>"`, both `deny_unknown_fields`, with each project's runner required to exist), `src/lib.rs`

**Interfaces:**
- Produces:
  - `pub const SIGNATURE_HEADER: &str = "shoephone-runner-signature"` and `pub const RUNNER_HEADER: &str = "shoephone-runner"`
  - `pub fn canonical(method: &str, path: &str, body: &[u8], job: Option<u64>, timestamp: u64, nonce: &str) -> Vec<u8>`, with the format `shoephone-runner-v1\n{method}\n{path}\n{sha256hex(body)}\n{job|-}\n{timestamp}\n{nonce}\n`
  - `pub fn sign(key: &ssh_key::PrivateKey, message: &[u8]) -> Result<String, String>`: an SSHSIG with namespace `shoephone-runner`, PEM-armored, then base64url so it fits in a header
  - `pub struct Verifier { keys: BTreeMap<String, ssh_key::PublicKey>, seen: VecDeque<(u64, String)> }`
  - `pub fn verify(&mut self, now: SystemTime, runner: &str, signature: &str, message_parts: (&str, &str, &[u8], Option<u64>, u64, &str)) -> Result<(), Refusal>`. It refuses `WrongRunner` for an unknown name or a bad signature, and `Stale` when the timestamp is more than 60 s from `now` or the nonce was already seen within 120 s.

- [ ] **Step 1:** Tests:
  - `signed_request_verifies`
  - `tampered_body_is_refused`
  - `replayed_nonce_is_refused`
  - `old_timestamp_is_refused`
  - `other_runners_key_is_refused`
  - `config_refuses_project_with_unknown_runner`
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement, using `ssh_key::SshSig`, which the crate already provides.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Signed, replay-checked runner requests".

### Task 6: Agent-side endpoints

**Files:**
- Modify: `src/server.rs` (`Inner` gains `jobs: Jobs`, `archives: HashMap<u64, Vec<u8>>`, `verifier: Verifier`), `src/api.rs`, `src/client.rs`

**Interfaces:**
- Produces:
  - `POST /api/trust` with body `TrustBody { project: String, archive: String (base64 of a gzip tar), reason: String, requester: String, context: Option<String> }`, under a body limit of 16 MiB × 4/3 + 4 KiB. The daemon stores the decoded bytes in `archives` under the job id, with their SHA-256 in `JobKind::Trust`.
  - `POST /api/apply` with body `ApplyBody { project, manifest: String, allow_destroy: bool, reason, requester, context }`, where `manifest` is at most 64 KiB
  - Both reply with `JobReply { id: u64, match_code: String, expires: u64 }`.
  - `GET /api/job/{id}` replies with `JobStatus { id, project, kind, state: String, result: Option<String>, failure: Option<FailureView>, summary: Option<SummaryView> }`. `state` is one of `queued`, `working`, `waiting`, `approved`, `claimed` or `done`. `SummaryView` carries the counts, the address lines, the variable names that changed, and `baseline_status`; it never carries values.
  - `POST /api/kill` accepts `{ "project": P }` beside the existing `{ "host": H }`.
  - Client: `Client::trust(&self, body: &TrustBody) -> Result<JobReply, Error>`, `Client::apply(&self, body: &ApplyBody) -> Result<JobReply, Error>`, `Client::job(&self, id: u64) -> Result<JobStatus, Error>`, and `Client::kill_project(&self, project: &str) -> Result<(), Error>`.

- [ ] **Step 1:** Integration tests in `tests/jobs.rs`, using the existing test-daemon harness in `tests/loop.rs`, which should be factored into `tests/common/mod.rs` if it is not already shared:
  - `trust_request_returns_match_code`
  - `apply_for_unknown_project_is_400_unknown_project`
  - `oversized_archive_is_413`
  - `second_request_while_job_active_is_busy`
  - `kill_project_declines_waiting_job`
  - `job_status_never_contains_manifest_values`. This one requests an apply with the manifest `{"secret_looking":"VALUE123"}` and asserts that `VALUE123` appears in no reply body.
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement. Map `Refusal` to HTTP status the way the existing handlers do: `UnknownProject` gives 400, `Busy` 409, `Cooldown` and `RateCapped` 429.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Agent endpoints for trust and apply requests".

### Task 7: Runner endpoints

**Files:**
- Modify: `src/server.rs`, `src/api.rs`

**Interfaces:**
- Consumes: `Verifier::verify` (Task 5), and `Jobs::poll`, `submit`, `refuse`, `claim` and `finish` (Task 3)
- Produces. Every route requires both headers and a signature over the request:
  - `POST /api/runner/poll` with body `{}` replies with `Option<RunnerJob>`, where `RunnerJob { id, project, kind: "trust"|"apply", state: "working"|"approved", manifest: Option<String>, allow_destroy: bool, trusted: Option<TrustRecord> }`
  - `GET /api/runner/archive/{id}` returns the raw bytes. It is served only while the job is `Working` for this runner, and the archive is dropped once the job leaves `Working`.
  - `POST /api/runner/submit` with body `{ id, scope: JobScopeWire, display: DisplayWire }` replies `{}`. `DisplayWire` carries what the approver needs in order to recompute: for a trust, the diff text, or `external: true` plus the verification command; for an apply, the canonical manifest text, the baseline manifest text, and the address text. The daemon checks each digest in `scope` against the text in `display` before it accepts the submission.
  - `POST /api/runner/refuse` with body `{ id, result: "refused"|"plan_failed", failure: FailureView }`
  - `POST /api/runner/claim` with body `{ id }` replies with `JobScopeWire`.
  - `POST /api/runner/finish` with body `{ id, result: "trusted"|"applied"|"apply_failed"|"outcome_unknown", failure: Option<FailureView> }`. On `trusted` the daemon writes the `TrustRecord` (Task 4) and calls `Jobs::set_trusted`.

- [ ] **Step 1:** Tests in `tests/jobs.rs`, with a test runner key generated in the harness:
  - `unsigned_poll_is_401`
  - `poll_hands_queued_job_to_its_runner_only`
  - `submit_with_digest_not_matching_display_is_400`
  - `claim_is_single_use`
  - `unknown_job_result_is_ledgered_as_outcome_unknown`
  - `finish_trusted_persists_trust_record`
  - `archive_unavailable_after_submit`
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Runner endpoints: poll, archive, submit, refuse, claim, finish".

### Task 8: Approval ceremony, pending view, push and ledger for jobs

**Files:**
- Modify: `src/server.rs` (`ApproveCeremony.scope` becomes `enum CeremonyScope { Ssh(Scope), Job(JobScope) }`; `approve_start` and `approve_finish` dispatch on whichever is waiting, an SSH `Pending` or a `Waiting` job, since at most one exists; `decline`; `test_approve` handles jobs; `drain_and_append` drains `jobs.take_events()` too; `push_for` gains `fn push_for_job(event: &JobEvent) -> Push`), `src/notify.rs` (new `Push` variants), `src/api.rs`

**Interfaces:**
- Produces:
  - `ApproverState` gains `job: Option<JobPendingView>`, carrying `{ id, project, kind, match_code, nonce, reason, requester, context, created, expires, scope: JobScopeWire, display: DisplayWire }`.
  - `Push` gains `TrustWaiting`, `ApplyWaiting`, `Trusted`, `PlanStarted`, `PlanRefused`, `Applied`, `ApplyFailed` and `OutcomeUnknown`, with kinds `trust_waiting`, `apply_waiting`, `trusted`, `plan_started`, `plan_refused`, `applied`, `apply_failed` and `outcome_unknown`. Only `TrustWaiting` and `ApplyWaiting` are not `is_record()`. Each has a fixed body line and a tag, and is added to `Push::ALL`. `JobEvent::Requested` maps to `PlanStarted` for an apply and to `RequestWaiting` for neither: a trust request is silent until `Waiting`.
  - The challenge for a job is `challenge_of(&scope.bytes_to_sign(&nonce))`, bound with the existing `bind_challenge`.

- [ ] **Step 1:** Tests:
  - In `tests/webauthn.rs`, using the existing software authenticator: `apply_approval_with_real_assertion_moves_job_to_approved` and `assertion_over_ssh_challenge_cannot_approve_job`.
  - In `notify.rs`: `only_waiting_job_pushes_interrupt`.
  - In `server.rs`: `push_for_job_is_exhaustive`, a match test listing every `JobEvent`.
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Approve, decline and push for trust and apply jobs".

## Phase C — approve page

### Task 9: Render and verify job scopes in `assets/approve.html`

**Files:**
- Modify: `assets/approve.html`, `tests/page.rs`

**Interfaces:**
- Consumes: `ApproverState.job` (Task 8), and the byte formats and `address_text` (Task 2)

What the page does. Rendering follows spec "Approver changes" and "Apply" step 4. Verification happens before the security-key prompt; the page refuses to sign on any mismatch, with the message "the daemon's challenge does not match the request on screen":

- **Trust.**
  - A heading: "Trust new code for {project}".
  - A distinct color band unlike the apply screen.
  - The obligation statement, verbatim from the spec.
  - Counts, `schema changed` yes or no, and the diff in a monospace block.
  - When `display.external` is set, the digests and the verification command appear instead.
  - The page recomputes `sha256(display.diff)`, unless the diff is external, compares it with `scope.diff`, rebuilds the trust bytes, and checks the challenge.
- **Apply.**
  - A heading: "Apply to {project}".
  - The variable diff, computed in the page by parsing both canonical manifests and listing added, removed and changed keys with their old and new values.
  - The `baseline_status`. `uncertain` shows the warning "last apply did not finish cleanly; this diff may be incomplete".
  - Deletes and replaces first, in a warning style, when `destructive` is set.
  - The page recomputes `sha256` of the manifest, the baseline manifest and the address text, compares each with the scope, rebuilds the apply bytes, and checks the challenge.
- **Both.** The agent's reason, labeled "the agent says:".

- [ ] **Step 1:** Extend `tests/page.rs`. Keep `approve_page_script_parses`, and add `page_rebuilds_trust_and_apply_bytes`. It extracts the script, appends a small harness that calls the page's `trustBytes(scope, nonce)`, `applyBytes(scope, nonce)` and `addressText(lines)` functions on each vector in `job-scope-vectors.json`, and runs it under `node`, asserting byte equality. Like the existing test, it skips loudly without node.
- [ ] **Step 2:** Run `cargo test --test page`. Expect a failure.
- [ ] **Step 3:** Implement. The page functions must be top-level `function` declarations so the harness can call them.
- [ ] **Step 4:** Run `cargo test --test page`. Expect PASS. Then load the page against a test daemon with a waiting apply job and check by eye that the diff is not truncated (Review Focus 5).
- [ ] **Step 5:** Commit: "Approve page: trust and apply scopes, verified before signing".

## Phase D — the runner

### Task 10: Runner skeleton, config and state

**Files:**
- Create: `src/bin/shoephone-runner.rs`, `src/runner/mod.rs`, `src/runner/config.rs`, `src/runner/state.rs`
- Modify: `Cargo.toml` (`[[bin]] shoephone-runner`)

**Interfaces:**
- Produces:
  - `pub struct RunnerConfig { pub name: String, pub daemon: String, pub key: PathBuf, pub state_dir: PathBuf, pub log_dir: PathBuf, pub log_days: u32 (default 30), pub terraform: PathBuf, pub plugin_dir: PathBuf, pub bwrap: PathBuf, pub review_user: String, pub terraform_user: String, pub secret_command: Vec<String>, pub projects: BTreeMap<String, ProjectConfig> }`. The `secret_command` is run with each reference appended as its last argument; the resolved value is its stdout, trimmed.
  - `pub struct ProjectConfig { pub path: String, pub terraform_version: String, pub backend_config: BTreeMap<String, Source>, pub env: BTreeMap<String, Source>, pub variables: BTreeMap<String, Source>, pub schema_file: String (default "shoephone-schema.toml") }`
  - `pub enum Source { Value(String), Secret(String) }`, written as `{ value = "..." }` or `{ secret = "ref" }`
  - The state layout under `state_dir/projects/<name>/`: `trusted/` (the unpacked trusted tree), `trusted.json` (`{ digest, schema }`), `applied.json` (`{ manifest: String, status: "applied"|"uncertain" }`), and `journal.json` (`{ job, phase: "claimed"|"applying"|"done", result }`). Every write goes through `fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()>`, using rename and fsync.
  - `RunnerConfig::from_file(path: &Path) -> Result<RunnerConfig, String>`, using `deny_unknown_fields` and refusing a project whose `variables` names overlap its own schema (checked again at trust time).
  - The binary's verbs: `run` (the poll loop, Task 16), `review-worker <job-dir>` and `--skill`, with exit codes per `src/exit.rs`.
- [ ] **Step 1:** Tests: `config_parses_example`, using `contrib/runner/shoephone-runner.toml.example`, created here with placeholder values only; `config_refuses_unknown_field`; `write_atomic_replaces_whole_file`; `state_paths_are_under_project_dir`.
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Runner binary skeleton, config and state layout".

### Task 11: Archive unpack, tree digest and execution-input refusals

**Files:**
- Create: `src/runner/tree.rs`
- Modify: `Cargo.toml` (`tar`, `flate2`, `similar`, and the HCL parser, each `dep-quality` checked; compare `hcl-rs` with `hcl-edit` and pick the higher score that parses `module` blocks and attribute expressions)

**Interfaces:**
- Produces:
  - `pub struct Tree { pub root: PathBuf, pub files: BTreeMap<String, FileEntry> }` and `pub struct FileEntry { pub mode: u32, pub sha256: String, pub size: u64 }`
  - `pub fn unpack(archive: &[u8], into: &Path, limits: &Limits) -> Result<(), Failure>`. It refuses: symlinks, hard links, device files, absolute paths and `..` components (category `archive_entry_refused`); more than the bounds in Global Constraints (`archive_too_large`); and processing past 60 s (`archive_timeout`).
  - `pub fn execution_input(checkout: &Path, project_path: &str) -> Result<Tree, Failure>`. It walks the project directory plus every directory reached through `module { source = "./..." | "../..." }`, transitively, inside the checkout. A non-local `source` refuses with `module_not_local`. It refuses `.terraform/`, `*.tfstate*`, `*.tfplan`, `terraform.tfvars`, `terraform.tfvars.json`, `*.auto.tfvars` and `*.auto.tfvars.json` (`input_file_refused`), and any `*.tf.json` (`tf_json_refused`). Paths are recorded relative to the checkout.
  - `pub fn digest(tree: &Tree) -> String`: SHA-256 over sorted `"{path}\0{mode:o}\0{sha256}\n"` lines
- [ ] **Step 1:** Tests in `tree.rs`, building tars in memory:
  - `symlink_entry_is_refused`
  - `dotdot_entry_is_refused`
  - `too_many_files_is_refused`
  - `unpacked_size_bound_holds_for_small_gzip_bomb`
  - `non_local_module_is_refused`
  - `local_module_outside_project_dir_is_included`
  - `auto_tfvars_json_is_refused`
  - `digest_changes_with_mode_and_content`
  - `digest_ignores_files_outside_execution_input`
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Bounded unpack and the execution-input digest".

### Task 12: Schema, manifest validation and canonical form

**Files:**
- Create: `src/runner/schema.rs`

**Interfaces:**
- Produces:
  - A schema file (`shoephone-schema.toml`, inside the project directory and so part of the trusted tree):
    ```toml
    [variables.NAME]
    type = "string" | "number" | "bool" | "list_of_strings"
    # string: exactly one of pattern, choices; max_len (default 256)
    # number: min, max, integer (bool)
    # list_of_strings: item pattern or item choices; max_items (default 64)
    # optional: default
    ```
  - `pub struct Schema` and `pub fn parse_schema(text: &str) -> Result<Schema, Failure>`
  - `pub fn validate(schema: &Schema, manifest: &str) -> Result<Canonical, Failure>`. It parses with a duplicate-key-rejecting JSON reader: `serde_json` with a custom map visitor that errors on a repeated key. Refusals: `manifest_unknown_variable`, `manifest_duplicate_key`, `manifest_type` (no coercion, so `"1"` is not a number), `manifest_constraint`, `manifest_missing` and `manifest_too_large`. Each puts the variable *name*, never the value, in `Failure.addresses`.
  - `pub struct Canonical(pub String)`: sorted keys, no whitespace, with defaults filled in
  - `pub fn disjoint(schema: &Schema, runner_vars: &BTreeSet<String>) -> Result<(), Failure>` (`schema_overlaps_runner_variables`)
- [ ] **Step 1:** Tests:
  - `unknown_key_is_refused`
  - `duplicate_key_is_refused`
  - `string_number_is_not_coerced`
  - `pattern_mismatch_names_variable_not_value`
  - `choices_enforced`
  - `list_item_pattern_enforced`
  - `missing_without_default_is_refused`
  - `canonical_is_sorted_and_compact`
  - `overlap_with_runner_variables_is_refused`
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Manifest schema, strict validation and canonical form".

### Task 13: Trust review, run by the review worker

**Files:**
- Create: `src/runner/review.rs`

**Interfaces:**
- Consumes: `execution_input` and `digest` (Task 11), `parse_schema` and `disjoint` (Task 12), the HCL parser
- Produces:
  - `pub struct Review { pub scope: TrustScope, pub diff: Option<String>, pub verify_command: String, pub warnings: Vec<Warning> }`, where `diff` is `None` when the diff is external
  - `pub fn review(baseline: Option<&Path>, candidate: &Path, project: &str, cfg: &ProjectConfig, policy_version: u32) -> Result<Review, Failure>`
    - The diff is a unified diff (`similar`, 3 lines of context) over every execution-input file, with mode changes shown as `old mode` and `new mode` lines.
    - When `baseline` is `None`, every file is diffed against empty.
    - When the rendered diff exceeds **256 KiB**, `diff` is `None` and `verify_command` is `shoephone-runner diff-digest <baseline-digest> <candidate-dir>`. The runner provides that verb too: the operator runs it against their own checkout, and it prints the same diff digest.
    - The scope's `diff` field is the SHA-256 of the full diff text, whether or not that text is displayed.
  - `pub enum Warning`, with the variants `Provisioner`, `ExternalData`, `HttpData`, `Import`, `Nonsensitive`, `ProviderFunction`, `SchemaVariableSteers { variable, into: "secret_selector"|"file_path"|"count"|"for_each"|"condition" }` and `LocalFileRead`. Each carries `file` and `line`. `SchemaVariableSteers` is a conservative scan: a `var.NAME` reference anywhere inside a `count`, `for_each` or conditional expression, a `data "onepassword_item"` argument, or a `source_file`, `file()` or `templatefile()` path argument.
  - `review-worker <job-dir>` reads `job-dir/request.json` (`{ baseline_dir, candidate_dir, project, policy_version }`) and writes `job-dir/review.json`. The project config arrives in `request.json`, reduced to the variable names; the worker never sees secrets.
- [ ] **Step 1:** Tests:
  - `first_trust_diffs_against_empty`
  - `mode_change_is_shown`
  - `oversized_diff_is_marked_external`
  - `diff_digest_matches_verify_command_output`, which runs the `diff-digest` verb in-process
  - `schema_change_sets_flag`
  - `provisioner_is_warned`
  - `var_in_count_is_warned`
  - `var_in_onepassword_lookup_is_warned`
  - `schema_overlap_refuses_review`
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Trust review: full diff, digests and reviewer warnings".

### Task 14: Plan summary and failure categories

**Files:**
- Create: `src/runner/plan.rs`

**Interfaces:**
- Produces:
  - `pub fn summarize(show_json: &str) -> Result<Summary, Failure>`, where `pub struct Summary { pub counts: Counts, pub changes: Vec<(Action, String)>, pub destructive: bool }`. Actions are read from `resource_changes[].change.actions`: `["create"]`, `["update"]`, `["delete"]`, and `["delete","create"]` or `["create","delete"]` as `Replace`. `no-op` and `read` are skipped. Changes are ordered deletes, replaces, creates, updates, then by address.
  - `pub fn categorize(diagnostics_jsonl: &str, phase: Phase) -> Failure`, with `pub enum Phase { Init, Plan, Apply }`. It reads `terraform -json` diagnostic lines and keeps only each diagnostic's `address` field. It never copies `summary` or `detail` text. The category is `init_failed`, `plan_failed` or `apply_failed`; `detail` is `None`.
- [ ] **Step 1:** Tests with fixture JSON under `tests/fixtures/plan/` (hand-written, generic resource names):
  - `replace_in_either_order_counts_as_replace`
  - `no_op_and_read_are_skipped`
  - `destructive_set_by_delete_or_replace`
  - `categorize_keeps_address_drops_text`, where the fixture's `detail` holds the string `LEAKME` and the test asserts it appears nowhere in the `Failure` (Debug-formatted)
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Plan summary and text-free failure categories".

### Task 15: The executor: resolver, sandboxed Terraform, logs and journal

**Files:**
- Create: `src/runner/exec.rs`, `src/runner/journal.rs`

**Interfaces:**
- Consumes: `RunnerConfig` (Task 10), `validate` (Task 12), `summarize` and `categorize` (Task 14)
- Produces:
  - `pub fn resolve(cfg: &RunnerConfig, project: &ProjectConfig) -> Result<Resolved, Failure>`, where `pub struct Resolved { pub env: Vec<(String, String)>, pub tf_vars: Vec<(String, String)>, pub backend: Vec<(String, String)>, pub masks: Vec<String> }`. It runs `secret_command` once per secret reference, and only in the root process. On failure the category is `secret_unavailable` and the reference is not logged.
  - `pub fn terraform(cfg: &RunnerConfig, job_dir: &Path, args: &[&str], resolved: &Resolved) -> Result<Output, Failure>`. It starts `bwrap` as `terraform_user` (via `CommandExt::uid`/`gid`) with:
    - read-only binds for `/usr` and `/lib*`, the terraform binary, and `plugin_dir`;
    - a read-write bind for `job_dir` only;
    - a fresh `/tmp`, `--unshare-pid`, `--die-with-parent`, `--clearenv`;
    - in the environment, only `resolved.env`, `TF_VAR_*` from `resolved.tf_vars`, `TF_PLUGIN_CACHE_DIR` unset, and `TF_CLI_ARGS_init=-plugin-dir=<plugin_dir>` together with `-backend-config` pairs from `resolved.backend`.
    It writes full stdout and stderr to `log_dir/<project>/<job>.log` (mode 0600, root) and masks nothing there. The returned `Output` carries the exit status and the `-json` stream for `categorize`.
  - `pub fn plan(cfg, project_name, job_dir, manifest: &Canonical, resolved) -> Result<(Summary, PathBuf /*plan file*/, String /*plan sha256*/), Failure>`. It runs `init`, then `plan -json -input=false -out=plan.tfplan -var-file=<job_dir>/manifest.tfvars.json`, writing the manifest file outside the checkout directory but inside `job_dir`, then `show -json plan.tfplan`.
  - `pub fn apply(cfg, job_dir, plan_file: &Path, expected_sha256: &str, resolved) -> Result<(), Failure>`. It re-hashes the plan file (category `plan_changed` on a mismatch) and then runs `apply -json -input=false plan.tfplan`.
  - `Journal` provides `begin(job) -> io::Result<()>` (phase `applying`, written before Terraform starts), `end(job, result)`, and `pending_unknown() -> Option<u64>`, which returns a job journaled `applying` with no `end`.
  - Log pruning: `fn prune_logs(log_dir: &Path, days: u32)`, called at startup.
- [ ] **Step 1:** Tests. The executor runs a **fake terraform**, a shell script at `tests/fixtures/fake-terraform.sh` that records its argv and environment to a file and emits canned `-json` lines. They also run with `bwrap` replaced by a pass-through stub when `SHOEPHONE_TEST_NO_SANDBOX=1`, which only `cfg(test)` code honors.
  - `resolver_output_never_reaches_review_worker`
  - `terraform_env_has_only_resolved_values`
  - `manifest_file_is_outside_checkout`
  - `plan_file_tamper_is_refused`
  - `journal_reports_started_job_as_unknown`
  - `log_file_is_0600`
  - `old_logs_are_pruned`
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** On a Linux host with bubblewrap, a manual check: run the fake terraform through the real `bwrap` path and confirm it cannot read `cfg.key` or the runner config (`cat` exits non-zero inside the sandbox). Record the output in the commit message.
- [ ] **Step 6:** Commit: "Executor: root resolver, sandboxed Terraform worker, logs and journal".

### Task 16: The runner loop

**Files:**
- Create: `src/runner/client.rs`, `src/runner/run.rs`
- Modify: `src/bin/shoephone-runner.rs`

**Interfaces:**
- Consumes: Task 5 `canonical` and `sign`, and Tasks 10–15
- Produces:
  - `RunnerClient` with `poll`, `archive(id)`, `submit`, `refuse`, `claim` and `finish`. Each request is signed with a fresh nonce and the current timestamp.
  - `pub fn run(cfg: RunnerConfig) -> ExitCode`. At startup it prunes logs and reports a journaled unknown outcome first. The loop polls every 2 s and backs off to 30 s on errors. It handles one job at a time:
    - **Trust:** fetch the archive, unpack it into a fresh `job_dir/candidate` owned by `review_user`, run `review-worker` as `review_user`, then `submit` the trust scope and display. On `approved` with a matching claim, copy the candidate tree into `trusted/` and write `trusted.json`, then `finish(trusted)`.
    - **Apply:** check that the daemon's `trusted` record and the local `trusted.json` agree on the digest (otherwise refuse with `no_trusted_revision`), then validate the manifest. Then plan in a copy of `trusted/`. If the plan is destructive without `allow_destroy`, refuse with `destroy_not_requested` and the addresses. Otherwise build the `ApplyScope` and display from `applied.json`'s baseline, and submit. On approval, claim, journal `begin`, apply, then journal `end`. Write `applied.json`: on success with `status: applied` and the new manifest, on failure or unknown with `status: uncertain` and the old manifest kept. Then `finish`.
  - Every job directory is removed afterward, logs aside.
- [ ] **Step 1:** Integration test `tests/runner_loop.rs`. It runs the real daemon (test-hooks) and the runner in-process with the fake terraform and no sandbox. Approval happens through `/api/test/approve` extended for jobs (Task 8). Tests:
  - `trust_then_apply_end_to_end`
  - `apply_without_trust_refuses_no_trusted_revision`
  - `destructive_plan_without_flag_is_refused`
  - `apply_failure_marks_baseline_uncertain`
  - `second_apply_shows_diff_against_last_applied`
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test`. Expect PASS.
- [ ] **Step 5:** Commit: "Runner loop: trust and apply end to end".

## Phase E — CLI and docs

### Task 17: `shoephone trust` and `shoephone apply`

**Files:**
- Modify: `src/bin/shoephone.rs`, `src/exit.rs` (`PlanFailed = 100`, `ApplyFailed = 101`, `OutcomeUnknown = 102`), `SKILL.md`, `AGENTS.md`, `tests/cli.rs`

**Interfaces:**
- Consumes: `Client::trust`, `apply`, `job` and `kill_project` (Task 6)
- Produces:
  - `shoephone trust <project> --reason R`. It refuses a dirty tree (exit 3, naming `git status`), builds the archive with `git archive --format=tar HEAD | gzip`, and sends it. It prints the match code to stderr and polls `job` until the job is done.
  - `shoephone apply <project> --manifest FILE --reason R [--allow-destroy]`. It reads FILE (at most 64 KiB) and sends it as is; validation is the runner's job.
  - The mapping from result to exit code:
    - `trusted` and `applied` give 0.
    - `declined` and `timed_out` give 12.
    - Busy gives 20, cooldown and cap give 23.
    - `refused` gives 30, with the category and addresses on stderr.
    - `plan_failed` gives 100, `apply_failed` 101, `outcome_unknown` 102.
  - `--json` prints `{"result": {"id","project","kind","outcome","category","addresses","counts","changed_variables"}, "empty": false}`.
  - `shoephone status` lists the active job, if any, beside windows.
  - SKILL.md gains sections for both verbs, the exit table rows, and "Notes for an agent" lines: 102 means check before anything else; never retry 12; a trust request is rare and needs the operator to read a diff; the manifest holds data only.
  - AGENTS.md: exit codes 100–102 under "Tool-specific exit codes", the three new invariants from the spec's "Security invariants this adds" under "Security invariants", a Decisions row pointing at the spec, and the Build status updated.
- [ ] **Step 1:** Tests in `tests/cli.rs`, with stdout piped, stdin closed and `NO_COLOR=1`, as CI does: `trust_in_dirty_tree_exits_3`, `apply_missing_manifest_exits_3`, `apply_refused_exits_30_with_category_on_stderr` (against the test daemon), and `skill_mentions_trust_and_apply`.
- [ ] **Step 2:** Run them. Expect a failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full verification block from AGENTS.md. Expect all four clean.
- [ ] **Step 5:** Commit: "CLI: trust and apply verbs, exit codes 100-102, skill and AGENTS.md".

### Task 18: Deployment examples and the design record

**Files:**
- Create: `contrib/systemd/shoephone-runner.service` (runs as root; `ProtectSystem=strict`, `ReadWritePaths` set to the state and log dirs; `NoNewPrivileges=no` is required for `bwrap` setuid, so give the reason in a comment), `contrib/runner/nftables.conf.example` (per-uid egress: `terraform_user` may reach only listed endpoints, `review_user` nothing, root the daemon only; placeholder addresses from the documentation ranges), `contrib/runner/README.md` (install, users, operator-only SSH, first trust)
- Modify: `docs/DESIGN.md` (a short "Plan approval" section pointing at the spec), `README.md` (one paragraph and the new binary)

- [ ] **Step 1:** Write the files. The example nftables file must parse: `nft -c -f contrib/runner/nftables.conf.example` where nft exists. Note in the commit if it was not available.
- [ ] **Step 2:** Grep the new files for anything estate-specific (hostnames, vault names, non-documentation addresses). Expect no hits.
- [ ] **Step 3:** Commit: "Runner deployment examples and design record".

## Not in this plan

- **The iOS app** (`shoephone-app`): rendering and verifying the trust and apply scopes, using `tests/fixtures/job-scope-vectors.json` copied in. That is a separate plan in that repository, after Task 9 settles the screens.
- **The deployment** (the runner guest, its secrets identity, the firewall, the first trust reviews, and the vault-split amendment): in the operator's infrastructure repository.
- **The secret-release action:** deferred by the spec.
