---
name: shoephone
description: Request a phone-approved, short-lived SSH certificate for admin work on a host, renew it inside the approved window, end it early, and check why a request cannot succeed before making it. Also file Terraform trust and apply jobs for a person to approve. Use when an agent session needs escalation beyond its promptless read-only account, or when `shoephone` exits non-zero and you need to know what the code means.
---
<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# shoephone {{VERSION}}

`shoephone` gets you admin on one host, for a limited time, with a person's
approval. You already have a promptless read-only account for everyday work.
When a task needs more, this tool asks the daemon for an SSH certificate, a
person approves or declines on their phone, and on approval the certificate
goes into your ssh-agent.

Use it only when the task needs admin. A decline is a normal answer, not a
tool failure.

## Invocation

```bash
shoephone [--json] [--daemon URL] <command>
shoephone doctor                     # check everything a request needs
shoephone request <host> --reason "..." [--context URL] [--window MINUTES]
shoephone renew <host>               # a fresh certificate inside the open window
shoephone disavow <host>             # end the window early; unload the key
shoephone status                     # list open windows and the active Terraform job
shoephone trust <project> --reason "..."
shoephone apply <project> --manifest FILE --reason "..." [--allow-destroy]
shoephone --skill                    # print this document
shoephone --version
```

The daemon address comes from `--daemon`, then `$SHOEPHONE_DAEMON`, then
`daemon = "https://..."` in `~/.config/shoephone/config.toml`. `doctor`
reports which one is in effect and whether it answers.

**`--reason` is required** and is read by a person deciding on their phone.
In one or two sentences, say what the task is, why it needs admin on that
host, and roughly what you will run. It is kept in the history.

The request also carries a link to this session so the person can read the
context. Inside Claude Code the link comes from the session id in the
environment. `--context URL` overrides it (https only).

## What a request does

1. Sends the host, the reason and a session public key to the daemon. Each
   host has its own unencrypted key in
   `~/.local/state/shoephone/hosts/<host>/`, created on first use. It is
   useless without a certificate.
2. Prints a **match code**. The person compares it with the code on their
   phone. It is not an input and not a secret; do not act on it.
3. Waits for the verdict, up to the daemon's pending timeout (default
   5 minutes).
4. On approval, writes the certificate to
   `hosts/<host>/session_ed25519-cert.pub` and loads the key with
   `ssh-add -t`, so ssh works until the certificate expires (default
   15 minutes).

The approved window (default 60 minutes) outlasts the certificate.
`shoephone renew <host>` gets the next certificate without a second
approval.

The account to log in as is the part of the printed principal before the
colon: `agent-admin` for `agent-admin:web01`. Then:

```bash
ssh agent-admin@web01 sudo ...
```

When the task is done, run `shoephone disavow <host>`. A certificate already
loaded still works until it expires.

## Terraform: trust and apply

For a project the daemon manages, a person approves on their phone and a
runner holding the credentials does the work. You never hold a credential.

- `shoephone trust <project> --reason "..."` archives the whole repository at
  `HEAD` and files it for the person to read as a diff. Run it from inside the
  checkout. It refuses (exit 3, naming `git status`) when tracked files have
  uncommitted changes, because only committed code can be trusted. Untracked
  files are ignored. An archive over 16 MiB compressed is refused (exit 30).
- `shoephone apply <project> --manifest FILE --reason "..."` sends FILE (JSON,
  at most 64 KiB) as is. The manifest holds variable values and nothing else:
  no code, no secrets. The runner validates it and may refuse it (exit 30,
  with the category and addresses on stderr). `--allow-destroy` says the plan
  may delete or replace resources or remove an output; without it, a plan
  that does any of those is refused.

Both print a match code and then wait, polling every 2 seconds, until the job
is done. The person compares the code with their phone. The runner plans
first, so the wait can be several minutes.

`--json` prints, once the job is done:

```
{"result": {"id", "project", "kind", "outcome", "category", "addresses", "counts", "changed_variables"}, "empty": false}
```

`outcome` is `trusted`, `applied`, `refused`, `plan_failed`, `apply_failed`,
`outcome_unknown`, `declined`, `timed_out` or `killed`. `category` and
`addresses` describe a failure (`null` and `[]` otherwise). `counts`
(`create`, `update`, `replace`, `delete`) and `changed_variables` come from
the plan summary and are `null` when there is none. Manifest values are never
printed. `summary` is null for trust jobs; for an apply it appears once the
runner has planned.

`trust` sends what `git archive` produces. It honors `export-ignore` and
`export-subst` and archives submodules empty, so what is reviewed and run is
the archived form, and modules that live in submodules are absent.

## Exit status

| Code | Meaning | What to do |
|---|---|---|
| 0 | success | continue |
| 1 | ran fine; the answer is empty (`disavow` with no window) | not an error; `set -e` will still abort, so use `\|\| true` |
| 2 | usage error | fix the argument named in stderr |
| 3 | missing precondition | configure what stderr names: daemon address, ssh-agent, state dir |
| 4 | daemon unreachable | check DNS, route, TLS trust, and whether the daemon is up |
| 10 | certificate issued but not loaded into the agent | use `ssh -i <key>` as stderr says, or fix ssh-agent |
| 11 | a person must act (no open window; the request needs approval) | run `shoephone request <host>` if the task still needs admin |
| 12 | denied: declined, timed out, or the key does not match the window; for `trust`/`apply` also `killed` | do not retry; the person saw the request and chose |
| 20 | another request is pending | wait for it; a retry is free |
| 22 | the daemon answered with an error or nonsense, or the connection failed after the request may have been sent; outcome unknown; for `trust`/`apply` also an unknown result, no result after the CLI's 8 hour backstop, or the daemon forgot the job before it was ever approved (nothing ran) | run `shoephone status` before retrying |
| 23 | cooldown or hourly cap; stderr says until when | come back after that time |
| 30 | permanent: unknown host or project, a malformed key, a manifest or archive the runner or daemon refused | the request itself must change; stderr names the category |
| 100 | `plan_failed`: the Terraform plan failed; nothing was applied | read the category on stderr, fix the code or manifest, then file again |
| 101 | `apply_failed`: the apply started and failed; infrastructure may be partly changed. For `trust`, the runner could not install the change and the previous trust stands | check the real state; do not blindly file the same apply again |
| 102 | `outcome_unknown`: the runner cannot say whether the apply took effect, or the daemon no longer knows a job it had approved (it restarted) | check the real state before anything else; do not retry |

## Output

`--json` prints a single JSON document on stdout and nothing else.
Diagnostics, including the match code, always go to stderr. `--version`
honors `--json` (`{"version": "..."}`); `--skill` does not, because this
document is its output.

An empty result is marked in the payload
(`{"result": null, "empty": true, "reason": "..."}`), so a caller never needs
the exit status to learn the answer was empty. `request` and `renew` return:

```
{"result": {"host", "serial", "valid_before", "ends_at", "certificate", "key", "in_agent"}, "empty": false}
```

## Notes for an agent

- **Exit 12 is a verdict.** Do not retry a declined or timed-out request.
  Each one adds to a growing cooldown, and the hourly cap is shared by every
  requester.
- **Exit 102 means check before anything else.** An apply that may or may not
  have happened must be read back from the infrastructure itself. Do not file
  another apply, and never retry it.
- **Never retry exit 12 on `trust` or `apply` either.** A declined or timed-out
  job is the person's answer, and it adds to the cooldown.
- **A trust request is rare.** The person has to read a diff of the whole
  repository. File one only after the code change is committed and reviewed,
  and say in `--reason` what changed.
- **The manifest holds data only.** Variable values go in; code, scripts and
  secrets never do. To change what Terraform does, change the code and trust
  it.
- **One host per request.** A window covers one host and one key. Admin on a
  second host is a second request and a second approval.
- **Run `shoephone doctor` first** in a new environment. It reports the
  daemon, the enrolled approver devices, the hosts the daemon signs for, and
  whether ssh-agent is reachable. It exits 3 if anything is missing.
- **Show the match code to the person exactly as printed.** Never paraphrase
  it.
- **If ssh-agent refuses the key** (exit 10 with "agent refused operation" on
  every request; the 1Password agent does this), set `agent = false` in
  `~/.config/shoephone/config.toml`. The CLI then skips ssh-agent, exits 0,
  and leaves the certificate beside the host's session key. Point ssh at it
  in `~/.ssh/config`:

  ```
  Match user agent-admin
      IdentityFile ~/.local/state/shoephone/hosts/web01/session_ed25519
      IdentitiesOnly yes
      IdentityAgent none
  ```

  ssh finds the `-cert.pub` file next to the key on its own, so
  `ssh agent-admin@web01` needs no `-i`. For several hosts, add one
  `IdentityFile` line per host. ssh tries them in order, so keep the list
  short or sshd's `MaxAuthTries` runs out before the right one.
