---
name: shoephone
description: Request a phone-approved, short-lived SSH certificate for admin work on a host, renew it inside the approved window, end it early, and check why a request cannot succeed before making it. Use when an agent session needs escalation beyond its promptless read-only account, or when `shoephone` exits non-zero and you need to know what the code means.
---
<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# shoephone {{VERSION}}

`shoephone` is the grant CLI of a two-tier access model for coding agents.
The safe tier is a promptless read-only account the agent already holds.
The dangerous tier is a short-lived SSH certificate that a person approves
from their phone; this tool requests it, waits for the verdict, and loads the
resulting key and certificate into the session's ssh-agent. An agent should
reach for it only when a task genuinely needs admin on a host, and should
expect the request to be declined without that being an error in the tool.

## Invocation

```bash
shoephone [--json] [--daemon URL] <command>
shoephone doctor                     # check preconditions before guessing
shoephone request <host> --reason "..." [--context URL] [--window MINUTES]
shoephone renew <host>               # a fresh certificate inside the open window
shoephone disavow <host>             # end the window early; unload the key
shoephone status                     # open windows
shoephone --skill                    # print this document
shoephone --version
```

The daemon address comes from `--daemon`, else `$SHOEPHONE_DAEMON`, else
`daemon = "https://..."` in `~/.config/shoephone/config.toml`. `doctor`
says which one is in effect and whether it answers.

`--reason` is required. Write it for the person who will read it on
their phone before deciding: what the task is, why it needs admin on
that host, and roughly what you will run, in one or two sentences. It is
shown beside the match code and kept in the history. A request with no
reason is refused before anyone is asked.

The request also carries a link to this session, so the person can open
it on their phone and read the context behind the reason. Inside Claude
Code it is filled in from the session id in the environment; `--context
URL` overrides it (https only).

## What a request does

1. Sends the host, the reason, and this machine's session public key to
   the daemon.
   The session key is generated once, unencrypted, in
   `~/.local/state/shoephone/`; it is useless without a certificate.
2. Prints a **match code** on stdout. The person compares it with the one on
   their phone. It is not an input and not a secret; do not act on it.
3. Waits for the verdict, polling for up to the daemon's pending timeout
   (default 5 minutes).
4. On approval, fetches a certificate valid for one principal on that host,
   writes it next to the session key as `session_ed25519-cert.pub`, and
   runs `ssh-add -t` so `ssh agent-admin@<host>` works for the rest of the
   certificate's life (default 15 minutes). The approved window (default
   60 minutes) is longer; `shoephone renew <host>` gets the next
   certificate silently, no second approval.

Then use ssh as usual: `ssh agent-admin@<host> sudo ...`. When the task is
done, `shoephone disavow <host>` closes the window; a certificate already
loaded expires within one certificate lifetime.

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
| 12 | denied: declined, timed out, or the key does not match the window | do not retry; the person saw the request and chose |
| 20 | another request is pending | wait for it; a retry is free |
| 22 | daemon answered with an error or nonsense; outcome unknown | check `shoephone status` before retrying |
| 23 | cooldown or hourly cap; stderr says when | come back after that time |
| 30 | permanent: unknown host or a malformed key | the request itself must change |

## Output

`--json` emits a single JSON document on stdout and nothing else. Diagnostics
always go to stderr, including the match code while waiting. `--version`
honors it (`{"version": "..."}`); `--skill` does not, because this document
is the output. An empty result
is typed in the payload (`{"result": null, "empty": true, "reason": "..."}`),
so a structured caller never has to read the exit status to learn the answer
was empty. `request` and `renew` return
`{"result": {"host", "serial", "valid_before", "ends_at", "certificate", "key", "in_agent"}, "empty": false}`.

## Notes for an agent

- A declined or timed-out request is exit 12, not a tool failure. Do not
  retry it; the person who declined can see the request and chose not to
  approve it. Repeated requests cost a growing cooldown on the daemon side,
  and the hourly cap is shared by every requester.
- Ask for one host per request. A window is bound to one host and one key;
  admin on a second host is a second request and a second tap.
- Run `shoephone doctor` first in a fresh environment. It reports the
  daemon, the enrolled approver devices, the hosts the daemon signs for,
  and whether ssh-agent is reachable, and exits 3 if anything is missing.
- The match code the tool prints is for the person at the terminal to
  compare against their phone. Show it to them; never paraphrase it.
