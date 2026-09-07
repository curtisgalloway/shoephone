---
name: shoephone
description: Request a phone-approved, short-lived SSH certificate for admin work on a host, check whether the grant daemon is reachable, and end a grant early. Use when an agent session needs escalation beyond its promptless read-only account, or when `shoephone` exits non-zero and you need to know what the code means.
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
shoephone [--json] <command>
shoephone doctor        # check preconditions before guessing
shoephone --skill       # print this document
shoephone --version
```

Verbs for requesting, renewing, and disavowing a grant land with the daemon;
until then only `doctor` exists.

## Exit status

| Code | Meaning | What to do |
|---|---|---|
| 0 | success | continue |
| 1 | ran fine; the answer is empty | not an error; `set -e` will still abort, so use `\|\| true` |
| 2 | usage error | fix the argument named in stderr |
| 3 | missing precondition | install or configure what stderr names |
| 4 | target unreachable | check DNS, route, and whether the daemon is up |
| 10 | auth fixable locally | remediate, then retry |
| 11 | auth needs a person | stop and surface it |
| 12 | denied by rule | do not retry; the policy must change |
| 20 | transient, nothing done | retry with backoff |
| 21 | transient, partially done | reconcile state, then retry |
| 22 | no response, outcome unknown | check state before retrying |
| 23 | retry after a long delay | schedule, come back later |
| 30 | permanent | the request itself must change |

## Output

`--json` emits a single JSON document on stdout and nothing else. Diagnostics
always go to stderr. An empty result is typed in the payload
(`{"result": null, "empty": true, "reason": "..."}`), so a structured caller
never has to read the exit status to learn the answer was empty.

## Notes for an agent

- A declined or timed-out request is exit 12, not a tool failure. Do not
  retry it; the person who declined can see the request and chose not to
  approve it. Repeated requests cost a cooldown on the daemon side.
- The match code the tool prints is for the person at the terminal to
  compare against their phone. It is not an input and not a secret.
