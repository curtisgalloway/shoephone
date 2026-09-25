---
name: shoephone
description: Request a phone-approved, short-lived SSH certificate for admin work on a host, renew it inside the approved window, end it early, and check why a request cannot succeed before making it. Use when an agent session needs escalation beyond its promptless read-only account, or when `shoephone` exits non-zero and you need to know what the code means.
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
shoephone status                     # list open windows
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
| 22 | the daemon answered with an error or nonsense, or the connection failed after the request may have been sent; outcome unknown | run `shoephone status` before retrying |
| 23 | cooldown or hourly cap; stderr says until when | come back after that time |
| 30 | permanent: unknown host or a malformed key | the request itself must change |

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
