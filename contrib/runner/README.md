<!--
  SPDX-FileCopyrightText: 2026 Curtis Galloway
  SPDX-License-Identifier: Apache-2.0
-->

# Deploying shoephone-runner

The runner is the host that holds Terraform credentials. Read
[RUNNER.md](../../RUNNER.md) for what it does and
[the design](../../docs/superpowers/specs/2026-10-26-plan-approval-design.md)
for why. This file is the install checklist. Every name, path and address
here is a placeholder; use your own.

**Terms**

- **Runner host:** a dedicated machine (a VM is fine) with no agent account.
  Root on it means every credential it holds.
- **Daemon host:** where `shoephoned` runs. The runner polls it; it never
  connects to the runner.
- **review_user:** an unprivileged user that unpacks and reviews uploaded
  code with no credentials.
- **terraform_user:** an unprivileged user that runs Terraform inside
  bubblewrap (`bwrap`, a Linux sandbox tool) and sees only one job's files.
- **Secrets identity:** the runner's own login to a secrets store, able to
  read the credentials the projects need. The agent's identity must not.

Linux only: the sandbox and the user switch use Linux interfaces.

## 1. Build and install

```bash
cargo build --release      # never add --features test-hooks for a deployed runner
install -m 0755 target/release/shoephone-runner /usr/local/bin/
```

A build with `test-hooks` runs Terraform without the sandbox. It refuses to
start unless `SHOEPHONE_RUNNER_ALLOW_TEST_HOOKS=1`, which only this
repository's tests set. Never set it on the runner host, and never enable the
feature for a deployed `shoephoned` or `shoephone-runner`.

Install `bubblewrap` and `terraform` from your distribution or the vendor, as
root-owned files no other user can write.

## 2. Users

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin shoephone-review
useradd --system --no-create-home --shell /usr/sbin/nologin shoephone-terraform
```

Two different users, neither in any group that can read `/etc/shoephone-runner`
or the state directory. The names must match `review_user` and
`terraform_user` in the config and the `meta skuid` rules in the firewall.

## 3. Directories and modes

```bash
install -d -m 0700 /etc/shoephone-runner
install -d -m 0711 /var/lib/shoephone-runner
install -d -m 0700 /var/log/shoephone-runner
install -d -m 0755 -o root -g root /opt/shoephone-runner
```

`state_dir` must be 0711 or 0755 so both worker users can reach their own job
directories. The runner creates `state_dir/jobs` as 0711 and each job
directory as 0700 owned by the worker user. Logs are 0600 in 0700
directories, readable by the operator only.

## 4. The secrets identity

Create a login for the runner in your secrets store that can read exactly the
items the projects name, and nothing else. Put its token or key where
`secret_command` can reach it, readable by root only (mode 0600 in
`/etc/shoephone-runner`, or the operating system's credential store). The
command is run with the reference as its last argument, with an environment of
only `PATH=/usr/bin:/bin` plus the variables named in `secret_env`. Never put
the token in a project's `env` table.

## 5. Runner key and config

```bash
ssh-keygen -q -t ed25519 -N '' -C shoephone-runner -f /etc/shoephone-runner/runner.key
chmod 0600 /etc/shoephone-runner/runner.key
cat /etc/shoephone-runner/runner.key.pub
```

The runner reads an unencrypted OpenSSH private key and refuses an encrypted
one. Put the printed public key in the daemon's config as
`[runners.<name>] public_key = "..."`, and name the project with
`[projects.<name>] runner = "<name>"`. Then write
`/etc/shoephone-runner/shoephone-runner.toml` from
[shoephone-runner.toml.example](shoephone-runner.toml.example), mode 0600. The
`daemon` URL must be `https://` (loopback excepted); a private CA in the
host's trust store works.

## 6. The plugin directory, pinned by hash

Terraform runs with `init` forbidden from downloading anything, so every
provider must already be in `plugin_dir`.

```bash
install -d -m 0755 /opt/shoephone-runner/plugins
```

Download each provider on a trusted machine, check its published checksum
and signature there, copy it into `plugin_dir` as root-owned, read-only
files, and record the SHA-256 of each file in the operator's own notes (or
infrastructure repository). Keep the project's `.terraform.lock.hcl` in the
reviewed code, so a provider that changes is a change the reviewer sees.
Re-check the hashes whenever a provider is added or upgraded.

## 7. Operator-only SSH

The runner host's only inbound service is SSH for the operator.

- Use the operator's own key. Do not trust shoephone's user CA on this host,
  and give the agent no account of any kind.
- Admit only the operator's machines in the firewall (the `operator_net`
  rule below) and in `sshd_config` (`AllowUsers`).
- Turn off password logins and agent forwarding.

The operator reads full Terraform output from `log_dir/<project>/<job>.log`
over this SSH session. That output never goes through the daemon.

## 8. Firewall

Edit [nftables.conf.example](nftables.conf.example): replace the
documentation addresses with your daemon host, resolver, secrets store,
operator network and each project's endpoints. The rules are per user
(`meta skuid`): `terraform_user` reaches only the listed endpoints, the
review user nothing, root only the daemon, the secrets store and the
resolver. Everything else is counted and rejected. Check, then load:

```bash
nft -c -f /etc/nftables.d/shoephone-runner.conf
nft -f /etc/nftables.d/shoephone-runner.conf
```

The firewall is defense in depth. The boundary is that Terraform runs only
reviewed code with validated input.

## 9. Service

```bash
cp contrib/systemd/shoephone-runner.service /etc/systemd/system/
systemctl enable --now shoephone-runner
journalctl -u shoephone-runner -f
```

Startup prints sandbox warnings on stderr; fix every one. Keep
`ReadWritePaths=` in the unit equal to `state_dir` and `log_dir`.

## 10. First trust of a project

A project has nothing runnable until an operator-approved trust. From the
agent's checkout, `shoephone trust <project> --reason "..."` uploads HEAD.
The approve page shows the full diff, or for a first trust the full content,
and the warnings. When the diff is too large to show, it shows only digests
and a command to run in your own checkouts:

```bash
shoephone-runner diff-digest none - /path/to/clean/candidate infra/example
```

For a later trust, the first two arguments are the baseline digest and the
baseline checkout. Use clean exports (`git worktree add` or
`git archive | tar x`), and compare both printed digests with the page
before approving. Read the whole diff against the reviewer's obligation at
the top of the trust screen: with any manifest the schema accepts, protected
credentials may reach only their provider and approved destinations.

## 11. Verify on Linux before relying on it

The runner was written on a host without Linux or bubblewrap. These checks
have not been run and must be, on the runner host, before it holds a real
credential:

```bash
cargo test
cargo test bwrap_hides_runner_secrets -- --ignored
```

The first compiles and tests the Linux-only code (the signal sender id and the
file-descriptor binding for `bwrap`). The second runs a command in the real
sandbox as `terraform_user` and asserts it cannot see the runner key, the
config or another job. Then, as root on the host:

1. Start the service with a test project and confirm a job runs as
   `shoephone-terraform` (`ps -o user,cmd` during a plan), the review as
   `shoephone-review`, and that neither can read `/etc/shoephone-runner`.
2. Check that a job directory under `state_dir/jobs` is owned by the worker
   user, mode 0700, that `state_dir/jobs` itself is 0711, and that the other
   worker user cannot list it.
3. Check that the production user switch worked: the worker processes have
   no supplementary groups and no capabilities
   (`grep -E 'Cap|Groups' /proc/<pid>/status`).
4. Confirm the firewall: as `shoephone-terraform`, a connection to an unlisted
   address is rejected and counted.
