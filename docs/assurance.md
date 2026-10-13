# Assurance case

Why lss can be trusted with root on a server: what it protects, who might attack it, where the trust boundaries are,
and how the design and the tests counter the attacks. Vulnerabilities are reported as described in the
[security policy](../.github/SECURITY.md).

## Claim

Running lss leaves a server in the documented, hardened state or, when a step fails, in the state it was in before
that step. lss itself does not open a way for someone without root rights to gain them, to read its secrets or to
change what it installs.

## Assets

- Root on the managed server, and the services lss configures there
- The generated secrets in `/etc/lss/secrets` (admin password, 2FA enrolment, service passwords)
- The SSH access of the administrator: a run must never lock them out
- The integrity of what lss installs: packages, vendor repositories, downloaded files
- The integrity of lss itself: its code, its releases and this repository

## Attackers

| Attacker                                     | What they can do                                                                 |
| -------------------------------------------- | -------------------------------------------------------------------------------- |
| Local user without root on the server        | Write in their home, `/tmp` and other writable places; run processes; read world-readable files |
| Someone on the network path                  | Read and change unencrypted traffic, serve a fake mirror or download             |
| A compromised or malicious vendor repository | Serve packages or metadata that lss installs                                     |
| A contributor with a malicious change        | Open pull requests against this repository                                       |
| An attacker after a GitHub account or action | Change the repository, a workflow or a release                                   |

Root on the server is not an attacker: whoever can edit `/etc/lss/lss.conf` or run `lss` already has root.

## Trust boundaries and how they are protected

### Settings and command line

Settings come from root-owned files and the command line. They are parsed as `KEY=value` lines and never sourced,
so a value cannot run code. Every module validates its settings in `mod_check` (user names, ports, paths, times, key
formats) before the first change, and an unknown setting is reported so that a typo does not silently fall back to a
default. Templates replace `{{NAME}}` literally, without `eval` or `sed`.

### Files in places a local user controls

lss runs as root and writes into home directories (`authorized_keys`), `/etc` and `/var`. `file_write` writes the
content to a private temporary file (mode 0600) next to the destination, sets mode and owner and then renames it into
place. A rename replaces a symbolic link instead of following it, and nobody ever sees a half-written file or one with
the wrong mode. The original is backed up first. In home directories, `file_ensure_lines` and the modules refuse a
destination or a `.ssh` directory that is a symbolic link, and commands that work on a user's own files, such as the
2FA enrolment, run as that user (`runuser`), so a link planted there cannot redirect a root write. A run holds
`/run/lss.lock`, so two runs cannot interleave.

### Network and packages

Packages come from the distribution or from a vendor repository in `data/repos`. A vendor key is accepted only when
its fingerprint matches the one pinned in the repository; apt limits the key to that repository with `Signed-By`,
dnf checks package signatures with `gpgcheck`. A repository configuration without a signature check is refused.
Single files are downloaded only over HTTPS with TLS 1.2 or later (`curl --proto =https --tlsv1.2`) and used only
when their SHA-256 matches the pinned value. There is no `curl | sh`.

### Secrets

Secrets are generated from the kernel's random source (`/dev/urandom`), stored one per file with mode 0600 in a 0700
directory, masked in logs and passed to programs through files or standard input, never as command line arguments,
where other users could read them in the process list. Guard notifications contain findings, not secrets.

### Remote access

Changes to SSH, the firewall, PAM and sudo keep a way in. Before sshd is restarted, lss checks that an administrator
key is in place and that the new configuration passes `sshd -t`; the new SSH port is opened in the firewall before
sshd moves to it. When the firewall is enabled, a timer switches it off again after two minutes unless lss confirms
that SSH still answers. A failed step restores every file it changed.

### This repository and its releases

Every change reaches `main` through a pull request with 28 required checks (lint, unit tests with coverage, workflow
and licence checks, secret scanning, sign-off and the integration tests on six distributions); force pushes and
deletion of `main` are blocked. Workflows run with read-only tokens by default, pin every action to a commit SHA and
are checked by actionlint and zizmor. From 2.0.0 on, releases are built only by the release workflow and carry a
signed build attestation that `lss update` verifies before it installs a version.

## Secure design principles

| Principle                  | How lss applies it                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------------------ |
| Economy of mechanism       | Plain Bash and the tools every distribution ships; no runtime dependencies, no daemon of its own       |
| Fail-safe defaults         | Modules default to the stricter choice (keys only, no root login, deny incoming); options that weaken it are opt-in |
| Complete mediation         | Every file, package, service and firewall change goes through the `file_*`, `pkg_*`, `svc_*` and `fw_*` helpers, which apply the checks above |
| Open design                | All code, settings and the reasons for deviations from CIS are public ([hardening guide](hardening.md)) |
| Separation of privilege    | Changes to `main` need a pull request with passing checks; releases need the release workflow           |
| Least privilege            | Workflows start with `contents: read`; commands on a user's own files run as that user; secrets are readable by root only |
| Least common mechanism     | Each module step runs in its own process with only the settings of the run                             |
| Psychological acceptability| One command per task, `lss verify` to prove the result, messages that say what to do next             |
| Recoverability             | Every changed file is backed up per run and restored when a step fails                                 |

## Common weaknesses countered

| Weakness                                              | Countermeasure                                                                |
| ----------------------------------------------------- | ----------------------------------------------------------------------------- |
| CWE-78 OS command injection                           | Settings are validated against strict patterns and passed as arguments, never through `eval`; ShellCheck enforces quoting |
| CWE-59 and CWE-61 link following                      | Files are replaced by rename, which never follows a link; writes in home directories refuse links; user commands run as the user |
| CWE-367 race between check and use                    | Content, mode and owner are set on a private temporary file before the atomic rename; one run at a time through the lock |
| CWE-214 and CWE-532 secrets in process list or logs   | Secrets go through files or standard input and are masked in logs             |
| CWE-276 and CWE-732 wrong permissions                 | Every managed file is written with an explicit mode and owner                 |
| CWE-494 download without integrity check              | Pinned SHA-256 for files, pinned key fingerprints for repositories            |
| CWE-330 weak random values                            | Secrets come from `/dev/urandom`                                              |
| CWE-327 broken cryptography                           | SSH allows only modern key exchange, ciphers, MACs and moduli of 3072 bits or more; nothing lss configures falls back to SHA-1 or CBC |
| Lockout (availability)                                | SSH and firewall changes are checked before they take effect and rolled back on failure |

## Evidence

- Unit tests (bats) cover the CLI, the libraries and the module runner, including link refusal, setting validation,
  restore on failure and the repository signature checks; line coverage of `lib/` is above 90 % and enforced in CI.
- The integration tests install, verify, reinstall (which must change nothing) and remove every module on six
  distributions, and run the `minimal-secure` profile on a virtual machine followed by a Lynis audit that must
  reach a hardening index of 70.
- ShellCheck, shfmt, SonarQube Cloud, actionlint, zizmor, gitleaks and the REUSE check run on every pull request.
