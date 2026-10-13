# lss stage 1: core, CI, base and security modules

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working `lss` command with the module runner, the base and security modules, tests and CI on six
distributions, and the repository set up like Self-Updater.

**Architecture:** Bash 5 core in `lib/`, sourced by `lss`. Each module in `modules/<group>/<name>.sh` is sourced in a
subshell and implements the module contract of the spec. CI runs ShellCheck/shfmt, bats unit tests with kcov, and an
integration matrix (module x distribution) in systemd containers and on Ubuntu VMs.

**Tech Stack:** Bash 5, coreutils, systemd, whiptail; bats-core 1.x, bats-support/assert, kcov; GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-13-lss-2.0-design.md`

## Global Constraints

- Distributions: Debian 12 and 13, Ubuntu 22.04 and 24.04, RHEL family 9 and 10 (Rocky, AlmaLinux).
- Bash 5, `set -Eeuo pipefail` in every executable, ShellCheck clean with `--enable=all` minus documented exclusions.
- No `curl | bash`; every third-party key pinned by fingerprint; every direct download in `data/checksums.txt`.
- Configuration files are parsed, never sourced. Secrets never in argv, logs or compose files.
- Every module: idempotent install, `mod_verify` proves function, `mod_remove` leaves the system clean.
- License MIT, SPDX header `SPDX-FileCopyrightText: 2025-2026 VectoDE` + `SPDX-License-Identifier: MIT` in every file.
- Commits signed off (`git commit -s`).

## Review Focus

- Running `lss install` twice: the second run reports "unchanged" for every module and edits no file.
- A value with spaces, quotes, `$()` or newlines in `lss.conf` or `--set`: stored literally, never executed.
- SSH hardening on a server without a key for a sudo user: refuses with an explanation, password login stays on.
- A failing `configure` step (for example `sshd -t` fails): the replaced files are restored and the service keeps
  running with the old configuration.
- Running on an unsupported OS or as non-root: exits with a clear message before any change.

---

## File structure

| File                                     | Responsibility                                                       |
| ---------------------------------------- | -------------------------------------------------------------------- |
| `lss`                                    | CLI parsing, command dispatch                                        |
| `lib/log.sh`                             | log levels, log file, journal, secret masking, `die`                 |
| `lib/os.sh`                              | OS detection and support check                                       |
| `lib/config.sh`                          | settings store, file parser, precedence, option lookup               |
| `lib/pkg.sh`                             | apt/dnf wrappers                                                     |
| `lib/repo.sh`                            | third-party repositories with pinned keys                            |
| `lib/fetch.sh`                           | downloads verified against `data/checksums.txt`                      |
| `lib/service.sh`                         | systemd helpers and hardening drop-ins                               |
| `lib/firewall.sh`                        | ufw/firewalld abstraction, rollback timer                            |
| `lib/secrets.sh`                         | secret generation and storage                                        |
| `lib/template.sh`                        | `{{VAR}}` rendering without eval                                     |
| `lib/files.sh`                           | managed writes with backup, restore, checksums                       |
| `lib/state.sh`                           | module state                                                         |
| `lib/module.sh`                          | module discovery, metadata, dependency order, step runner            |
| `lib/ui.sh`                              | whiptail menu                                                        |
| `modules/base/*.sh`, `modules/security/*.sh` | the modules of stage 1                                           |
| `profiles/minimal-secure.conf`           | first profile                                                        |
| `tests/unit/*.bats`                      | unit tests per library                                               |
| `tests/integration/run.sh`               | install, verify, reinstall, remove for one module in one system      |
| `tests/integration/images/*.Containerfile` | systemd images per distribution                                    |
| `.github/workflows/*.yml`                | ci, integration, codeql-replacement (semgrep/shellcheck), scorecard, release, dco, auto-merge |

## Tasks

### Task 1: Logging, OS detection, configuration

**Interfaces produced:** `log_info|log_warn|log_error|log_step MSG`, `die MSG`, `log_mask VALUE`;
`os_detect` sets `OS_ID OS_VERSION OS_FAMILY(debian|rhel) OS_CODENAME OS_ARCH`, `os_require_supported`;
`config_set KEY VALUE`, `config_get KEY [DEFAULT]`, `config_load_file FILE`, `config_option MODULE KEY DEFAULT`.

- [ ] Write `tests/unit/config.bats`: values with spaces, quotes, `$(id)`, backticks and `#` are stored literally;
  invalid keys and lines without `=` fail with the line number; precedence `--set` > environment > file > default.
- [ ] Write `tests/unit/log.bats`: masked values never appear in the log file; levels; `die` exits 1.
- [ ] Write `tests/unit/os.bats` with fixture `os-release` files for all six systems plus CentOS 7 (unsupported).
- [ ] Implement `lib/log.sh`, `lib/os.sh`, `lib/config.sh` until the tests pass; commit.

### Task 2: Files, templates, secrets, state

**Interfaces produced:** `file_write MODE OWNER DEST` (content on stdin, backup of the old file, returns 0 changed /
`LSS_UNCHANGED` when identical), `files_restore_run`, `template_render SRC` (stdout; fails on unresolved `{{X}}`),
`secret_get NAME [LENGTH]`, `state_set MODULE KEY VALUE`, `state_get MODULE KEY`.

- [ ] Tests: identical content leaves mtime and backups untouched; restore brings back the previous content and mode;
  template values containing `&`, `\`, `/` and newlines render literally; secrets are 0600, stable on a second call
  and registered for masking.
- [ ] Implement `lib/files.sh`, `lib/template.sh`, `lib/secrets.sh`, `lib/state.sh`; commit.

### Task 3: Packages, repositories, downloads, services, firewall

**Interfaces produced:** `pkg_update`, `pkg_install PKG...`, `pkg_remove PKG...`, `pkg_is_installed PKG`;
`repo_add NAME` (reads `data/repos/NAME.conf` with url, suite, components, key file, fingerprint per family);
`fetch_verified NAME DEST`; `svc_enable NAME`, `svc_restart NAME`, `svc_reload NAME`, `svc_is_active NAME`,
`svc_harden NAME PROFILE`; `fw_enable`, `fw_allow SPEC`, `fw_deny SPEC`, `fw_remove SPEC`, `fw_status`.

- [ ] Unit tests with stubbed `apt-get`, `dnf`, `gpg`, `systemctl`, `ufw`, `firewall-cmd` on `PATH`: the right
  commands are called; a key with a wrong fingerprint is rejected; a download with a wrong checksum is deleted.
- [ ] Implement the libraries; commit.

### Task 4: Module runner and CLI

**Interfaces produced:** `module_list`, `module_meta NAME VAR`, `module_resolve NAME...` (ordered, with
requirements, fails on conflicts and cycles), `module_run NAME STEP`, `lss_install NAME...`.

- [ ] Tests with fixture modules in `tests/fixtures/modules`: order by requirements; cycle and conflict errors name the
  modules; a failing configure restores files and marks the module failed; second install reports unchanged;
  `--dry-run` changes nothing; unknown module and unknown command give usage errors; non-root refuses.
- [ ] Implement `lib/module.sh`, `lib/ui.sh`, `lss`; commit.

### Task 5: base modules

`system` (updates, hostname, timezone, locale), `time` (chrony with NTS servers), `swap` (swapfile sized from RAM,
swappiness), `admin-user` (user, sudo group, authorized key from option or file), `tools`, `logging` (persistent
journal with size limit, logrotate).

- [ ] Each module with `mod_check/install/configure/verify/remove`, options documented in `MOD_OPTIONS`.
- [ ] Integration test entries; commit.

### Task 6: security modules

`guard` (daily verify with auto-fix, updates with restart/reboot window, AIDE/rkhunter/ClamAV/Lynis schedules, vulnerability checks, alerts), `ssh-hardening`, `ssh-2fa`, `firewall`, `fail2ban`, `crowdsec`, `kernel-hardening`, `mac`, `auditd`,
`auto-updates`, `aide`, `rkhunter`, `clamav`, `lynis`, `usbguard`, `password-policy`; profile `minimal-secure`.

- [ ] Lockout protection tests for ssh-hardening and firewall (see Review Focus).
- [ ] Implement modules; integration entries; commit.

### Task 7: CI and repository

- [ ] Workflows: `ci.yml` (shellcheck, shfmt, bats + kcov, REUSE, actionlint, zizmor), `integration.yml` (matrix
  module x distribution, nightly profile run with Lynis threshold), `security.yml` (Gitleaks, OSV, Semgrep SARIF),
  `scorecard.yml`, `dco.yml`, `dependabot-auto-merge.yml`; `dependabot.yml`.
- [ ] Community files and docs (`README.md`, `docs/architecture.md`, `docs/module-guide.md`, `docs/hardening.md`,
  `.github/*`), `REUSE.toml`, `CHANGELOG.md`.
- [ ] Repository settings: ruleset on `main` with required checks, Discussions, Project, labels; commit; PR.
