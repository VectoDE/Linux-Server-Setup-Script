# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

Version 2.0.0 replaces the single install script with `lss`, a modular command. Each module installs, configures,
verifies and removes one part of the server, and you can run all of them at once, a profile, or just the ones you need,
now or later.

### Added

- `lss` command with an interactive menu and the commands `list`, `info`, `install`, `configure`, `verify`, `status`,
  `remove`, `audit`, `secrets` and `profiles`; `--dry-run`, `--set KEY=VALUE` and a settings file in
  `/etc/lss/lss.conf`.
- Module runner: requirements and conflicts are resolved, every step runs in its own process, and a failed step
  restores every file it changed. Installing again changes nothing; `lss verify` reports managed files that were
  changed outside lss.
- Base modules: `system`, `time` (chrony with NTS), `swap`, `admin-user`, `tools`, `logging`.
- Security modules: `ssh-hardening`, `ssh-2fa`, `firewall` (ufw or firewalld with a rollback timer), `fail2ban`,
  `crowdsec`, `kernel-hardening`, `mac` (AppArmor or SELinux), `auditd`, `auto-updates`, `password-policy`, `aide`,
  `rkhunter`, `clamav`, `lynis`, `usbguard` and `guard`, which checks the server on a timer, repairs drift and
  sends notifications.
- Profile `minimal-secure`.
- Web modules: `nginx`, `apache` and `caddy` (one of them owns ports 80 and 443), `tls` (certbot with a deploy hook
  that installs every certificate for the web server and reloads it), `vhost` (static, PHP and reverse-proxy sites,
  each with its own certificate) and `haproxy` (load balancing of TCP services with health checks).
- Runtime modules: `php` (PHP-FPM with a hardened, sandboxed pool on the web servers' socket), `composer`, `node`
  (NodeSource), `python` (venv, pip, pipx), `ruby` (Bundler), `java` (OpenJDK, Temurin where missing), `go` (official
  archive) and `dotnet` (.NET SDK, telemetry off), all from repositories with pinned keys or checksum-verified
  downloads.
- A warning for every setting that no module reads, so a misspelt key does not silently fall back to the default.
- Quiet output: the output of apt, dnf and long-running tools such as the AIDE database build goes to the run log,
  and appears on the terminal only with `--verbose` or, with its last 40 lines, when the command fails.
- guard reports vulnerable packages (debsecan, `dnf updateinfo`), failed SSH logins above a threshold and what the
  daily AIDE, rkhunter and ClamAV runs found, which their units had only written to the journal; successful logins
  and active bans appear as notes.
- More hardening towards a Lynis index of 85: the login banner also in `/etc/issue` and `/etc/issue.net`, costlier
  password hashes, libpam-tmpdir, process accounting, debsums, apt-show-versions, cron files and `sshd_config`
  readable by root only. minimal-secure reaches 85 to 87 on Debian.
- The AIDE, rkhunter, ClamAV and Lynis runs are confined by systemd: read-only system and home directories, no new
  privileges, writes only to their own state and logs; AIDE and ClamAV have no network.
- System requirements in the README: RAM, disk and install time for the profile and every module, measured by the
  integration tests on every supported system.
- Package repositories of vendors are added only with a pinned key fingerprint.
- Supported systems: Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, Rocky Linux 9, AlmaLinux 10. CI installs,
  verifies, reinstalls and removes every module on each of them.
- OpenSSF Scorecard, signed-off commits (DCO), REUSE licensing, security policy and governance.

### Removed

- `install-configure-script.bash` will be removed when 2.0.0 is released. Its features move into modules.

## [1.0.1] - 2025-10-22

### Added

- Several domains per server, logs and a state file of the run.
- Daily MariaDB backups kept for 14 days, `/root/.my.cnf` for the root login.
- HTTPS redirect, optional SSH hardening and automatic updates, more Fail2Ban jails.

## [1.0.0] - 2025-10-09

### Added

- Install script for Nginx, PHP-FPM, MariaDB, phpMyAdmin, Node.js, Fail2Ban, UFW or firewalld and Certbot, natively
  or with Docker.

[1.0.1]: https://github.com/VectoDE/Linux-Server-Setup-Script/compare/v1.0.0...1.0.1
[1.0.0]: https://github.com/VectoDE/Linux-Server-Setup-Script/releases/tag/v1.0.0
