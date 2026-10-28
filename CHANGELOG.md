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
- `modsecurity`: the ModSecurity web application firewall with the OWASP Core Rule Set for nginx and Apache on every
  supported system, with a module built from verified sources where the distribution has none.
- Database modules: `mariadb`, `mysql`, `postgresql`, `redis`, `valkey` and `mongodb`, on localhost with hardened
  authentication, optional databases and least-privilege users; root or admin accounts never exist without a password.
- Profiles `webhosting` and `all`.
- Database tools: `phpmyadmin`, `adminer` and `pgadmin` on the admin port of the web server, from checksum-verified
  downloads, limited to the local database servers; pgAdmin runs as its own sandboxed service.
- Container modules: `docker` (Docker CE from Docker's repository with a hardened daemon after CIS Docker), `podman`
  (from the distribution), `portainer` (pinned image, on 127.0.0.1 or the WireGuard network, the only container with
  the engine socket) and `k3s` (pinned, checksum-verified single-server Kubernetes after the k3s CIS hardening guide,
  with k3s-selinux on the RHEL family).
- Container firewall: published container ports pass only where a module opened the port in the lss firewall, on ufw
  and firewalld alike; `fw_trust` binds trusted networks to their interface.
- `lib/container.sh`: containers of lss run with a digest-pinned image, no new privileges, no capabilities, a
  read-only root, memory and process limits and never the engine socket; host paths are checked after following
  symbolic links. Compose files are checked against the same rules.
- guard scans the images of Docker and Podman daily with Trivy and reports HIGH and CRITICAL vulnerabilities.
- Profile `k8s-node` (minimal-secure plus k3s); `all` includes docker and portainer.
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
- Backup modules: `restic` (encrypted daily backups to a local path, SFTP or S3, retention, repository checks, the
  password and keys in the lss secrets) and `db-dumps` (consistent dumps of every database engine lss installed,
  taken before each backup).
- Monitoring modules: `node-exporter`, `prometheus` (with alert rules for down targets, full disks, guard findings and
  old or failed backups), `alertmanager` (e-mail and webhook), `grafana`, `loki`, `alloy` (Promtail's successor; it
  ships the journal to Loki), `netdata` (never claimed to Netdata Cloud, no registry or telemetry) and `smartd`.
  Every interface listens on 127.0.0.1 or, with `access=vpn`, on the WireGuard address, and can be published below
  the web server's admin port.
- Network modules: `wireguard` (server with peers from the settings, keys in the lss secrets), `dns-resolver` (Unbound
  with DNSSEC on localhost, optionally for the WireGuard network, used by the server itself) and `ntp-server` (chrony of
  the time module serves the WireGuard network or everyone, rate-limited).
- Profile `devops` (minimal-secure, Docker and the monitoring stack); `webhosting` adds restic and db-dumps, `all`
  every new module.
- Mail modules: `mail-relay` (send-only Postfix on the loopback addresses, through a smarthost with a checked
  certificate or directly with opportunistic TLS or DANE), `mailserver` (Postfix, Dovecot and Rspamd: submission with
  TLS and login only, senders tied to their login, spam filter, DKIM signing, SPF, DKIM and DMARC checks; it prints the
  MX, SPF, DKIM, DMARC and PTR records to set) and `webmail` (checksum-verified Roundcube on the web server). guard
  sends its e-mail through them. Profile `office`; `all` adds mailserver and webmail.
- guard checks the age of the last backup (`LSS_GUARD_BACKUP_MAX_AGE`), runs a restore test every week and exports
  its results for Prometheus through the node exporter.
- The services of the backup, monitoring and network modules run with a systemd sandbox drop-in; a service that
  listens on the WireGuard address starts after the interface.
- Website on GitHub Pages: lss explained as a film that plays while scrolling, generated from the module metadata,
  the profiles and `data/systems.conf` on every deploy. A field of packets drawn on a canvas closes into a shield
  while the module groups pass. Strict Content Security Policy, a still version for reduced motion and Lighthouse
  100 checked in CI.

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
