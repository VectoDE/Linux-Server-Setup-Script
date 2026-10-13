# Linux Server Setup (lss)

[![CI](https://github.com/VectoDE/Linux-Server-Setup-Script/actions/workflows/ci.yml/badge.svg)](https://github.com/VectoDE/Linux-Server-Setup-Script/actions/workflows/ci.yml)
[![Integration](https://github.com/VectoDE/Linux-Server-Setup-Script/actions/workflows/integration.yml/badge.svg)](https://github.com/VectoDE/Linux-Server-Setup-Script/actions/workflows/integration.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/VectoDE/Linux-Server-Setup-Script/badge)](https://scorecard.dev/viewer/?uri=github.com/VectoDE/Linux-Server-Setup-Script)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15442/badge)](https://www.bestpractices.dev/projects/15442)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`lss` sets up and hardens Linux servers from modules. Install everything a profile lists in one run, or only the
modules you need, and come back later to add, change or remove one. Every module checks its settings before it
touches the system, restores its files when something fails, and can prove with `lss verify` that it still works.

> Version 2.0 is in development on this branch. The 1.x install script (`install-configure-script.bash`) still works
> and is replaced when 2.0.0 is released.

## Supported systems

| Distribution                 | Releases            | Tested in CI          |
| ---------------------------- | ------------------- | --------------------- |
| Debian                       | 12, 13              | 12, 13                |
| Ubuntu                       | 22.04, 24.04, 26.04 | 22.04, 24.04, 26.04   |
| Rocky Linux, AlmaLinux, RHEL | 9, 10               | Rocky 9, AlmaLinux 10 |

x86_64 and arm64 (aarch64). CI runs on x86_64: on every pull request it installs, verifies, installs again and removes
every module on each tested system.

## System requirements

| Setup                                   | RAM                                       | Free disk | Install time            |
| --------------------------------------- | ----------------------------------------- | --------- | ----------------------- |
| Profile `minimal-secure`                | 1 GB; 2 GB on the RHEL family             | 4 GB      | 3 to 5 min plus AIDE    |
| `minimal-secure` with `crowdsec`        | 1.5 GB; 2 GB on the RHEL family           | 4.5 GB    | about 30 s more         |
| `minimal-secure` with `clamav`          | 2.5 GB                                    | 4.5 GB    | about 1 min more        |

One CPU core is enough; more cores mainly shorten the first AIDE database build. The disk figure includes the swap
file (`LSS_SWAP_SIZE`, 1 GB in the measurement), the journal (up to `LSS_LOGGING_MAX_USE`, 1 GB) and the audit logs
(up to 10 × 32 MiB). The RHEL family needs more memory because dnf loads its repository metadata during every install,
up to 0.7 GB.

The first AIDE run reads every file under the directories it watches, so its time depends on the server: 12 to 90
seconds on a fresh system, 16 minutes on a CI machine full of preinstalled toolchains. It runs with the lowest CPU and
I/O priority.

What each module costs, measured by the integration tests on all seven systems (largest value across them, rounded
up). Peak RAM covers install and `lss verify`; "while running" is what stays resident afterwards.

| Module             | Install and verify | Peak RAM                  | Disk    | While running                                       |
| ------------------ | ------------------ | ------------------------- | ------- | --------------------------------------------------- |
| `system`           | 20 s               | 170 MiB                   | 120 MiB | –                                                   |
| `time`             | 10 s               | 120 MiB                   | 125 MiB | chronyd                                             |
| `swap`             | 20 s               | –                         | swap file size | –                                            |
| `admin-user`       | 5 s                | 70 MiB                    | –       | –                                                   |
| `tools`            | 20 s               | 550 MiB (dnf), else 180 MiB | 170 MiB | –                                                 |
| `logging`          | 5 s                | 70 MiB                    | 10 MiB  | journal up to 1 GB                                  |
| `ssh-hardening`    | 35 s               | 190 MiB                   | 125 MiB | –                                                   |
| `ssh-2fa`          | 45 s               | 560 MiB (dnf), else 130 MiB | 75 MiB | –                                                  |
| `firewall`         | 5 s                | 30 MiB                    | –       | –                                                   |
| `fail2ban`         | 15 s               | 160 MiB                   | 55 MiB  | about 35 MiB                                        |
| `crowdsec`         | 30 s               | 310 MiB                   | 410 MiB | about 200 MiB (agent and firewall bouncer)          |
| `kernel-hardening` | 5 s                | 40 MiB                    | –       | –                                                   |
| `mac`              | 10 s               | 100 MiB                   | 5 MiB   | –                                                   |
| `auditd`           | 10 s               | 70 MiB                    | 5 MiB   | audit logs up to 320 MiB                            |
| `auto-updates`     | 15 s               | 260 MiB                   | 110 MiB | daily update run                                    |
| `password-policy`  | 25 s               | 250 MiB                   | –       | –                                                   |
| `aide`             | 90 s and more, see above | 190 MiB             | 130 MiB and the database | daily check                       |
| `rkhunter`         | 105 s              | 720 MiB (dnf), else 210 MiB | 110 MiB | daily check                                       |
| `clamav`           | 70 s               | 1.6 GiB                   | 215 MiB | freshclam about 20 MiB; every scan peaks at 1.6 GiB |
| `lynis`            | 25 s               | 80 MiB                    | 5 MiB   | weekly audit                                        |
| `usbguard`         | 10 s               | 90 MiB                    | 10 MiB  | usbguard-daemon                                      |
| `guard`            | 5 s                | 90 MiB                    | –       | daily check                                         |

The integration jobs print these figures as `RESOURCES` lines, so every new module and every new system adds its own.

## Quick start

```bash
git clone https://github.com/VectoDE/Linux-Server-Setup-Script.git /opt/lss
sudo ln -s /opt/lss/lss /usr/local/sbin/lss

sudo lss install --profile minimal-secure \
  --set LSS_ADMIN_USER_NAME=alice \
  --set LSS_ADMIN_USER_GITHUB_USER=alice-on-github
```

That creates the administrator `alice` with the SSH keys of the GitHub account, switches SSH to keys only, turns on
the firewall, fail2ban, kernel hardening, AppArmor or SELinux, auditing, automatic security updates, integrity checks
and the daily guard. Keep a second SSH session open the first time.

Without a command, `sudo lss` opens a menu. On the RHEL family, sudo looks for commands only in `/usr/sbin` and
`/usr/bin` until the `admin-user` module has added `/usr/local/sbin`; call `sudo /usr/local/sbin/lss` until then.

## Commands

| Command                              | What it does                                                                     |
| ------------------------------------ | -------------------------------------------------------------------------------- |
| `lss list [--group GROUP]`           | All modules and whether they are installed                                       |
| `lss info MODULE`                    | What a module does, what it needs, its settings and defaults                     |
| `lss install MODULE... \| all`       | Install modules and everything they require                                      |
| `lss install --profile NAME`         | Install the modules of a profile                                                 |
| `lss configure MODULE...`            | Apply changed settings to installed modules                                      |
| `lss verify [MODULE...]`             | Check that installed modules work and that nobody changed their files            |
| `lss status`                         | Installed modules and their services                                             |
| `lss remove MODULE... [--purge]`     | Remove modules; `--purge` also deletes their data                                |
| `lss audit`                          | Lynis audit with the hardening index                                             |
| `lss secrets show NAME`              | Print a generated secret, such as `admin-user-password`                          |

Options: `--set KEY=VALUE` for one setting, `--config FILE` for another settings file, `--dry-run` to see what
would happen, `--yes` for scripts, `--verbose` for more output.

## Settings

Settings are `KEY=value` lines in `/etc/lss/lss.conf`, named `LSS_<MODULE>_<OPTION>`:

```bash
LSS_ADMIN_USER_NAME=alice
LSS_ADMIN_USER_SSH_KEY=ssh-ed25519 AAAAC3Nz... alice@laptop
LSS_SSH_HARDENING_PORT=2222
LSS_TIME_TIMEZONE=Europe/Berlin
LSS_FIREWALL_ALLOW=8443/tcp 51820/udp
LSS_GUARD_WEBHOOK=https://ntfy.sh/your-topic
LSS_TLS_DOMAINS=server.example.com
LSS_VHOST_SITES=shop:php:shop.example.com,www.shop.example.com api:proxy:api.example.com:http://127.0.0.1:3000
```

`--set` wins over the environment, which wins over the file, which wins over the profile, which wins over the
module's default. lss parses the file and never runs it. `lss info MODULE` lists every setting of a module. After a
change, run `lss configure MODULE`.

## Modules

**Base:** `system` (host name, locale, updates, base packages), `time` (chrony with NTS), `swap`, `admin-user`,
`tools`, `logging` (persistent journal, optional TLS forwarding).

**Security:** `ssh-hardening`, `ssh-2fa`, `firewall`, `fail2ban` or `crowdsec`, `kernel-hardening`, `mac`
(AppArmor or SELinux), `auditd`, `auto-updates`, `password-policy`, `aide`, `rkhunter`, `clamav`, `lynis`,
`usbguard`, `guard`.

**Web:** `nginx`, `apache` or `caddy`, `tls` (certificates from Let's Encrypt), `vhost` (sites), `haproxy`.

**Runtimes:** `php` (PHP-FPM with a hardened pool for the web server), `composer`, `node` (Node.js 22, 24 or 26 from
NodeSource), `python` (venv, pip, pipx), `ruby` (Bundler), `java` (OpenJDK 21, Temurin where the distribution has
none), `go` (official archive), `dotnet` (.NET SDK 10, telemetry off). `LSS_PHP_VERSION`, `LSS_NODE_VERSION`,
`LSS_JAVA_VERSION` and `LSS_DOTNET_VERSION` pick another version.

**Database tools:** `phpmyadmin`, `adminer` (only the local database servers) and `pgadmin` (its own service; the
first password with `lss secrets show pgadmin-admin-password`), all on the admin port.

The [hardening guide](docs/hardening.md) lists what each security module changes, the CIS Benchmark areas it covers
and where lss deliberately deviates. Containers, backup, monitoring and mail follow as further module groups.

### Web sites

One web server owns ports 80 and 443. It answers only for the sites you set up; requests for any other host name get
no answer, and port 80 serves nothing but ACME challenges and redirects to HTTPS. A site is one entry in
`LSS_VHOST_SITES`: a name, `static`, `php` or `proxy`, its host names and, if needed, a document root or backend URL.
With the `tls` module each site gets its own certificate from Let's Encrypt; until it arrives, and without `tls`, the
site uses a self-signed certificate. The names must point to the server and port 80 must be reachable from the
internet for Let's Encrypt to issue one.

Admin interfaces such as phpMyAdmin listen on `127.0.0.1:8090`. Reach them through an SSH tunnel
(`ssh -L 8090:127.0.0.1:8090 server`, then `http://localhost:8090/phpmyadmin/`) or set
`LSS_<SERVER>_ADMIN_PUBLIC=true` to publish port 8090 with TLS and the password from
`lss secrets show web-admin-password`.

## Guard

The `guard` module checks the server every day: it runs `lss verify`, repairs modules that fail or whose files were
changed (`LSS_GUARD_AUTOFIX`), and reports failed services, full disks, pending security updates, a needed reboot, a
falling Lynis index and vulnerable packages (debsecan on Debian, `dnf updateinfo` on the RHEL family). It passes on
what the daily AIDE, rkhunter and ClamAV runs found, and reports more failed SSH logins than
`LSS_GUARD_LOGIN_THRESHOLD` with their main sources. Successful SSH logins and active fail2ban or CrowdSec bans are
listed as notes. Findings go to a webhook (Slack, Teams, Mattermost, Discord, ntfy) or by e-mail.

## Documentation

- [Architecture](docs/architecture.md): how a run works, where lss keeps its state
- [Hardening](docs/hardening.md): what the security modules change, CIS mapping, deviations
- [Troubleshooting](docs/troubleshooting.md): locked out, failed modules, common messages
- [Assurance case](docs/assurance.md): threat model, trust boundaries and how lss counters common weaknesses
- [Writing a module](docs/module-guide.md)
- [Changelog](CHANGELOG.md)

## Contributing and security

See the [contributing guide](.github/CONTRIBUTING.md). Report vulnerabilities privately as described in the
[security policy](.github/SECURITY.md).

## License

[MIT](LICENSE)
