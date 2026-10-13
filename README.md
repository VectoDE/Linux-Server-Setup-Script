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

Without a command, `sudo lss` opens a menu.

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

The [hardening guide](docs/hardening.md) lists what each security module changes, the CIS Benchmark areas it covers
and where lss deliberately deviates. Web servers, runtimes, databases, containers, backup, monitoring and mail follow
as further module groups.

## Guard

The `guard` module checks the server every day: it runs `lss verify`, repairs modules that fail or whose files were
changed (`LSS_GUARD_AUTOFIX`), and reports failed services, full disks, pending security updates, a needed reboot and
a falling Lynis index. Findings go to a webhook (Slack, Teams, Mattermost, Discord, ntfy) or by e-mail.

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
