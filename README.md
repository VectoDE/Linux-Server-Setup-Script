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
| `docker`           | not measured yet   | not measured yet          | not measured yet | dockerd and containerd                     |
| `podman`           | not measured yet   | not measured yet          | not measured yet | – (no daemon)                              |
| `portainer`        | not measured yet   | not measured yet          | not measured yet | Portainer container, up to 512 MiB         |
| `k3s`              | not measured yet   | not measured yet          | not measured yet | k3s server, about 1 GiB with Traefik       |
| `restic`           | not measured yet   | not measured yet          | not measured yet | daily backup                               |
| `db-dumps`         | not measured yet   | not measured yet          | not measured yet | dumps before each backup                   |
| `node-exporter`    | not measured yet   | not measured yet          | not measured yet | node exporter                              |
| `prometheus`       | not measured yet   | not measured yet          | not measured yet | Prometheus and its metrics on disk         |
| `alertmanager`     | not measured yet   | not measured yet          | not measured yet | Alertmanager                               |
| `grafana`          | not measured yet   | not measured yet          | not measured yet | Grafana                                    |
| `loki`             | not measured yet   | not measured yet          | not measured yet | Loki and the logs on disk                  |
| `alloy`            | not measured yet   | not measured yet          | not measured yet | Alloy                                      |
| `netdata`          | not measured yet   | not measured yet          | not measured yet | Netdata and its plugins                    |
| `smartd`           | not measured yet   | not measured yet          | not measured yet | smartd                                     |
| `wireguard`        | not measured yet   | not measured yet          | not measured yet | – (kernel)                                 |
| `dns-resolver`     | not measured yet   | not measured yet          | not measured yet | Unbound                                    |
| `ntp-server`       | not measured yet   | not measured yet          | not measured yet | – (the chronyd of `time`)                  |

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
LSS_DOCKER_USERNS_REMAP=true
LSS_PORTAINER_ACCESS=vpn
LSS_K3S_API_ACCESS=vpn
LSS_K3S_TRAEFIK=false
LSS_RESTIC_REPOSITORY=sftp:backup@nas.example.com:/srv/restic/server1
LSS_WIREGUARD_PEERS=laptop:<public key of the laptop>:10.66.0.2
LSS_GRAFANA_ACCESS=vpn
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

**Web:** `nginx`, `apache` or `caddy`, `tls` (certificates from Let's Encrypt), `vhost` (sites), `haproxy`,
`modsecurity` (web application firewall with the OWASP Core Rule Set for nginx or Apache).

**Runtimes:** `php` (PHP-FPM with a hardened pool for the web server), `composer`, `node` (Node.js 22, 24 or 26 from
NodeSource), `python` (venv, pip, pipx), `ruby` (Bundler), `java` (OpenJDK 21, Temurin where the distribution has
none), `go` (official archive), `dotnet` (.NET SDK 10, telemetry off). `LSS_PHP_VERSION`, `LSS_NODE_VERSION`,
`LSS_JAVA_VERSION` and `LSS_DOTNET_VERSION` pick another version.

**Databases:** `mariadb` or `mysql`, `postgresql`, `redis` or `valkey`, `mongodb`. Each listens on localhost only,
with hardened authentication and optional databases and users (`LSS_<ENGINE>_USERS=user:database`, the password with
`lss secrets show <engine>-user-<user>`). `access=vpn` or `public` opens the port.

**Database tools:** `phpmyadmin`, `adminer` (only the local database servers) and `pgadmin` (its own service; the
first password with `lss secrets show pgadmin-admin-password`), all on the admin port.

**Containers:** `docker` or `podman`, `portainer` (needs one of them) and `k3s` (single-server Kubernetes; not
together with `docker`). See [Containers](#containers).

The [hardening guide](docs/hardening.md) lists what each security module changes, the CIS Benchmark areas it covers
and where lss deliberately deviates. Mail follows as a further module group.

**Backup:** `restic` (daily, encrypted backups to a local path, SFTP or S3) and `db-dumps` (dumps of the databases
before each backup). See [Backup](#backup).

**Monitoring:** `node-exporter`, `prometheus`, `alertmanager`, `grafana`, `loki`, `alloy`, `netdata`, `smartd`. See
[Monitoring](#monitoring).

**Network:** `wireguard` (VPN server), `dns-resolver` (Unbound with DNSSEC), `ntp-server` (chrony serves the time).
See [WireGuard, DNS and NTP](#wireguard-dns-and-ntp).

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

### Containers

`docker` installs Docker CE from Docker's repository (Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, the RHEL 9 and
10 family; `docker.io` from the distribution where Docker has no packages), `podman` the distribution's Podman. Both
run with limits for processes, logs and open files and the default seccomp profile; Docker also with `icc` off,
`live-restore`, `no-new-privileges` and a user namespace for containers (`LSS_DOCKER_USERNS_REMAP`).

A published port (`docker run -p 8080:80`) bypasses ufw and firewalld: the kernel redirects it to the container before
their rules apply. lss therefore adds a container firewall (`lss-container-firewall.service`, an nftables table of its
own) that lets a published port through only when a module opened it in the lss firewall, with the same scope. To
publish a port of your own container, bind it to 127.0.0.1 and put a site of the web server in front of it, or open
it with `LSS_FIREWALL_ALLOW=8080/tcp`. Without a host address Docker binds published ports to `LSS_DOCKER_BIND`
(127.0.0.1).

Containers that lss starts itself follow fixed rules: the image pinned by digest, no new privileges, no capabilities,
a read-only root file system, memory and process limits, never the engine's socket. Modules use `ctr_run` and
`ctr_compose_up` from `lib/container.sh` for that; `ctr_compose_check` checks a Compose file of your own against the
same rules.

`portainer` is the one container with the engine's socket, so it is as powerful as root and listens only on
`127.0.0.1:9443` (`LSS_PORTAINER_ACCESS=local`, through an SSH tunnel) or on the WireGuard network (`vpn`). The admin
password is `lss secrets show portainer-admin-password`. `LSS_PORTAINER_WEB_ADMIN=true` also publishes it below
`/portainer/` on the admin port of the web server.

`k3s` runs a single-server Kubernetes from a pinned, checksum-verified binary, hardened along the k3s CIS guide:
encrypted secrets, Pod Security `restricted` by default, an audit log, protected kernel defaults and SELinux on the
RHEL family. The API stays on 127.0.0.1 until `LSS_K3S_API_ACCESS` opens it; `kubectl` is installed next to it. The
profile `k8s-node` installs `minimal-secure` plus `k3s`:

```bash
sudo lss install --profile k8s-node --set LSS_ADMIN_USER_NAME=alice --set LSS_ADMIN_USER_GITHUB_USER=alice-on-github
```

With `docker` or `podman` installed, the guard scans every image daily with Trivy and reports HIGH and CRITICAL
vulnerabilities per image.

### Backup

`restic` backs up `LSS_RESTIC_PATHS` (configuration, home directories, web roots, the database dumps) every night at
`LSS_RESTIC_TIME`, keeps 7 daily, 4 weekly and 6 monthly snapshots and checks the repository after each run. The
repository is a local path (`/var/backups/lss-restic` by default; put it on another disk), `sftp:USER@HOST:/PATH` or
`s3:https://HOST/BUCKET/PATH`. lss generates the repository password; keep a copy outside the server, since no backup
can be restored without it:

```bash
sudo lss secrets show restic-password
```

For SFTP lss creates an SSH key and prints its public half, which the backup host must accept. For S3,
`LSS_RESTIC_S3_KEY_ID` and `LSS_RESTIC_S3_SECRET` go into the lss secrets. `/usr/local/lib/lss/backup restic
snapshots` runs restic with the settings of the server, and `/usr/local/lib/lss/backup restore-test` restores the
latest backup's test file and reads back 5 % of the data.

`db-dumps` dumps every database engine lss installed (MariaDB, MySQL, PostgreSQL, MongoDB, Redis, Valkey) to
`/var/backups/lss-db` before each backup. A database added later is dumped without further setup.

### Monitoring

Prometheus scrapes the node exporter, itself, Alertmanager and Loki, and alerts on unreachable targets, full disks,
low memory, guard findings and backups that failed, are older than 30 hours or did not pass the restore test.
Alertmanager sends the alerts to `LSS_ALERTMANAGER_EMAIL` or `LSS_ALERTMANAGER_WEBHOOK`. Grafana starts with
Prometheus, Alertmanager and Loki as data sources; the user is `admin`, the first password `lss secrets show
grafana-admin-password`. Alloy ships the systemd journal to Loki (Promtail reached its end of life in March 2026).

| Module          | Address                                  | `LSS_<MODULE>_WEB_ADMIN=true` |
| --------------- | ---------------------------------------- | ----------------------------- |
| `prometheus`    | `http://127.0.0.1:9090/prometheus/`      | `/prometheus/` on port 8090   |
| `alertmanager`  | `http://127.0.0.1:9093/alertmanager/`    | `/alertmanager/` on port 8090 |
| `grafana`       | `http://127.0.0.1:3000/grafana/`         | `/grafana/` on port 8090      |
| `netdata`       | `http://127.0.0.1:19999/`                | `/netdata/` on port 8090      |
| `node-exporter` | `http://127.0.0.1:9100/metrics`          | –                             |
| `loki`          | `http://127.0.0.1:3100`                  | –                             |
| `alloy`         | `http://127.0.0.1:12345` (always local)  | –                             |

With `LSS_<MODULE>_ACCESS=vpn` a module listens on the server's WireGuard address instead (the first address of
`LSS_WIREGUARD_NETWORK`, 10.66.0.1 by default) and the firewall opens its port to the WireGuard network only; Netdata
keeps 127.0.0.1 as well. That needs the `wireguard` module. Debian and Ubuntu get Prometheus, Alertmanager and the
node exporter from the distribution, the RHEL family the checksum-verified upstream releases; Grafana, Loki and Alloy
come from Grafana's repository and Netdata from Netdata's, both with pinned keys. `smartd` watches the drives, also in
virtual machines, where it usually finds none.

The profile `devops` installs `minimal-secure`, `docker` and the monitoring stack without Netdata:

```bash
sudo lss install --profile devops --set LSS_ADMIN_USER_NAME=alice --set LSS_ADMIN_USER_GITHUB_USER=alice-on-github
```

### WireGuard, DNS and NTP

`wireguard` sets up `wg0` with the server's key in the lss secrets and one preshared key per peer. Each peer is
`NAME:PUBLIC_KEY:ADDRESS` in `LSS_WIREGUARD_PEERS`; lss prints the settings a peer needs (the server's public key,
endpoint and port) after every change, and `lss secrets show wireguard-psk-NAME` the peer's preshared key. Peers reach
the server, not the networks behind it: IP forwarding stays off.

`dns-resolver` runs Unbound on 127.0.0.1 as a validating (DNSSEC) resolver and makes the server use it, through
systemd-resolved, NetworkManager or `/etc/resolv.conf`; removing the module restores the previous resolver.
`LSS_DNS_RESOLVER_ACCESS=vpn` serves the WireGuard network too, `LSS_DNS_RESOLVER_FORWARD` forwards to other
resolvers, over TLS with `LSS_DNS_RESOLVER_FORWARD_TLS=true`.

`ntp-server` opens chrony of the `time` module to the WireGuard network (or to everyone with
`LSS_NTP_SERVER_ACCESS=public`), with rate limiting.

## Guard

The `guard` module checks the server every day: it runs `lss verify`, repairs modules that fail or whose files were
changed (`LSS_GUARD_AUTOFIX`), and reports failed services, full disks, pending security updates, a needed reboot, a
falling Lynis index, vulnerable packages (debsecan on Debian, `dnf updateinfo` on the RHEL family) and container
images with HIGH or CRITICAL vulnerabilities (Trivy, with `docker` or `podman`). It passes on
what the daily AIDE, rkhunter and ClamAV runs found, and reports more failed SSH logins than
`LSS_GUARD_LOGIN_THRESHOLD` with their main sources. Successful SSH logins and active fail2ban or CrowdSec bans are
listed as notes. Findings go to a webhook (Slack, Teams, Mattermost, Discord, ntfy) or by e-mail.

With `restic` installed, the guard reports a last successful backup older than `LSS_GUARD_BACKUP_MAX_AGE` hours (30)
and runs a restore test every week. With `node-exporter` installed, the number of findings goes to Prometheus as
well, where an alert rule picks it up.

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
