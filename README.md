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

Web, runtime and database modules, measured the same way. Modules that only work together are tested together; their
row is the cost of the whole set, including the web server or PHP it needs.

| Modules tested together            | Install and verify | Peak RAM                    | Disk    | While running                         |
| ---------------------------------- | ------------------ | --------------------------- | ------- | ------------------------------------- |
| `nginx` `tls` `vhost`              | 50 s               | 640 MiB (dnf), else 270 MiB | 235 MiB | nginx, renewal timer                  |
| `apache` `tls` `vhost`             | 60 s               | 370 MiB                     | 170 MiB | Apache, renewal timer                 |
| `caddy` `tls` `vhost`              | 30 s               | 210 MiB                     | 110 MiB | Caddy, renewal timer                  |
| `haproxy`                          | 10 s               | 215 MiB                     | 10 MiB  | haproxy                               |
| `nginx` `modsecurity`              | 155 s (build)      | 1.5 GiB                     | 55 MiB  | nginx with the Core Rule Set          |
| `apache` `modsecurity`             | 45 s               | 310 MiB                     | 110 MiB | Apache with the Core Rule Set         |
| `nginx` `php`                      | 30 s               | 275 MiB                     | 125 MiB | nginx, PHP-FPM                        |
| `php` `composer`                   | 40 s               | 305 MiB                     | 285 MiB | PHP-FPM                               |
| `node`                             | 15 s               | 435 MiB                     | 285 MiB | –                                     |
| `python`                           | 30 s               | 755 MiB (dnf), else 145 MiB | 90 MiB  | –                                     |
| `java`                             | 30 s               | 485 MiB                     | 735 MiB | –                                     |
| `go`                               | 10 s               | 255 MiB                     | 285 MiB | –                                     |
| `dotnet`                           | 25 s               | 480 MiB                     | 690 MiB | –                                     |
| `ruby`                             | 15 s               | 265 MiB                     | 265 MiB | –                                     |
| `mariadb`                          | 25 s               | 470 MiB                     | 455 MiB | mariadbd                              |
| `mysql`                            | 40 s               | 900 MiB                     | 1.2 GiB | mysqld                                |
| `postgresql`                       | 25 s               | 300 MiB                     | 305 MiB | postgres                              |
| `redis`                            | 15 s               | 165 MiB                     | 95 MiB  | redis-server                          |
| `valkey`                           | 10 s               | 165 MiB                     | 85 MiB  | valkey-server                         |
| `mongodb`                          | 25 s               | 820 MiB                     | 780 MiB | mongod                                |
| `nginx` `php` `mariadb` `phpmyadmin` | 45 s               | 385 MiB                     | 170 MiB | nginx, PHP-FPM, mariadbd              |
| `caddy` `php` `adminer`            | 35 s               | 240 MiB                     | 135 MiB | Caddy, PHP-FPM                        |
| `apache` `postgresql` `pgadmin`    | 70 s               | 500 MiB                     | 705 MiB | Apache, pgAdmin (gunicorn), postgres  |

`nginx` `modsecurity` builds libmodsecurity and the nginx module from source on the first install; that is where the
time and the peak memory go. Later runs reuse the build.

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
and where lss deliberately deviates. Backup, monitoring and mail follow as further module groups.

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

## Guard

The `guard` module checks the server every day: it runs `lss verify`, repairs modules that fail or whose files were
changed (`LSS_GUARD_AUTOFIX`), and reports failed services, full disks, pending security updates, a needed reboot, a
falling Lynis index, vulnerable packages (debsecan on Debian, `dnf updateinfo` on the RHEL family) and container
images with HIGH or CRITICAL vulnerabilities (Trivy, with `docker` or `podman`). It passes on
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
