# Installing and upgrading lss

lss is installed from signed releases. `bootstrap.sh` puts the first version on a server, `lss update` brings later
ones, goes back to an older one or rolls back to the version before. Both check every release the same way before any
of its code runs.

## What gets checked

Each release on GitHub carries these files:

| File                           | What it is                                                                          |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| `lss-<version>.tar.gz`         | lss itself, unpacked to `/opt/lss/<version>`                                        |
| `bootstrap.sh`                 | the installer                                                                       |
| `vectode-lss-<version>.tar.gz` | the [Ansible collection](../ansible/README.md) of that version                      |
| `lss-<version>.cdx.json`       | software bill of materials (CycloneDX): lss and everything it downloads by checksum |
| `SHA256SUMS`                   | SHA-256 of the files above                                                          |
| `lss-<version>.intoto.jsonl`   | the signed build attestation of all of them (Sigstore bundle, SLSA provenance)      |

Before it installs a version, `bootstrap.sh` (and `lss update`, which runs the `bootstrap.sh` of the installed
version):

1. downloads `SHA256SUMS`, the archive and the attestation over HTTPS;
2. compares the SHA-256 of the archive with `SHA256SUMS`;
3. downloads the GitHub CLI at a pinned version and checks it against the SHA-256 written into `bootstrap.sh`;
4. checks with `gh attestation verify` that the attestation covers `SHA256SUMS` and the archive, was signed by the
   workflow `.github/workflows/release.yml` of `VectoDE/Linux-Server-Setup-Script` running on `refs/heads/main`, on a
   GitHub-hosted runner, and is logged in the public Sigstore transparency log.

If any step fails, nothing is unpacked and the active version stays as it is. The checks need no GitHub account or
token.

## First installation

Download `bootstrap.sh` from the [latest release](https://github.com/VectoDE/Linux-Server-Setup-Script/releases/latest)
and check it before you run it as root. With the GitHub CLI on any machine:

```bash
gh release download -R VectoDE/Linux-Server-Setup-Script --pattern bootstrap.sh
gh attestation verify bootstrap.sh --repo VectoDE/Linux-Server-Setup-Script \
  --cert-identity https://github.com/VectoDE/Linux-Server-Setup-Script/.github/workflows/release.yml@refs/heads/main
sudo bash bootstrap.sh
```

Without the GitHub CLI, compare `sha256sum bootstrap.sh` with the line for `bootstrap.sh` in the release's
`SHA256SUMS`, which the release page shows. `sudo bash bootstrap.sh 2.0.1` installs a given version instead of the
latest. The server needs `curl`, `tar` and access to github.com.

## Where lss lives

| Path                       | Content                                                                          |
| -------------------------- | -------------------------------------------------------------------------------- |
| `/opt/lss/<version>`       | one directory per installed version, owned by root, writable only by root        |
| `/opt/lss/current`         | symbolic link to the active version                                              |
| `/opt/lss/previous`        | symbolic link to the version that was active before, for `lss update --rollback` |
| `/usr/local/sbin/lss`      | symbolic link to `/opt/lss/current/lss`                                          |
| `/etc/lss`, `/var/lib/lss` | settings, secrets and state; an update or rollback leaves them as they are       |

The links are replaced with a single rename, so at every moment `lss` is either the old or the new version. Versions
other than the active and the previous one are deleted after an update. Each version directory has a file list
(`.lss-manifest`, SHA-256 of every file), and a rollback refuses a version whose files changed since it was installed.

## lss update

| Command                      | What it does                                                      |
| ---------------------------- | ----------------------------------------------------------------- |
| `sudo lss update`            | installs the latest release; never goes back to an older version  |
| `sudo lss update 2.1.0`      | installs exactly this version, newer or older than the active one |
| `sudo lss update --rollback` | switches back to the previous version, without a download         |
| `sudo lss --dry-run update`  | downloads and checks the release, changes nothing                 |

After the new version is active, lss starts it once (`lss version`); if it does not answer with its version, the
links go back to the version before. Then run `sudo lss verify`. A new version can harden a module further; `sudo lss
configure MODULE...` applies the new configuration to modules that are installed already. Read the release notes for
settings that changed: a renamed setting is listed under "Breaking changes", and lss warns about every setting that no
module reads.

A downgrade (`lss update` with an older version) keeps the state and settings of the newer one. lss warns about
settings the older version does not know; modules the older version does not have stay installed but are no longer
managed by it (no verify, no removal) until you update again.

## From a 2.0 development checkout

Servers that ran a development version of 2.0 from a git checkout in `/opt/lss` move it away first, then install the
release; settings and state stay:

```bash
sudo mv /opt/lss /opt/lss.checkout
sudo bash bootstrap.sh
sudo lss verify
sudo rm -rf /opt/lss.checkout
```

## From 1.x

The 1.x script `install-configure-script.bash` is gone with 2.0.0. It set up one web stack in a single run and kept no
state that lss could take over, so the upgrade is a fresh setup with lss on top of the existing server. Plan for a
maintenance window and a backup first; keep a second SSH session open while the SSH and firewall modules run.

1. Back up the databases and the web roots: `mysqldump --defaults-file=/root/.my.cnf --all-databases`, and
   `/var/www`.
2. Install lss with `bootstrap.sh` (above).
3. Write `/etc/lss/lss.conf` with what the 1.x options did, and install the modules:

| 1.x option or feature                                | lss 2.0                                                                                                           |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `--domains "a.com,www.a.com;b.com"`                  | `LSS_VHOST_SITES=a:php:a.com,www.a.com b:php:b.com` and `LSS_TLS_DOMAINS`; modules `nginx`, `php`, `tls`, `vhost` |
| `--email`                                            | `LSS_TLS_EMAIL`                                                                                                   |
| `--php 8.2`                                          | `LSS_PHP_VERSION=8.2`                                                                                             |
| MariaDB with a root password in `/root/.my.cnf`      | module `mariadb`: root logs in through the Unix socket; application users with `LSS_MARIADB_USERS`                |
| phpMyAdmin under `/phpmyadmin`                       | module `phpmyadmin` on the admin port of the web server (127.0.0.1:8090 by default)                               |
| Node.js                                              | module `node`                                                                                                     |
| Fail2Ban (`/etc/fail2ban/jail.d/hardening.conf`)     | module `fail2ban`                                                                                                 |
| UFW or firewalld                                     | module `firewall`                                                                                                 |
| `ENABLE_AUTO_UPDATES`                                | module `auto-updates`                                                                                             |
| `ENABLE_SSH_HARDENING`                               | modules `ssh-hardening` and `admin-user`                                                                          |
| daily MariaDB dump (`/etc/cron.d/mariadb-backup`)    | modules `db-dumps` and `restic`                                                                                   |
| `--mode docker` (`/opt/<domain>/docker-compose.yml`) | `--mode docker` where a module supports it; lss does not take over the 1.x stacks                                 |

   For a typical 1.x server: `sudo lss install --profile webhosting`, or the modules from the table.

4. lss writes its own nginx configuration; the 1.x sites in `/etc/nginx/sites-available` and `/etc/nginx/conf.d` are
   no longer included. Recreate each one as an entry of `LSS_VHOST_SITES`, pointing at the same document root.
5. Remove what 1.x left behind once the modules run: `/etc/ssh/sshd_config.d/99-enterprise-hardening.conf`,
   `/etc/fail2ban/jail.d/hardening.conf`, `/etc/cron.d/mariadb-backup`, `/usr/local/sbin/backup-mariadb.sh`, the
   state in `/var/local/enterprise-server-setup` and the log `/var/log/enterprise-server-setup.log`. Keep
   `/root/.my.cnf` until the `mariadb` module is installed, then delete it: root no longer needs a password.
6. `sudo lss verify` checks every module; `sudo lss audit` shows the Lynis hardening index.

Docker stacks that 1.x wrote to `/opt/<domain>` keep running; move them to modules (`docker`, `vhost` as a reverse
proxy) when convenient.
