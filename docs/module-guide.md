# Writing a module

A module is one Bash file in `modules/<group>/<name>.sh`. It installs, configures, checks and removes one part of
the server. lss finds it by its file name, so `modules/security/fail2ban.sh` is the module `fail2ban`.

## Metadata

The file starts with variables that `lss list` and `lss info` show and that the runner uses to order modules:

```bash
MOD_NAME="fail2ban"
MOD_GROUP="security"
MOD_DESCRIPTION="Bans addresses after failed logins (SSH and the jails other modules add), growing ban times"
MOD_REQUIRES="system"
MOD_CONFLICTS="crowdsec"
MOD_OPTIONS="bantime|1h|First ban duration
maxretry|5|Failures within findtime before a ban"
```

| Variable          | Meaning                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------- |
| `MOD_NAME`        | The file name without `.sh`. Quote it.                                                                    |
| `MOD_GROUP`       | The directory: `base`, `security`, and later `web`, `database` and so on.                                 |
| `MOD_DESCRIPTION` | One line that says what the module does on the server.                                                    |
| `MOD_REQUIRES`    | Modules that are installed first, separated by spaces. `a\|b` means one of them; lss keeps the one that is installed or requested, otherwise it takes the first. |
| `MOD_CONFLICTS`   | Modules that cannot run next to this one. lss refuses to install both.                                    |
| `MOD_OPTIONS`     | One option per line: `key\|default\|description`.                                                         |
| `MOD_MODES`       | `native`, `docker` or both, for services that can run either way. Missing means `native`.                 |
| `MOD_PORTS`       | The ports the module opens, for `lss info`.                                                               |
| `MOD_SECRETS`     | Names of secrets the module generates or reads, for `lss info`.                                           |

An option `bantime` of the module `fail2ban` is the setting `LSS_FAIL2BAN_BANTIME`, in `/etc/lss/lss.conf`, a
profile or `--set LSS_FAIL2BAN_BANTIME=2h`. Inside the module, read it with `opt bantime`. `opt_bool` accepts
`true/false/yes/no/on/off/1/0` and `opt_int` accepts a non-negative number; both stop the step with a clear message
on anything else. Reading an option that is not in `MOD_OPTIONS` is a bug and stops the step too.

## Steps

The runner calls up to five functions. Each one runs in its own `bash` process with `set -Eeuo pipefail` and
`inherit_errexit`, so a failing command always stops the step, and the module cannot change the variables of lss or
of another module.

| Function        | Called by                      | Job                                                                                       |
| --------------- | ------------------------------ | ----------------------------------------------------------------------------------------- |
| `mod_check`     | every command, before changes  | Validate the settings. Change nothing.                                                    |
| `mod_install`   | `install`                      | Install packages and add repositories.                                                    |
| `mod_configure` | `install`, `configure`         | Write configuration, enable services, open ports.                                         |
| `mod_verify`    | `install`, `verify`, the guard | Prove that the module works: the service runs, the port answers, the rule is active.      |
| `mod_remove`    | `remove`                       | Undo what the module did. With `--purge` (`LSS_PURGE=1`) also delete its data.            |

A missing function is skipped. When `mod_install`, `mod_configure` or `mod_verify` fails, the runner restores every
file the module changed in this run and marks it as failed; the server is back where it was.

Rules every step follows:

- **Idempotent.** The second `lss install` of the same module changes nothing and reports "unchanged". The
  integration tests install every module twice and fail when the second run changes something.
- **Validate first.** Check settings in `mod_check`, before anything changes. Compute values in plain assignments,
  not inside `$( )` or `< <( )`: `die` in a command substitution ends only the substitution, not the step.
- **Root is careful.** Never write, `chown` or `chmod` as root inside a directory a user controls (home directories,
  `/tmp`). Run such commands as the user with `runuser -u USER --`, or refuse symbolic links first.
- **No secrets in output.** Pass secrets through files or standard input, never on a command line or into a log.

## Helpers

All of `lib/` is loaded in every step. The ones modules use most:

### Files

- `file_write MODE OWNER:GROUP DEST` writes standard input to `DEST` as a managed file: lss keeps a backup, restores
  it when the step fails, and `lss verify` reports when someone changed the file later. It sets `LSS_FILE_CHANGED` to
  `1` or `0`, so a service is restarted only when its configuration changed. Feed it with a here-document or with
  `file_write … < <(command)`. A pipe (`command | file_write …`) runs it in a subshell, and `LSS_FILE_CHANGED` is lost.
- `file_ensure_lines MODE OWNER:GROUP DEST` adds the lines from standard input that are missing in a file shared with
  the administrator, such as `authorized_keys`. It refuses symbolic links.
- `file_remove PATH` deletes a managed file, with backup.
- `template_install MODULE FILE MODE OWNER DEST` renders `templates/MODULE/FILE` into `DEST`; `{{NAME}}` placeholders
  take the value of the variable `NAME`, and a
  placeholder without a value stops the step.

### Packages and repositories

- `pkg_install PACKAGE...` and `pkg_install_family "DEBIAN PACKAGES" "RHEL PACKAGES"` install what is missing.
  `pkg_remove` and `pkg_remove_family` do the reverse. `pkg_enable_epel` adds EPEL on Rocky and AlmaLinux.
- `repo_add NAME` adds the vendor repository described in `data/repos/NAME.conf`. The key in `data/keys/` must match
  the pinned `FINGERPRINTS`, or lss stops. Keep a comment in the file that says where the key came from and when.
- `fetch_verified NAME DEST` downloads a file whose SHA-256 is pinned per architecture.

### Services

- `svc_enable UNIT`, `svc_disable UNIT`, `svc_restart UNIT`, `svc_reload UNIT`, `svc_is_active UNIT`.
- `svc_unit UNIT` writes a unit of lss to `/etc/systemd/system` from standard input and reloads systemd when it
  changed. Timers of lss are named `lss-<module>…`.
- `svc_dropin UNIT NAME` writes standard input as a drop-in for a unit of the distribution instead of replacing it.
- `svc_wait_port HOST PORT SECONDS` waits for a service to listen.

### Firewall

- `fw_allow 443/tcp 51820/udp:vpn` opens ports for the module. The scope after the colon is `public` (default),
  `vpn` (only from the VPN network) or `local` (nothing is opened). lss records the rule for the module, applies it
  when the firewall module is installed (also later), and closes it again when the module is removed.
- `fw_trust NETWORK INTERFACE` accepts all traffic from NETWORK arriving on INTERFACE, recorded and removed like a
  port. Only for networks of the server itself (a pod network on its bridge).

### Monitoring and admin interfaces

`lib/monitoring.sh` is for services with a web interface or an API, so they all bind, open and publish the same way:

- `mon_address MODULE` is 127.0.0.1, or the server's WireGuard address (`fw_vpn_address`) with
  `LSS_<MODULE>_ACCESS=vpn`; `mon_vpn_dropin UNIT` starts the unit after `wg0` in that case, and `mon_firewall
  PORT/PROTO...` opens the ports to the WireGuard network only.
- `mon_web_admin KIND URL` publishes the interface below the web server's admin port when `LSS_<MODULE>_WEB_ADMIN`
  is true (`proxy` keeps the path, `strip` removes the prefix); `mon_web_admin_remove` takes it away.
- `mon_target NAME JOB HOST:PORT [PATH]` adds a Prometheus scrape target, `mon_datasource NAME TYPE URL` a Grafana data
  source; both have a `_remove` counterpart.
- `mon_upstream_install NAME VERSION PROGRAM...` installs programs from a release archive listed in
  `data/checksums.txt`; `mon_install_stopped PKG...` installs Debian packages without letting them start their
  service before lss configured it.
- `mon_wait_http URL [SECONDS]` and `mon_listen_check [--process NAME] PORT ADDRESS...` are for `mod_verify`.

### Containers

- `ctr_run NAME IMAGE [OPTION...] [-- COMMAND...]` runs a container with the engine of the server (docker or podman)
  under the rules of `lib/container.sh`: the image as `registry/name@sha256:...`, `--publish ADDRESS:PORT:PORT`
  with an address, `--volume` with named volumes or host paths outside system directories (a container may mount its
  own `/etc/lss/containers/NAME`), `--cap` for single capabilities, `--memory` and `--pids` for other limits,
  `--writable` only when the image cannot run with a read-only root. A container with the same definition is left
  alone. `ctr_remove NAME` deletes it; named volumes stay.
- `ctr_compose_check FILE` and `ctr_compose_up PROJECT FILE` do the same for Compose files (Docker only).
- `ctr_firewall_setup` is for engine modules only; published ports are opened with `fw_allow` like any other port.

### Secrets, system and logging

- `secret_get NAME [LENGTH]` returns a generated secret and creates it on first use; `secret_set NAME VALUE` stores
  one from the settings. They live in `/etc/lss/secrets`, mode 0600. `lss secrets show NAME` prints one.
- `os_is_debian`, `os_is_rhel`, `OS_ID`, `OS_VERSION`, `OS_MAJOR`, `OS_CODENAME` and `os_in_container` describe the system.
- `log_info`, `log_warn`, `log_ok` print and log; `die MESSAGE` stops the step.

## Tests

1. Unit tests in `tests/unit` cover the libraries; add one when a module needs a new helper.
2. Add the module to a group of the matrix in `.github/workflows/integration.yml`. The harness installs it on every
   supported distribution in a container with systemd, verifies it, installs it again (which must change nothing) and
   removes it. A module that needs a real kernel (sysctl, firewall, swap) goes into the `host` job, which runs on a
   virtual machine.
3. Run it yourself with `tests/integration/run.sh debian-13 system <module>`.

## Checklist

- [ ] Metadata complete; every option has a safe default and a description
- [ ] `mod_check` rejects every invalid setting with a message that names the setting
- [ ] Installing twice reports "unchanged"
- [ ] `mod_verify` proves that it works, not only that a package is installed
- [ ] `mod_remove` leaves no lss file and no open port behind
- [ ] Integration tests green on all distributions
