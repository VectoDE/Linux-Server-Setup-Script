# Architecture

lss is a Bash program with no dependencies beyond what every supported distribution ships: Bash, coreutils,
systemd, `flock` and the package manager. It is built around one idea: every part of a server is a module that can be
installed, checked and removed on its own, at any time, without breaking the others.

## Parts

```text
lss                     command line, menu, locking, the run of a command
lib/
  log.sh                output, log file per run, journal (tag "lss"), masking of secrets
  os.sh                 distribution, release, architecture, container detection
  config.sh             settings: --set, environment, /etc/lss/lss.conf, profile, module default
  module.sh             module discovery, dependency order, the step runner, option helpers
  step.sh               runs one step of one module in a fresh bash process
  files.sh              managed files: write, back up, restore, detect changes made outside lss
  template.sh           {{NAME}} placeholders, without eval
  pkg.sh repo.sh fetch.sh   packages, vendor repositories with pinned keys, downloads with pinned checksums
  service.sh            systemd units, drop-ins and timers
  firewall.sh           ufw or firewalld; ports and trusted networks recorded per module
  container.sh          hardened container runs, Compose check, container firewall, Trivy
  secrets.sh state.sh   generated secrets; which modules are installed, in which version and mode
  ui.sh                 the interactive menu (whiptail, or plain prompts)
modules/<group>/        one file per module
templates/<module>/     configuration files that modules render
data/repos data/keys    vendor repositories and their public keys
profiles/               module sets with settings
libexec/lss-guard       the daily check of the guard module
libexec/lss-container-firewall   nftables rules for published container ports
bootstrap.sh            installs, updates and rolls back lss from verified releases (`lss update` runs it)
ansible/                the Ansible collection vectode.lss
scripts/release/        version, build, SBOM and checksums of a release (used by the release workflow)
```

lss itself is installed in `/opt/lss/<version>`, with `/opt/lss/current` pointing to the active version and
`/usr/local/sbin/lss` to `/opt/lss/current/lss` ([installing and upgrading](upgrading.md#where-lss-lives)).

## A run

`lss install fail2ban` goes through these stages:

1. **Start.** lss checks that it runs as root on a supported system, takes the lock `/run/lss.lock` (a second run
   started meanwhile stops at once), and opens the log file `/var/log/lss/<run id>.log`.
2. **Settings.** `/etc/lss/lss.conf`, the profile and `--set` values are parsed as `KEY=value` lines. They are never
   sourced, so a value cannot run code. `--set` wins over the environment, which wins over the file, which wins over
   the profile, which wins over the default of the module.
3. **Order.** The requested modules and everything they require are sorted so that requirements come first.
   Conflicts with each other or with installed modules stop the run before anything changes.
4. **Check.** `mod_check` of every module validates its settings. A bad value stops the run here.
5. **Apply.** For each module, `mod_install`, `mod_configure` and `mod_verify` run, each in a new bash process
   (`lib/step.sh`) that gets only the settings and paths of the run. The new process is what makes `set -e` reliable:
   Bash ignores it inside functions called from a condition, and every module step would otherwise be one.
6. **Record or restore.** When all three succeed, the module is recorded as installed with the version of lss and
   the time. When one fails, every file the module changed in this run is restored from its backup and the module is
   marked as failed; modules applied before it stay as they are.

## State

Everything lss knows about a server lives in a few places, all owned by root and not readable by others:

| Path                              | Content                                                                         |
| --------------------------------- | ------------------------------------------------------------------------------- |
| `/etc/lss/lss.conf`               | Your settings                                                                   |
| `/etc/lss/secrets/`               | Generated secrets, one file each, mode 0600                                     |
| `/var/lib/lss/modules/`           | Installed modules: status, version, mode, install and update time               |
| `/var/lib/lss/managed/`           | Checksums of managed files, to find changes made outside lss                    |
| `/var/lib/lss/firewall/`          | Ports opened per module                                                         |
| `/var/lib/lss/backup/<run>/`      | Originals of the files a run changed, per module                                |
| `/var/log/lss/`                   | One log per run; the journal has the same lines under the tag `lss`             |

Because this state is kept per module, lss can be run again at any time: to add a module, to remove one, to change a
setting (`lss configure`), or to find out whether everything still works (`lss verify`).

## Managed files and drift

Every file a module writes goes through `file_write`. It writes only when the content differs, keeps the original once
per run, and records a checksum. `lss verify` and the guard compare the checksums and report files that someone
changed afterwards; with `autofix` on, the guard runs `lss configure` for that module, which writes the file again.

Files that lss shares with the administrator, such as `authorized_keys`, are not checksummed;
lss only makes sure its own lines are there.

## Firewall

Modules never call ufw or firewalld themselves. They call `fw_allow 443/tcp`, and lss records the rule for that
module. If the firewall module is installed, the rule is applied at once; if it is installed later, it applies every
recorded rule. Removing a module closes its ports. While the firewall module enables the firewall, a timer is armed
that switches it off again after two minutes unless lss confirms that SSH still answers, so a wrong rule cannot lock
you out.

Published container ports never reach the INPUT rules of ufw or firewalld: Docker, Podman and kube-proxy redirect
them to the container address (DNAT), so the packet is forwarded. The container modules (docker, podman, k3s)
therefore install `lss-container-firewall.service`. It loads the nftables table `inet lss_containers` with a forward
chain of its own, which every forwarded packet has to pass whatever the other tables say, and which no other tool
flushes. A connection redirected to a container network passes only when its original port is listed in
`/var/lib/lss/container-ports`; lss writes that list from the `public` and `vpn` rules of every module (`vpn` keeps
its source network), and reloads the chain whenever a rule is added or removed. New connections straight to a Docker
or Podman address are dropped. Traffic the containers start themselves passes.

`fw_trust NETWORK INTERFACE` accepts everything from a network on one interface, for networks that belong to the
server, such as the k3s pod network on `cni0`. ufw matches network and interface; firewalld puts the interface into its
trusted zone. Networks broader than /8 (IPv4) or /32 (IPv6) and networks that contain the server's own address are
refused.

## Security of lss itself

- Settings files are parsed, never sourced. Templates replace `{{NAME}}` literally, without `eval` or `sed`.
- Module steps run with `set -Eeuo pipefail` and `inherit_errexit` in their own process.
- As root, lss refuses symbolic links where it writes, and runs commands inside home directories as that user.
- Vendor repositories are added only when the key matches a fingerprint pinned in the repository; downloads only
  when their SHA-256 matches.
- lss itself is installed and updated only from releases whose SHA-256 and signed build attestation verify; the code
  in `/opt/lss` belongs to root and nobody else can write it.
- Secrets are generated with the kernel's random source, stored with mode 0600, masked in logs, and passed to
  programs through files or standard input, never on the command line.
