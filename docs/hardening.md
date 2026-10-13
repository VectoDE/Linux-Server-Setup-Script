# Hardening

This page lists what the security modules change, which part of the CIS Benchmarks for Debian, Ubuntu and Red Hat
Enterprise Linux each one covers, and where lss deliberately does something else. Every value below can be checked on
a server with `lss verify`; the `lynis` module gives a second opinion with `lss audit`.

The profile `minimal-secure` installs everything in this list except the modules marked opt-in. On an Ubuntu 24.04
virtual machine it reaches a Lynis hardening index of 75; CI checks that it stays at 70 or above.

## What the modules do

| Module             | Changes                                                                                                                                          | CIS area                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------- |
| `admin-user`       | One administrator with SSH keys only (RSA at least 3072 bits), sudo through the sudo or wheel group, a generated password for the console      | User accounts, sudo                   |
| `ssh-hardening`    | No root login, no passwords, public keys only, `AllowGroups`, 3 tries, 30 s login grace, idle sessions closed after 15 minutes, no agent, X11 or tunnel forwarding, verbose logging, a login banner, modern key exchange (ML-KEM and sntrup761 hybrids first), AEAD ciphers first with AES-CTR as fallback, encrypt-then-MAC MACs only, DH moduli of 3072 bits and more | SSH server                            |
| `ssh-2fa` (opt-in) | A TOTP code in addition to the key, per user                                                                                                    | SSH server, authentication            |
| `firewall`         | ufw or firewalld, everything inbound closed except SSH and the ports of installed modules; a rollback timer switches it off again if SSH cannot be confirmed | Host-based firewall                   |
| `fail2ban`         | Bans after 5 failures in 10 minutes, ban time grows from 1 hour to 1 week, a recidive jail for repeat offenders, bans through nftables          | (not in CIS; defence in depth)        |
| `crowdsec` (opt-in, instead of fail2ban) | Behaviour detection with shared block lists, bouncer on nftables                                                          | (not in CIS; defence in depth)        |
| `kernel-hardening` | ASLR, restricted kernel pointers and dmesg, ptrace scope 1, unprivileged BPF off, SysRq off, protected links, FIFOs and regular files, no core dumps of setuid programs, reverse path filter, no ICMP or IPv6 redirects, no source routing, SYN cookies, martians logged; unused file systems and protocols blocked (cramfs, freevxfs, hfs, jffs2, udf, dccp, sctp, rds, tipc, FireWire, Thunderbolt, Bluetooth), USB storage blocked; core dumps off | Kernel parameters, file system modules, network parameters |
| `mac`              | AppArmor (Debian, Ubuntu) or SELinux (Rocky, AlmaLinux) enabled and enforcing                                                                    | Mandatory access control              |
| `auditd`           | Audit rules for identity files, sudoers, logins, time changes, network configuration, permission changes, failed file access, mounts, deletions, kernel modules, sudo use, cron and the MAC policy; `audit=1` on the kernel command line | System auditing                       |
| `auto-updates`     | Security updates every day (unattended-upgrades or dnf-automatic), services restarted after updates (needrestart on Debian and Ubuntu), an automatic reboot at 04:00 when an update needs one | Software updates                      |
| `password-policy`  | At least 14 characters with pwquality, account locked for 15 minutes after 5 failures (faillock), umask 027, idle shells log out after 15 minutes | Password policy, PAM, shell timeout   |
| `aide`             | File integrity database, checked every day                                                                                                      | File integrity                        |
| `rkhunter`         | Rootkit scan every day                                                                                                                          | (not in CIS)                          |
| `clamav` (opt-in)  | Virus signatures updated several times a day, daily low-priority scan of writable directories                                                    | (not in CIS)                          |
| `lynis`            | Weekly audit with the hardening index kept as history; `lss audit` fails below a minimum you set                                                | (audit tool)                          |
| `usbguard` (opt-in)| Only the USB devices present at installation are allowed                                                                                         | Removable media                       |
| `logging`          | Persistent journal with size and age limits, optional forwarding to a syslog server over TLS                                                     | Logging                               |
| `time`             | chrony with NTS-authenticated servers, no NTP port open                                                                                          | Time synchronisation                  |
| `guard`            | Runs `lss verify` every day, repairs modules that failed or were changed outside lss, reports failed units, full disks, pending security updates, a needed reboot and a low Lynis index | (operations)                          |

## Deliberate deviations

These settings differ from a strict reading of the benchmarks. Each one has a setting to change it.

| Setting                                             | lss default                         | Reason                                                                                                                                       | Change with                                       |
| --------------------------------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| IPv6 router advertisements (`accept_ra`)            | accepted                            | Many hosters configure IPv6 through router advertisements; turning them off removes the server's IPv6 address.                               | `LSS_KERNEL_HARDENING_IPV6_ROUTER_ADVERTISEMENTS=false` |
| SSH port forwarding                                 | `local` (only `ssh -L`)             | Admin interfaces that listen on localhost (databases, dashboards) are reached through an SSH tunnel instead of an open port.                 | `LSS_SSH_HARDENING_TCP_FORWARDING=no`             |
| Audit rules immutable (`-e 2`)                      | off                                 | With immutable rules, every rule change by a later module needs a reboot. Turn it on once the server is complete.                            | `LSS_AUDITD_IMMUTABLE=true`                       |
| Two-factor login                                    | opt-in                              | Each user has to enrol an authenticator app first; enforcing it before that locks them out.                                                  | install `ssh-2fa`, then `LSS_SSH_2FA_ENFORCE=true`|
| Malware scanner                                     | opt-in                              | ClamAV needs about 1.2 GB of RAM for its signatures, more than small servers have.                                                           | install `clamav`                                  |
| USB device allow-list                               | opt-in                              | Virtual servers have no USB ports; on hardware it blocks keyboards plugged in later.                                                         | install `usbguard`                                |
| Password expiry                                     | 365 days                            | NIST SP 800-63B advises against forced rotation; logins use SSH keys, so the password is only for the console and sudo.                      | `LSS_PASSWORD_POLICY_MAX_DAYS`                    |
| Automatic reboot                                    | on, 04:00                           | Kernel and libc fixes only take effect after a reboot; a server that never reboots stays vulnerable.                                         | `LSS_AUTO_UPDATES_REBOOT=false`                   |

## What lss does not do

Some benchmark items cannot be applied safely to a running server, so lss reports them instead of changing them:

- **Separate partitions** for `/tmp`, `/var`, `/var/log`, `/var/log/audit` and `/home`, and mount options such as
  `noexec` on them. They are decided when the disk is partitioned. Set them up in the installer or the image of your
  hoster; Lynis lists the missing ones.
- **A boot loader password.** It stops an unattended reboot of a remote server at the boot menu.
- **Disk encryption.** Like partitions, it is set up when the system is installed.
- **Removing packages of the distribution** that a benchmark calls unnecessary. lss installs only what its modules
  need and leaves the rest to the image you started from.
