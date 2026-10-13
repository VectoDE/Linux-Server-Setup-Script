# Troubleshooting

## Where to look

- The last lines of every run name its log file: `/var/log/lss/<run id>.log`. It has the full output of every
  command, including what the distribution's tools printed.
- `journalctl -t lss` shows the messages of all runs; `journalctl -u <service>` shows the service a module manages.
- `lss verify` checks every installed module and lists files changed outside lss. `lss status` shows the services.
- `lss info MODULE` lists the settings of a module with their defaults.

## A module failed

lss restores every file the module changed in that run and marks it as failed. Modules that ran before it stay
installed. Read the error line and the log, fix the cause (usually a setting or the network), then run the same
command again; modules that are already done report "unchanged".

## Locked out of SSH

lss checks a few things before it changes SSH, the firewall or PAM, but a mistake in the settings can still lock you
out. Use the console of your hoster (VNC, serial console or rescue system) and log in as the administrator with the
generated password (`lss secrets show admin-user-password` shows it on the server, so note it down after the first
run).

- **Firewall:** after `lss install firewall`, a timer switches the firewall off again after two minutes unless lss
  could confirm that SSH still answers. If you were cut off during the run, wait two minutes. Afterwards,
  `ufw status` or `firewall-cmd --list-all` shows the rules; add the missing port with `LSS_FIREWALL_ALLOW` and run
  `lss configure firewall`.
- **Wrong SSH port or group:** fix `LSS_SSH_HARDENING_PORT` or `LSS_SSH_HARDENING_ALLOW_GROUPS` and run
  `lss configure ssh-hardening`. To get in at once, delete `/etc/ssh/sshd_config.d/00-lss.conf` and restart `ssh`
  (Debian, Ubuntu) or `sshd` (Rocky, AlmaLinux); `lss verify` reports the missing file, and `lss configure
  ssh-hardening` writes it again.
- **Two-factor codes rejected:** check the time first (`timedatectl`); TOTP codes need a clock within 30 seconds.
  With `LSS_SSH_2FA_ENFORCE=false`, users without an enrolled secret still log in with their key.
- **Banned by fail2ban or CrowdSec:** `fail2ban-client unban <address>` or `cscli decisions delete --ip <address>`
  from the console. Add your office address to `LSS_FAIL2BAN_IGNOREIP`.

## Common messages

| Message                                                     | Cause and fix                                                                                                                                       |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Another lss run is in progress.`                           | A second lss is running, often the guard timer. Wait for it.                                                                                         |
| `No terminal to confirm; run with --yes.`                   | lss asks before it changes things. In scripts and cloud-init, pass `--yes`.                                                                          |
| `... run it on a virtual machine or bare metal ...`         | `kernel-hardening`, `swap`, `mac`, `auditd` and `usbguard` need a real kernel and refuse to run in a container.                                     |
| `Refusing repository ...: its key does not match ...`        | The vendor's key file no longer matches the pinned fingerprint. Do not override it; report it as described in the security policy.                  |
| `clamav: no signatures after 7 minutes`                     | The ClamAV mirror refused the download (it rate-limits some cloud networks) or is unreachable. The log shows freshclam's reason; run it again later. |
| `fail2ban: the configuration does not load.`                | A jail file of your own in `/etc/fail2ban/jail.d` points to a missing log. `fail2ban-client --test` names it.                                        |
| `WARN <module>: changed outside lss`                        | Someone edited a file lss manages. `lss configure <module>` writes it again; to keep the change, express it as a setting instead.                    |

## SELinux denials (Rocky, AlmaLinux)

`ausearch -m avc -ts recent` lists what SELinux blocked. lss labels the ports and paths its modules use; for your own
services, prefer `semanage port` and `semanage fcontext` over turning SELinux off. The `mac` module keeps SELinux
enforcing even when it is removed.

## Reporting a problem

Open an issue with the bug template and attach the log of the run with secrets removed. lss masks the secrets it
knows, but check settings you pasted yourself.
