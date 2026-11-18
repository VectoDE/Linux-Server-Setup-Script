# Ansible collection vectode.lss

Sets up hardened Linux servers with [lss](https://github.com/VectoDE/Linux-Server-Setup-Script) from Ansible. The
collection is built and attached with every release of lss and has its version: collection 2.0.1 installs lss 2.0.1.

- Role `vectode.lss.lss`: installs lss on the target, writes `/etc/lss/lss.conf` and installs or removes modules.
- Module `vectode.lss.lss`: `lss install` and `lss remove` as a task, with check mode and a change only when lss
  changed something.

## Install

Download `vectode-lss-<version>.tar.gz` from the [release](https://github.com/VectoDE/Linux-Server-Setup-Script/releases),
check it, and install it:

```bash
gh attestation verify vectode-lss-2.0.1.tar.gz --repo VectoDE/Linux-Server-Setup-Script \
  --cert-identity https://github.com/VectoDE/Linux-Server-Setup-Script/.github/workflows/release.yml@refs/heads/main
ansible-galaxy collection install vectode-lss-2.0.1.tar.gz
```

The role copies `bootstrap.sh` to the target, which installs lss only after the SHA-256 and the GitHub build
attestation of the release verify (it downloads the GitHub CLI at a pinned version and checksum for that). Targets
need Python 3, `curl` and access to github.com. Supported: Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, RHEL,
Rocky Linux and AlmaLinux 9 and 10, on x86_64 and aarch64.

## Use

```yaml
- name: Hardened web server
  hosts: web
  become: true
  roles:
    - role: vectode.lss.lss
      vars:
        lss_profile: minimal-secure
        lss_modules: [nginx, tls, vhost]
        lss_settings:
          LSS_ADMIN_USER_NAME: alice
          LSS_ADMIN_USER_GITHUB_USER: alice-on-github
          LSS_TLS_DOMAINS: www.example.com
          LSS_VHOST_SITES: "site:static:www.example.com"
```

| Variable             | Default                   | Meaning                                                       |
| -------------------- | ------------------------- | ------------------------------------------------------------- |
| `lss_version`        | version of the collection | lss version to install; a different one updates or downgrades |
| `lss_settings`       | `{}`                      | `/etc/lss/lss.conf` as `KEY: value` (mode 0600)               |
| `lss_profile`        | `""`                      | profile to install                                            |
| `lss_modules`        | `[]`                      | modules to install                                            |
| `lss_modules_absent` | `[]`                      | modules to remove                                             |
| `lss_mode`           | `""`                      | `native` or `docker` for services that support both           |

The module on its own, once lss is installed:

```yaml
- name: Remove Adminer and its data
  vectode.lss.lss:
    modules: [adminer]
    state: absent
    purge: true
```

`ansible-doc vectode.lss.lss` describes every option. A second run with the same settings reports no change; check
mode runs `lss --dry-run install`, which checks every setting without changing anything.
