# Security policy

## Supported versions

| Version | Supported                                                                 |
| ------- | ------------------------------------------------------------------------- |
| 2.x     | Yes. Fixes ship in a new patch or minor release of the latest 2.x         |
| 1.x     | No. The single install script is replaced by `lss`; see the README        |

Only the latest release of a major version is supported. When a new major version comes out, the previous one keeps
getting security fixes for six months; the end date is added to this table and announced in the changelog.

## Reporting a vulnerability

Do not open a public issue. Report privately through
[GitHub Security Advisories](https://github.com/VectoDE/Linux-Server-Setup-Script/security/advisories/new).

Please include the version (`lss version`), the distribution, the modules involved, the relevant settings without
secrets, the steps that show the problem and the impact as you see it.

## What happens next

1. You get an answer within 7 days that confirms the report or asks for details.
2. The maintainer reproduces the problem in a private advisory and agrees on a severity with you (CVSS).
3. The fix is developed in the advisory's private fork, with a test, and released as a patch version. Medium and
   higher issues are fixed within 60 days, critical ones as fast as possible.
4. The advisory is published with a CVE where one applies, and the changelog lists the fix under "Security".
5. You are credited in the advisory and the changelog, unless you prefer to stay anonymous.

## What counts as a vulnerability

lss runs as root and changes the security configuration of a server, so these count:

- A module that leaves the system less secure than documented: a port open that the firewall should close, a weaker
  SSH algorithm than `ssh-hardening` promises, a check that `lss verify` reports as passing while it is not
- A generated secret or a value from the settings file that ends up in logs, the process list, world-readable files
  or the guard notifications
- A local user without root rights who can make lss write, change the owner of or follow a link to a file of their
  choice (symlink races in home directories, `/tmp` or other writable places)
- A package repository or key added without the pinned fingerprint check, or a download used without its checksum
- Command injection through values that do not come from the root-owned settings file (user names from the system,
  data from package metadata, guard input)
- A lockout: a run that leaves SSH unreachable although the lockout checks passed

A known vulnerability in a GitHub Action or container image used by this repository that does not affect lss is
documented as an [OpenVEX](https://openvex.dev/) statement in `.vex/`, with the reason. There are none today.

## Not a vulnerability

- Settings that root writes: whoever can edit `/etc/lss/lss.conf` or pass `--set` is root already.
- Findings of Lynis or another scanner on a default lss installation that the [hardening guide](../docs/hardening.md)
  lists as a deliberate deviation with its reason.
- Vulnerabilities in the packages of the distribution. lss installs them from the distribution or the vendor
  repository and keeps them updated with the `auto-updates` module; report them to the distribution.

## Verifying a release

From 2.0.0 on, releases are built only by the release workflow of this repository, never from a laptop. Each release
carries a signed build attestation (Sigstore, SLSA provenance) that names this repository, the workflow and the
commit. Verify a downloaded file with the GitHub CLI, naming the release workflow on `main` as the signer:

```bash
gh attestation verify lss-<version>.tar.gz --repo VectoDE/Linux-Server-Setup-Script \
  --cert-identity https://github.com/VectoDE/Linux-Server-Setup-Script/.github/workflows/release.yml@refs/heads/main
```

`bootstrap.sh` and `lss update` check the checksum and the attestation of every version before they install it and
refuse a release that does not verify ([installing and upgrading](../docs/upgrading.md#what-gets-checked)).

## Secrets and credentials

- Workflows use the short-lived `GITHUB_TOKEN`, attestations the workflow's OIDC identity. The only stored secrets
  are the deploy key and the SSH signing key of the release commit and tag, in the environment `release`, which only
  `main` can use and only the job that commits and tags reads ([releasing](../docs/releasing.md)).
- On a server, lss keeps generated secrets (passwords, 2FA enrolment) in `/etc/lss/secrets`, mode 0600 in a 0700 directory, and
  shows them only with `lss secrets show NAME`. They never go into logs.
- Secrets are never committed. gitleaks in CI and GitHub secret scanning with push protection block leaks.
- Access to repository settings is listed in the [governance](GOVERNANCE.md#access-to-sensitive-resources) document.
