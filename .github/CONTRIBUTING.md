# Contributing

Thanks for helping. Bug reports, fixes, new modules, support for more distributions and documentation improvements
are welcome.

## Before you start

- Security problems go through the [security policy](SECURITY.md), not through issues.
- For a new module or a new setting, open an issue first so we can agree on the name, the options and what the module
  changes on the system.

## Setup

```bash
git clone https://github.com/VectoDE/Linux-Server-Setup-Script.git
cd Linux-Server-Setup-Script
scripts/dev/install-bats.sh .bats
.bats/bin/bats tests/unit
```

Bash 5, `git` and `jq` are needed for development. The unit tests run on any Linux machine; they replace system
commands with stubs from `tests/fixtures/bin` and change nothing on your computer. The integration tests need Docker and install real packages inside systemd containers.

| Command                                                   | What it does                                                    |
| --------------------------------------------------------- | --------------------------------------------------------------- |
| `.bats/bin/bats tests/unit`                               | Unit tests of the CLI, the libraries and the module runner      |
| `scripts/dev/coverage.sh .bats`                           | Unit tests with line coverage of `lib/`; fails below 90 %       |
| `scripts/dev/lint.sh`                                     | ShellCheck and shfmt on every shell file                        |
| `tests/integration/run.sh debian-12 system fail2ban`      | Install, verify, reinstall and remove modules in a container    |
| `tests/integration/run.sh host kernel-hardening`          | The same on the machine itself, for modules that need a kernel  |

Run `host` mode only on a throwaway virtual machine: it hardens the system it runs on.

## Layout

- `lss` is the command. `lib/*.sh` holds the shared functions: packages, files with backup and restore, services,
  firewall, repositories with pinned keys, secrets, logging, the state of installed modules.
- `modules/<group>/<name>.sh` is one module. It declares its metadata (`MOD_NAME`, `MOD_REQUIRES`, `MOD_OPTIONS` and
  so on) and the functions `mod_check`, `mod_install`, `mod_configure`, `mod_verify` and `mod_remove`. The
  [module guide](../docs/module-guide.md) explains each of them.
- `templates/` holds configuration files that modules fill in, `data/repos` and `data/keys` the package repositories
  with their pinned key fingerprints, `profiles/` the module sets for `lss install --profile`.
- `libexec/lss-guard` is the guard that the `guard` module runs on a timer.

## Making a change

1. Branch from `main`: `fix/short-name` or `feat/short-name`.
2. Add or update tests. A bug fix comes with a test that fails without it. A new module gets an entry in the
   integration matrix (`.github/workflows/integration.yml`), so it is installed, verified, installed again and removed
   on every supported distribution.
3. Document new settings in the module's `MOD_OPTIONS` (that is what `lss info` shows) and in the README; add an
   entry under "Unreleased" in `CHANGELOG.md`.
4. Run the unit tests and `scripts/dev/lint.sh`.

## Coding standards

CI enforces these:

- Bash with `set -Eeuo pipefail`, ShellCheck without findings and shfmt formatting as set in `.editorconfig` (tabs).
  A ShellCheck rule is only switched off on the line it concerns, with a comment that says why.
- Modules change files only through `file_write`, `file_ensure_lines` and `file_remove`, which back up the original,
  refuse symbolic links and restore everything when a step fails. Services go through `svc_*`, packages through
  `pkg_*`, firewall rules through `fw_*`.
- Every step is idempotent: running `lss install` twice changes nothing the second time, and the integration tests
  fail if it does.
- Nothing is downloaded without a check: packages come from the distribution or from a repository in `data/repos`
  whose key fingerprint is pinned; files have a pinned SHA-256.
- Generated secrets go through `secret_get`/`secret_set`, never into logs or command lines.
- Comments explain why, not what. Messages to the user are short and say what to do next.

## Dependencies

- **On the server:** only packages of the distribution, or of the vendor repository in `data/repos` for software the
  distribution does not ship (for example CrowdSec). No `curl | sh`.
- **For development:** bats, ShellCheck, shfmt and actionlint are installed by scripts that pin the version and check
  the checksum or commit.
- **GitHub Actions and container images:** pinned to a full commit SHA or digest with the version in a comment.
  Dependabot opens weekly update pull requests; patch and minor ones merge on their own once every check passes.

## Commits and pull requests

- Write commit messages in English, imperative mood, and explain why: `Pin fail2ban's log so recidive finds it`.
- Sign off every commit (`git commit -s`). The sign-off certifies the
  [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change or have the right to
  submit it under the project's license. A check on every pull request rejects commits without a matching
  `Signed-off-by` line.
- One topic per pull request. Fill in the template.
- CI must be green before review, the integration tests on all distributions included.

## Code review

Every change reaches `main` through a pull request, and only a maintainer merges it. The reviewer reads the whole diff
and checks it against this list before approving:

1. **Purpose.** The pull request says what it changes and why, and links the issue it closes.
2. **Correctness.** The module works on every supported distribution and in a container where that makes sense; a
   failed step restores the files it changed and leaves the state file consistent.
3. **Tests.** New behaviour and every fixed bug have a test. Coverage of `lib/` stays above 90 %.
4. **Security.** No weaker default than before; no path a local user controls is written, chowned or followed as
   root; settings are validated in `mod_check` before anything changes; nothing is downloaded without a check.
5. **Lockout.** Changes to SSH, the firewall, PAM or sudo keep a way in and are covered by the lockout checks.
6. **Compatibility.** A changed setting name or default is labelled `breaking-change` with migration notes, and a
   module of the new version takes over the state an older version left (installed after `lss update`, applied with
   `lss configure`).
7. **Documentation.** README, module guide, hardening guide and `CHANGELOG.md` match the change.

## Releases

From 2.0.0 on, releases are built by the release workflow on `main`: it tags the version, attaches the archive,
`bootstrap.sh`, the Ansible collection, the SBOM and `SHA256SUMS` with a signed build attestation and publishes the
GitHub release. The version step comes from the pull request labels: `breaking-change` makes a major release,
`enhancement` a minor one, anything else a patch. Details: [releasing](../docs/releasing.md).

## License

By contributing you agree that your contribution is licensed under the [MIT License](../LICENSE).

Every new file starts with the SPDX header that the other files carry; the REUSE check in CI fails without it. Files
that cannot hold a comment are covered by `REUSE.toml`.
