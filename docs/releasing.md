# Releasing

Releases are made by the [release workflow](../.github/workflows/release.yml), never from a laptop. Every push to
`main` (a merged pull request) becomes a release:

1. **Pick the version and check.** `scripts/release/prepare.sh` reads the commits since the last version tag and the
   labels of their pull requests: `breaking-change` (or `type!:`, `BREAKING CHANGE`) makes a major release,
   `enhancement` (or `feat:`) a minor one, everything else a patch. While `VERSION` carries a pre-release suffix such
   as `2.0.0-dev`, the release is that version without the suffix. The script writes the version to `VERSION`,
   `ansible/galaxy.yml` and the default of the role `vectode.lss.lss`, and turns `## Unreleased` in `CHANGELOG.md`
   into the section of the release. The unit tests run on the result.
2. **Commit and tag.** A job without any code of the repository applies exactly that change (it refuses a change to
   any other file), signs the commit and the tag with the release SSH key and pushes both with the deploy key, the
   only actor allowed past the rulesets of `main` and of the tags.
3. **Build and sign.** `scripts/release/build.sh` builds `lss-<version>.tar.gz`, `bootstrap.sh`, the Ansible
   collection `vectode-lss-<version>.tar.gz`, the CycloneDX SBOM `lss-<version>.cdx.json` and `SHA256SUMS` from the
   tagged commit. `actions/attest-build-provenance` signs one SLSA provenance attestation for all of them with the
   workflow's OIDC identity (Sigstore, no stored key) and keeps it as `lss-<version>.intoto.jsonl`.
4. **Publish.** The GitHub release gets the six files and the notes from the changelog.

`bootstrap.sh` and `lss update` accept only releases whose attestation was signed by `release.yml` on
`refs/heads/main` ([upgrading](upgrading.md#what-gets-checked)). A commit message containing `[skip release]` leaves a
push out; the release commit carries it, so it does not release itself.

The workflow can be started by hand on `main`: with a version step, with a pre-release name such as `rc.1` (makes
`2.0.0-rc.1` without touching the changelog; a test of the workflow or a release candidate), or with `attach` to
build and attach the files of an existing tag again. Each step skips what exists already, so a rerun is safe.

The same build runs on every pull request: `.github/workflows/distribution.yml` builds two test releases with
`scripts/release/build.sh`, attests them with its own identity and installs, updates, rolls back and downgrades them
with `bootstrap.sh` on every supported system, refuses tampered copies, and runs the Ansible collection against the
same systems.

## Setting up the repository (owner)

These settings are needed once, before the first release. They are not in the repository and change who can push,
so only the owner applies them.

1. **Environment `release`**, usable from `main` only:

   ```bash
   gh api -X PUT repos/VectoDE/Linux-Server-Setup-Script/environments/release \
     -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
   gh api -X POST repos/VectoDE/Linux-Server-Setup-Script/environments/release/deployment-branch-policies \
     -f name=main -f type=branch
   ```

2. **Deploy key** with write access, its private half as the environment secret `RELEASE_DEPLOY_KEY`:

   ```bash
   ssh-keygen -t ed25519 -N '' -C 'lss release workflow' -f release-deploy-key
   gh repo deploy-key add release-deploy-key.pub -R VectoDE/Linux-Server-Setup-Script --allow-write \
     --title 'Release workflow'
   gh secret set RELEASE_DEPLOY_KEY -R VectoDE/Linux-Server-Setup-Script --env release < release-deploy-key
   rm release-deploy-key release-deploy-key.pub
   ```

3. **Signing key**: the private half of the SSH key in `.github/allowed_signers` (registered as a signing key on the
   maintainer's account, the same key as in Self-Updater) as the environment secret `RELEASE_SIGNING_KEY`:
   `gh secret set RELEASE_SIGNING_KEY -R VectoDE/Linux-Server-Setup-Script --env release < <private key file>`.

4. **Tag ruleset**: only the deploy key may create, move or delete tags. The ruleset "Protect tags" exists and
   already blocks moving and deleting; [`scripts/release/tag-ruleset.json`](../scripts/release/tag-ruleset.json) adds
   creation:

   ```bash
   id=$(gh api repos/VectoDE/Linux-Server-Setup-Script/rulesets --jq '.[] | select(.name == "Protect tags") | .id')
   gh api -X PUT "repos/VectoDE/Linux-Server-Setup-Script/rulesets/$id" --input scripts/release/tag-ruleset.json
   ```

   The ruleset of `main` lets the deploy key push past the pull request rule already.

5. **Test release**: run the workflow on `main` with the pre-release name `rc.1` (Actions, Release, Run workflow) and
   check the result with `bootstrap.sh 2.0.0-rc.1` on a test server or VM. The release `2.0.0` follows from the next
   merge.

## Verifying a release by hand

```bash
gh release download v2.0.1 -R VectoDE/Linux-Server-Setup-Script
sha256sum --check SHA256SUMS
gh attestation verify lss-2.0.1.tar.gz --bundle lss-2.0.1.intoto.jsonl --repo VectoDE/Linux-Server-Setup-Script \
  --cert-identity https://github.com/VectoDE/Linux-Server-Setup-Script/.github/workflows/release.yml@refs/heads/main
```

The same works for every other file of the release. Without `--bundle`, `gh` fetches the attestation from GitHub.
