# Governance

Linux-Server-Setup-Script (`lss`) is maintained by [VectoDE](https://github.com/VectoDE). This page says who decides
what, how changes get in, and how the project keeps going if the maintainer is gone.

## Roles

| Role        | Who                                                       | Responsibilities                                                                                                   |
| ----------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Maintainer  | [@VectoDE](https://github.com/VectoDE)                    | Reviews and merges pull requests, triages issues, answers security reports, owns the release workflow              |
| Contributor | Anyone who opens an issue, a discussion or a pull request | Follows the [contributing guide](CONTRIBUTING.md), the [code of conduct](CODE_OF_CONDUCT.md) and signs off commits |

A contributor with a record of good pull requests can be invited as a second maintainer. The invitation is a pull
request that adds them to this file and to [CODEOWNERS](CODEOWNERS).

## Decisions

- Bug fixes and small changes: a pull request that passes every required check. Pull requests from contributors
  need a maintainer's approval. While there is one maintainer, their own pull requests are merged once every check
  passes; when a second maintainer joins, the main ruleset will require an approval by someone other than the author.
- New modules, changed defaults and breaking changes: discussed in an issue first, then decided by the maintainers.
  The reasoning is written down in the issue or as a decision in Discussions.
- Security reports follow the [security policy](SECURITY.md) and are handled privately until a fix is released.

## Releases

From 2.0.0 on, releases are built and published only by the release workflow on `main`, with a signed build
attestation; nobody publishes from a laptop. A tag ruleset already blocks changing or deleting tags; with the release
workflow it will also allow only that workflow to create version tags. The 1.x releases were published by hand and
are not signed.

## Access to sensitive resources

| Resource                                | Who has access                                                     |
| --------------------------------------- | ------------------------------------------------------------------ |
| GitHub repository settings and rulesets | [@VectoDE](https://github.com/VectoDE) (owner)                     |
| Merging into `main`                     | [@VectoDE](https://github.com/VectoDE), through pull requests only |
| Security advisories                     | [@VectoDE](https://github.com/VectoDE)                             |
| OpenSSF Best Practices entry            | [@VectoDE](https://github.com/VectoDE)                             |

The project stores no secrets; workflows use the short-lived `GITHUB_TOKEN` and their OIDC identity. The list is
updated in the same pull request that grants or removes access.

Before anyone gets more than read access, the maintainers review their record: at least three merged pull requests
of good quality, constructive behaviour in issues and reviews, and two-factor authentication on GitHub. Rights are
given at the lowest level that does the job, and removed when no longer needed.

## Continuity

The project must keep working if a maintainer can no longer act:

- The code, issues, discussions, releases and the full history are public on GitHub, so anyone can fork and continue.
- Releases need no personal token or key: the attestation is signed with the workflow's identity.
- Installed servers keep working without the project: `lss` runs from its local copy and needs the repository only
  to update itself.
