# Governance / Governação

## Members with access to sensitive resources

| Member | Role | Access |
|---|---|---|
| [@Joao-Paulino](https://github.com/Joao-Paulino) (João Paulino) | Maintainer | Admin on the repository, releases, GitHub Actions secrets, container images on ghcr.io, security advisories |

No other account has write access. Changes to this list are made by pull request to this file.

## Roles and responsibilities

- **Maintainer:** reviews and merges pull requests, cuts releases, triages issues and security reports (see [SECURITY.md](SECURITY.md)), manages repository settings and secrets. Uses two-factor authentication.
- **Contributor:** anyone who opens an issue or pull request, following [CONTRIBUTING.md](CONTRIBUTING.md). Contributors get no write access; their changes go through review and CI.

New collaborators get write access only after a history of reviewed contributions, and only with the least privilege needed.

## Dependencies

Dependencies are Go modules declared in `go.mod` and pinned by checksum in `go.sum`; the Go checksum database verifies them. A new dependency needs a strong reason (each one is attack surface) and is reviewed in its pull request. Dependabot proposes updates for Go modules and GitHub Actions; `govulncheck` runs on every pull request and gates every release binary.

## Vulnerability data

Fixed vulnerabilities are published in GitHub Security Advisories when reported privately, in the release notes of the release that fixes them, and in the security test reports in [docs/security/](docs/security/).
