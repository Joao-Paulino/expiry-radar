# Contributing / Contribuir

Thank you for helping. Issues and pull requests are welcome in English or Portuguese.
Obrigado pela ajuda. Issues e pull requests são bem-vindos em inglês ou português.

## Reporting bugs and asking for features

Open a [GitHub issue](https://github.com/Joao-Paulino/expiry-radar/issues) with the version (`collector version` / `agent version`), the platform, what you expected and what happened. Remove tokens, hostnames and IP addresses you do not want public.
Questions, ideas and "does it support X?" go to [Discussions](https://github.com/Joao-Paulino/expiry-radar/discussions). / Perguntas e ideias vão para as Discussions.
**Security problems go through [SECURITY.md](SECURITY.md), never a public issue.**

## Development

Requirements: Go (the version in `go.mod` or newer). No CGO.

```bash
go build ./...
go vet ./...
go test ./...                       # unit + end-to-end (collector, SSO with a fake IdP)
go test -run '^$' -fuzz FuzzSanitize -fuzztime 30s ./internal/logging/   # example fuzz run
```

Architecture, code layout and how to add a checker: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Pull requests

- One topic per PR; `main` is protected and only accepts PRs with linear history.
- **New behaviour comes with a test that fails without it.** Bug fixes start with a test that reproduces the bug.
- Every exported identifier has a doc comment.
- Keep the principles: read only, no secret values in records or logs, no new dependency without a strong reason (each one is attack surface; the release gate scans every binary).
- CI must be green: tests on Linux/Windows/macOS, distro smoke test, Vault and Keycloak end-to-end jobs, govulncheck, CodeQL, gosec, OWASP ZAP and fuzzing. A new gosec or CodeQL finding is either fixed or suppressed with a written justification that a reviewer agrees with.
- Commit messages: imperative, short subject, body explaining why.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).

Every commit must carry a `Signed-off-by:` line (`git commit -s`), asserting the [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change or have the right to submit it under the project's license.
