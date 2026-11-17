# OpenSSF Best Practices badge: prepared answers

Respostas preparadas para o formulário em <https://www.bestpractices.dev> (nível *passing*). Criar o projeto com o URL do repositório, depois copiar cada resposta para o critério com o mesmo nome. Os critérios ficam em inglês porque o formulário é em inglês.

Repository: `https://github.com/Joao-Paulino/expiry-radar`

## Basics

| Criterion | Answer | Justification / URL |
|---|---|---|
| description_good | Met | README first paragraph: what the agent and collector do |
| interact | Met | README (install, usage), GitHub issues |
| contribution | Met | `CONTRIBUTING.md` |
| contribution_requirements | Met | `CONTRIBUTING.md` → Pull requests (tests, doc comments, CI green) |
| floss_license | Met | MIT, `LICENSE` |
| floss_license_osi | Met | MIT is OSI-approved |
| license_location | Met | `LICENSE` at the repository root |
| documentation_basics | Met | README, `docs/ARCHITECTURE.md`, `docs/ARQUITETURA.md` |
| documentation_interface | Met | `docs/api/ingest.openapi.yaml`, README configuration reference |
| sites_https | Met | GitHub (HTTPS only) |
| discussion | Met | GitHub issues and pull requests (searchable, URL-addressable) |
| english | Met | Docs, code comments and commit messages in English; Portuguese welcome too |
| maintained | Met | Regular releases (see Releases page) |

## Change control

| Criterion | Answer | Justification / URL |
|---|---|---|
| repo_public | Met | public GitHub repository |
| repo_track | Met | git |
| repo_interim | Met | every change goes through a pull request |
| repo_distributed | Met | git |
| version_unique | Met | semantic version tags `vX.Y.Z` |
| version_semver | Met | SemVer |
| version_tags | Met | git tags per release |
| release_notes | Met | GitHub release notes for each tag |
| release_notes_vulns | Met | release notes name fixed vulnerabilities (for example v0.8.1: BUSL-01, BUSL-02) |

## Reporting

| Criterion | Answer | Justification / URL |
|---|---|---|
| report_process | Met | GitHub issues, described in `CONTRIBUTING.md` |
| report_tracker | Met | GitHub issues |
| report_responses | Met | maintainer answers issues |
| enhancement_responses | Met | |
| report_archive | Met | GitHub issues are public and archived |
| vulnerability_report_process | Met | `SECURITY.md` |
| vulnerability_report_private | Met | GitHub private vulnerability reporting (`/security/advisories/new`) |
| vulnerability_report_response | Met | `SECURITY.md`: acknowledgement within 3 working days |

## Quality

| Criterion | Answer | Justification / URL |
|---|---|---|
| build | Met | `go build ./...` |
| build_common_tools | Met | standard Go toolchain |
| build_floss_tools | Met | Go is FLOSS |
| test | Met | `go test ./...`; documented in `CONTRIBUTING.md` |
| test_invocation | Met | `go test ./...` |
| test_most | Met | unit + end-to-end tests (collector, SSO with Keycloak, Vault) |
| test_continuous_integration | Met | GitHub Actions on every pull request (Linux, Windows, macOS) |
| test_policy | Met | `CONTRIBUTING.md`: new behaviour comes with a test that fails without it |
| tests_are_added | Met | visible in recent pull requests (e.g. #53) |
| tests_documented_added | Met | `CONTRIBUTING.md` |
| warnings | Met | `go vet`, gosec and CodeQL in CI |
| warnings_fixed | Met | gates fail the build on new findings |
| warnings_strict | Met | gosec + CodeQL `security-extended` as gates |

## Security

| Criterion | Answer | Justification / URL |
|---|---|---|
| know_secure_design | Met | maintainer works in DevSecOps; threat model in `docs/ARCHITECTURE.md` §7 |
| know_common_errors | Met | OWASP Top 10, CWE Top 25 and ASVS L2 assessed: `docs/security/` |
| crypto_published | Met | only Go standard library crypto (TLS, PBKDF2-SHA256, ECDSA P-256, HMAC-SHA1 for TOTP per RFC 6238) |
| crypto_call | Met | no own crypto implementations |
| crypto_floss | Met | |
| crypto_keylength | Met | ECDSA P-256, 256-bit tokens, TLS ≥ 1.2 |
| crypto_working | Met | no MD5/DES/RC4; SHA-1 only inside TOTP HMAC as RFC 6238 requires |
| crypto_weaknesses | Met | |
| crypto_pfs | Met | TLS 1.2/1.3 ECDHE suites (Go defaults) |
| crypto_password_storage | Met | PBKDF2-SHA256, 600 000 iterations, per-user random salt |
| crypto_random | Met | `crypto/rand` |
| delivery_mitm | Met | releases over HTTPS; installers verify SHA256SUMS |
| delivery_unsigned | Met | checksums are fetched over HTTPS from the same GitHub release |
| vulnerabilities_fixed_60_days | Met | no unpatched vulnerability older than 60 days |
| vulnerabilities_critical_fixed | Met | |
| no_leaked_credentials | Met | gosec G101; no secrets in the repository |

## Analysis

| Criterion | Answer | Justification / URL |
|---|---|---|
| static_analysis | Met | CodeQL, gosec, `go vet` on every pull request (`.github/workflows/security.yml`) |
| static_analysis_common_vulnerabilities | Met | CodeQL `security-extended`, gosec |
| static_analysis_fixed | Met | findings fixed or justified (`.github/codeql-accepted.txt`) |
| static_analysis_often | Met | every pull request |
| dynamic_analysis | Met | OWASP ZAP active scans (dashboard and `/ingest`) and Go fuzzing (6 targets) on every pull request |
| dynamic_analysis_unsafe | N/A | Go is memory-safe; CGO disabled |
| dynamic_analysis_enable_assertions | Met | Go runtime bounds and nil checks are always on in tests and fuzzing |
| dynamic_analysis_fixed | Met | fuzzing findings fixed (CWE-117, resource id validation) |

## Before submitting / Antes de submeter

1. Merge `SECURITY.md` and `CONTRIBUTING.md` (they are referenced above).
2. Private vulnerability reporting is already enabled in the repository (checked).
3. Add the badge to the README once it is granted: `[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>)`.
