# Security policy / Política de segurança

## Supported versions / Versões suportadas

Only the latest release receives security fixes. Releases older than v0.2.1 were withdrawn because of known vulnerabilities in their dependencies. v1.0.0 and v1.1.0 were withdrawn for an unrelated reason: a release-pipeline bug published them with no binaries attached; use v1.0.1 and v1.1.1 instead.
Só o release mais recente recebe correções de segurança. Os releases anteriores à v0.2.1 foram retirados por terem vulnerabilidades conhecidas nas dependências. A v1.0.0 e a v1.1.0 foram retiradas por um motivo diferente: um problema na pipeline de release publicou-as sem binários anexados; usa a v1.0.1 e a v1.1.1.

## Reporting a vulnerability / Reportar uma vulnerabilidade

**Please do not open a public issue.** Use GitHub's private reporting: [Report a vulnerability](https://github.com/Joao-Paulino/expiry-radar/security/advisories/new).
**Não abras uma issue pública.** Usa o reporte privado do GitHub: [Report a vulnerability](https://github.com/Joao-Paulino/expiry-radar/security/advisories/new).

Include, if you can: the version (`collector version` / `agent version`), the component, steps to reproduce, and the impact you see. English or Portuguese.
Inclui, se puderes: a versão, o componente, os passos para reproduzir e o impacto. Em inglês ou português.

| What to expect / O que esperar | Target / Prazo |
|---|---|
| Acknowledgement / Confirmação de receção | 3 working days / 3 dias úteis |
| Triage and severity (CVSS v3.1) / Triagem e severidade | 10 working days / 10 dias úteis |
| Fix for Critical / High | 30 days / 30 dias |
| Fix for Medium / Low | 90 days / 90 dias |

You will be credited in the advisory and the release notes unless you ask not to be. Coordinated disclosure: please wait for the fix, or 90 days, before publishing.
Serás creditado no aviso e nas notas do release, exceto se preferires que não. Divulgação coordenada: espera pela correção, ou 90 dias, antes de publicar.

## Scope / Âmbito

In scope: the collector and agent binaries, container images, installers and this repository's CI.
Out of scope: vulnerabilities in third-party services the checkers query (report those to the vendor), and findings that need an already compromised agent host or collector administrator account.

## How the project is tested / Como o projeto é testado

Every pull request runs: unit and end-to-end tests on Linux, Windows and macOS; CodeQL (security-extended) and gosec as gates; OWASP ZAP active scans of the dashboard and of the `/ingest` API; Go fuzzing of every parser that sees external input; govulncheck. Every release binary is scanned with govulncheck before it is published. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#7-security-model) and [docs/security/](docs/security/).
