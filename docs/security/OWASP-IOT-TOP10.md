# OWASP IoT Top 10 (2018) assessment: Expiry Radar v0.9.0

| | |
|---|---|
| Scope | The agent deployed in ICS/OT and IIoT networks (OPC UA, TLS, MQTT/AMQP checks, `ot_safe`), its link to the collector, and the release/update chain |
| Date | November 2026 |
| Method | OWASP IoT Top 10 (2018), grey box: code review, tests against a hostile fake OPC UA server, fuzzing, interop against a real OPC UA server (python asyncua 2.1.0), independent code review |
| Result | No open finding. One review finding (certificates with negative serials dropped) and nine gosec integer-conversion warnings fixed before release. One recommendation (I9). |

## Summary (EN-US)

Assessment of the Expiry Radar agent deployed in ICS/OT and IIoT networks against the OWASP IoT Top 10. The agent opens no ports, has no default passwords, talks to the collector over HTTPS only, stores no secrets, and never writes to field devices (OPC UA discovery only, no session). The OPC UA parser was tested against hostile servers and fuzzed. No open findings. Recommendation: enable `ot_safe` in OT networks (it is off by default so existing installations keep their behavior).

## Resumo (PT-PT)

Avaliação do agente da Expiry Radar quando instalado em redes ICS/OT e IIoT, segundo o OWASP IoT Top 10. O agente não abre portas, não tem passwords por omissão, só fala HTTPS com o coletor, não guarda segredos e nunca escreve nos equipamentos (OPC UA só por descoberta, sem sessão). O parser OPC UA foi testado contra servidores hostis e com fuzzing. Não há falhas em aberto. Recomendação: ativar `ot_safe` em redes OT (não está ativo por omissão para não mudar o comportamento de instalações existentes).

## Results

| ID | Category | Result | Evidence |
|---|---|---|---|
| I1 | Weak, guessable or hardcoded passwords | ✅ Pass | No default credentials anywhere. Agent tokens are 256-bit random, issued per agent (`collector add-agent`) and bound to the agent ID. Admin password ≥ 12 characters, PBKDF2-SHA256 600 000 iterations, TOTP. The OPC UA checker sends no credentials (anonymous discovery). |
| I2 | Insecure network services | ✅ Pass | The agent **listens on no port** (code search: no `Listen`/`Serve` in agent code). Outbound only. OPC UA client is hardened against hostile servers: chunk ≤ 1 MiB, message ≤ 16 MiB, ≤ 256 chunks, arrays ≤ 1024, deadlines on every read/write (`TestGetEndpoints_RejectsOversizedChunk`, `TestGetEndpoints_TimesOutOnSilentServer`, `FuzzParseGetEndpointsResponse` ~2M executions, no crash). |
| I3 | Insecure ecosystem interfaces | ✅ Pass | Collector web UI and `/ingest` API covered by the WSTG pentest, ASVS L2 and OWASP ZAP on every pull request ([PENTEST-2026-11.md](PENTEST-2026-11.md), [ASVS-L2.md](ASVS-L2.md)). |
| I4 | Lack of secure update mechanism | ✅ Pass | Releases carry `SHA256SUMS` and Sigstore-signed SLSA provenance (`gh attestation verify`); installers verify the checksum before installing. No auto-update by design: OT changes go through the plant's change management. |
| I5 | Use of insecure or outdated components | ✅ Pass | Standard library OPC UA implementation (no third-party OPC UA stack). `govulncheck` gates every pull request and release; SBOM (CycloneDX) and VEX (OpenVEX) ship with every binary. |
| I6 | Insufficient privacy protection | ✅ Pass | Only certificate and secret metadata (names, dates, issuers) is collected; never secret values, never personal data. |
| I7 | Insecure data transfer and storage | ✅ Pass | Agent → collector over HTTPS only (enforced at start-up), TLS ≥ 1.2. The OPC UA discovery channel is unencrypted by design (SecurityPolicy None), but carries only the server's public certificate and no credentials. Local queue file `0600`; it holds metadata only. |
| I8 | Lack of device management | ✅ Pass | Each agent has its own token and ID; the collector alerts on silent agents and failing checkers; agents can be forgotten from the dashboard; tokens revoked by removing them from the collector config. |
| I9 | Insecure default settings | ⚠️ Pass with recommendation | Secure defaults: HTTPS required, certificate verification on, no listening ports, read only. `ot_safe` (≥ 1 h interval, one target at a time with 2 s pause, 5 s timeouts) is **opt-in** so existing IT installations keep their behavior. **Recommendation: always set `"ot_safe": true` for agents in OT zones.** |
| I10 | Lack of physical hardening | N/A | Software only. Harden the host per ISA/IEC 62443-3-3 / plant baseline; the agent needs no admin rights (Linux: dedicated user via the installer; Windows: LocalService). |

## Safety towards field devices

- OPC UA: Hello → OpenSecureChannel (None) → GetEndpoints → CloseSecureChannel. **No CreateSession, no Read/Write/Browse/Call.** Pinned by `TestCheck_OnlyUsesDiscoveryMessages`.
- One TCP connection per server per run, no retries, servers checked one after another.
- Duplicate endpoints in the config are rejected.

## Findings fixed before release

| Finding | Source | Fix |
|---|---|---|
| Certificates with a negative serial (older PLC/HMI tooling) were dropped by Go's x509 parser, hiding the device | Independent review | Leaf-only parse with ASN.1 fallback (`TestCheck_NegativeSerialCertificateIsStillReported`) |
| A broken second certificate in a chain hid the leaf | Independent review | Leaf-only parse (`TestCheck_BrokenChainKeepsLeaf`) |
| Server-supplied strings unbounded in records | Independent review | Clipped to 256 bytes (`TestCheck_LongServerStringsAreTruncated`) |
| Server advertising no certificate looked healthy | Independent review | Reported as an error (`TestCheck_NoCertificateAdvertisedIsAnError`) |
| 9 × gosec G115 integer conversions in the OPC UA encoder | gosec in CI | Lengths and timeouts bounded; two's complement wire conversions annotated |

This is a self-assessment by the maintainer, not an independent third-party certification.
