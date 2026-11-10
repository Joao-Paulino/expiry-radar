# Expiry Radar — Design Spec

Date: 2026-11-10
Status: Approved for implementation planning

## 1. Purpose

A vendor-neutral, open-source tool that tracks anything with an expiry date
across an organization's infrastructure — TLS certificates, secrets/API
keys, cloud resources, virtualization platform certificates/licenses — and
surfaces what is about to expire before it causes an incident. Published
publicly on GitHub (MIT license) so any SecOps/DevSecOps professional can
install and run it, not just the author.

This is the first of three original SecOps tools planned (the other two —
a cross-framework compliance crosswalk, and an incident-response tabletop
generator — are separate projects with their own design cycles).

## 2. Non-goals (for this version)

- Not a general-purpose GRC platform or asset inventory system.
- Not a secrets manager or vault — it only reads expiry metadata from
  existing secret stores, never writes, rotates, or stores secret values.
- Not a replacement for `certbot-renewal-check` — it absorbs and
  generalizes that script's logic as its first TLS checker, rather than
  deprecating it outright.

## 3. Architecture

Two Go binaries, connected by a shared plugin interface:

- **Agent**: a single, dependency-free Go binary that runs on a schedule
  (cron / systemd timer / Windows Task Scheduler) on a host, VM, or
  server. It runs its configured local `Checker`s, collects results, and
  pushes them to the Collector over authenticated HTTPS. Cross-compiled
  for Windows, RedHat, Debian, Arch, and generic Linux from day one
  (validated on all five from the first milestone, since every later
  milestone builds on this same agent).
- **Collector**: a single Go service that is the system of record. It
  receives pushed results from agents, and independently runs its own
  remote `Checker`s on its own schedule for sources reachable via API
  (cloud providers, VMware vCenter, remote Vault). It stores everything
  in a database (SQLite by default), runs the alerting engine, and
  serves the dashboard and a REST API.
- **`Checker` interface**: the extension point. Every source — a TLS
  certificate, a Vault secret, an Azure/AWS/GCP resource, a VMware
  certificate/license — implements the same interface:

  ```go
  type Checker interface {
      Name() string                      // e.g. "azure-cert-checker"
      Kind() string                      // "certificate" | "secret" | "license" | "subscription"
      Check(ctx context.Context) ([]ExpiryRecord, error)
  }

  type ExpiryRecord struct {
      Source    string            // where it was found
      Name      string            // identifying name, never the secret value
      Kind      string
      ExpiresAt time.Time
      Metadata  map[string]string // non-sensitive context only
      Severity  string            // derived from alerting rules, not set by the checker
  }
  ```

  Adding a new source later (software license keys, SaaS subscriptions,
  OT/ICS devices) means writing a new `Checker`, not redesigning the
  system. The dashboard and alerting engine are generic over `Kind()`
  and never hardcode a specific source.

## 4. Scope and phasing

Full v1 scope (all using the same `Checker` interface): TLS certificates,
secrets/API keys, software license keys, SaaS subscriptions, and
resources across Azure, AWS, GCP, and VMware. OT/ICS support is an
explicitly deferred future extension, to be designed separately once the
IT-side tool is proven.

To keep delivery incremental, each source ships as its own milestone —
every milestone is a complete, working increment, not a partial feature:

1. **M1 — TLS checker + core platform.** Builds the whole foundation:
   agent (cross-compiled and tested on Windows, RedHat, Debian, Arch,
   Linux), collector, database schema, push ingestion endpoint, alerting
   engine (configurable thresholds, Slack/Teams/email/webhook), the
   dashboard (list view, history, rule management: mute, assign owner),
   JSON/CSV export, and the TLS checker itself — generalizing
   `certbot-renewal-check`'s logic (cron detection, recent-run check,
   STARTTLS served-cert comparison) to run against an arbitrary list of
   hosts/services rather than one hardcoded service.
2. **M2 — Vault checker.** Secrets/API keys nearing expiry in HashiCorp
   Vault (leases, dynamic secrets, token TTLs).
3. **M3 — Azure checker.** Certificates and secrets in Key Vault, App
   Registration credentials, managed certificates.
4. **M4 — AWS checker.** ACM certificates, IAM access keys, Secrets
   Manager rotation state.
5. **M5 — GCP checker.** Certificate Manager, Secret Manager, service
   account keys.
6. **M6 — VMware checker.** vCenter/ESXi certificates and license
   expiry.

Deferred, same interface, no architecture change needed: software
license keys (local installs), SaaS subscription renewals, and (at the
very end, as its own future project) OT/ICS device and certificate
checks.

## 5. Data flow

1. Agent wakes on schedule → runs its configured local `Checker`s →
   produces `ExpiryRecord`s (metadata only, never the secret/cert
   private key value) → pushes them via authenticated HTTPS to the
   Collector's ingest endpoint.
2. Independently, and on its own schedule, the Collector runs its remote
   `Checker`s (cloud APIs, VMware API, remote Vault) directly.
3. The alerting engine evaluates all current records against
   configurable per-kind thresholds (e.g. warn at 30 days, critical at 7
   days), dedupes, and sends alerts through configured channels.
4. The dashboard and REST API always read from the database — never
   query a live source directly.

## 6. Error handling

- A failing `Checker` never blocks others; its own failure is recorded
  and is itself an alertable condition ("could not check X").
- If an agent cannot reach the Collector, it queues results locally and
  retries with backoff, so a transient network issue does not lose data.
- If a source (agent or remote checker) stops reporting for longer than
  its expected interval, that silence itself raises an alert — "lost
  visibility on X" — so an outage in the monitoring path is never
  mistaken for "nothing to report."

## 7. Security requirements

- **Metadata only.** No `Checker`, log line, API response, or database
  row ever contains the actual secret/private key/credential value —
  only identifying metadata and the expiry date.
- **Encrypted transport.** All agent↔collector and collector↔external-API
  traffic uses TLS.
- **Least privilege.** Every credential the Collector or Agent uses
  (cloud role, Vault token, VMware service account) is read-only and
  scoped to only what listing expiry metadata requires.
- **Sanitized logging.** Before any log line is written (including error
  and debug logs), values that look like secrets, keys, or tokens are
  masked, so a stack trace or verbose log can never leak one.

## 8. Testing strategy

- Unit tests per `Checker`, driven by fixtures (sample certificates,
  mocked Vault/Azure/AWS/GCP/VMware API responses) — never against real
  external services.
- Integration test of the agent→collector push path over local HTTPS,
  covering authentication and log sanitization.
- End-to-end test using a fake HTTP server that mimics the relevant
  cloud/VMware API, validating the full collect → alert → dashboard flow
  without touching real accounts.

## 9. Distribution

- Public GitHub repository, MIT license, matching the pattern of the
  author's other public tools.
- Pre-built agent binaries per platform (Windows, RedHat, Debian, Arch,
  generic Linux) and a Collector binary, attached to each release.
- Docker images for both the Agent and the Collector.
- A Helm chart / Kubernetes manifests for running the Collector (and the
  Agent as a DaemonSet, where applicable) in a cluster.
- Terraform modules to deploy the Collector (and the Agent via
  cloud-init/VM extensions where relevant) on Azure, AWS, and GCP, plus
  listings on each provider's marketplace for one-click installs.
- For VMware: a Terraform module (vSphere provider) to deploy the
  Collector, plus a ready-to-import OVA/vApp template for anyone who
  prefers importing it directly into vCenter instead of using Terraform.
- Installation and usage documentation in PT-PT and EN.

## 10. Open items carried forward (not blocking M1)

- Exact alerting threshold defaults and how they're configured per
  `Checker` kind — decide during M1 implementation planning.
- Dashboard UI framework choice — decide during M1 implementation
  planning; keep it a server-rendered Go app or a minimal SPA, not a
  heavy frontend stack.
- Software license keys, SaaS subscriptions, and OT/ICS support: each
  gets its own short design pass when its milestone comes up, reusing
  this spec's architecture unchanged.
- Full distribution surface (Helm chart, Terraform modules, marketplace
  listings, OVA/vApp template) is release engineering, not core product
  code — it is built out progressively, starting with binaries + Docker
  images at M1, so it does not block the M1 implementation plan.
