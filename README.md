# Expiry Radar

**English** · [Português (PT-PT)](README.pt-PT.md)

Know what is about to expire before it causes an incident.

Expiry Radar is a self-hosted, open-source tool that tracks expiry dates across
your infrastructure. Lightweight agents check what they can see locally and
push the results to a central collector, which stores them, shows them on a
dashboard and sends alerts before anything runs out.

> **Status: milestone 1 (early).** The TLS certificate checker and the core
> platform (agent, collector, dashboard, alerts) work end to end. Secrets,
> cloud resources and virtualization platforms are planned. See
> [Known limitations](#known-limitations).

## How it works

```
 hosts / VMs                                 central
┌────────────┐   HTTPS + bearer token   ┌──────────────────────┐
│   agent    │ ───────────────────────▶ │      collector       │
│ TLS checks │   (queued locally if     │ SQLite · dashboard   │
└────────────┘    collector is down)    │ alerts · JSON/CSV    │
                                        └──────────────────────┘
```

- **Agent**: a single Go binary with no dependencies (Windows, Linux amd64
  and arm64). It checks TLS certificates on a schedule, including SMTP
  STARTTLS, and records expired or untrusted certificates instead of
  skipping them.
- **Collector**: a single Go service. It receives results over HTTPS,
  stores them in SQLite (pure Go, no CGO), serves the dashboard and export
  endpoints, and sends alerts to a webhook, Slack, Microsoft Teams or email.
- **Separate tokens**: agents use ingest tokens, and the dashboard, mute and
  export endpoints need a different admin token.
- **Never stores secret values**: only names, sources and expiry dates.

## Build

Requires Go 1.24.

```bash
git clone https://github.com/Joao-Paulino/expiry-radar.git
cd expiry-radar
go test ./...
go build -o collector ./cmd/collector
./scripts/build-agent.sh   # dist/agent-{windows-amd64.exe,linux-amd64,linux-arm64}
```

## Configure the collector

`collector.json`:

```json
{
  "db_path": "/var/lib/expiry-radar/radar.db",
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_file": "/etc/expiry-radar/collector.crt",
  "tls_key_file": "/etc/expiry-radar/collector.key",
  "auth_tokens": ["<long random agent token>"],
  "admin_tokens": ["<different long random admin token>"],
  "alert_interval_seconds": 3600,
  "slack_webhook_url": "",
  "teams_webhook_url": "",
  "webhook_url": "",
  "email": { "smtp_host": "", "smtp_port": 25, "from": "", "to": "" }
}
```

```bash
./collector collector.json
```

Open `https://<collector>:8443/` and send the admin token as
`Authorization: Bearer <admin token>`.

## Configure an agent

`agent.json`:

```json
{
  "collector_url": "https://collector.example.com:8443/ingest",
  "collector_ca_file": "/etc/expiry-radar/collector-ca.pem",
  "token": "<agent token>",
  "agent_id": "web-01",
  "queue_path": "/var/lib/expiry-radar/queue.jsonl",
  "interval_seconds": 3600,
  "tls_targets": [
    { "host": "www.example.com", "port": 443 },
    { "host": "mail.example.com", "port": 25, "start_tls": "smtp" }
  ]
}
```

```bash
./agent agent.json
```

`collector_ca_file` is only needed when the collector uses a self-signed
certificate. The agent refuses plain `http://` collector URLs.

## Known limitations

Milestone 1 deliberately leaves these for the next milestone:

- No alert yet when a checker keeps failing or an agent goes silent.
- Alerts are not deduplicated: every alert cycle re-sends every non-OK
  record. Mute a record to stop it.
- Records are identified by `host:port`, name and kind, so two agents
  checking the same address (for example `localhost:443`) overwrite each
  other. Use fully qualified target names.
- `go install ...@latest` does not work yet; build from source as shown above.

## Roadmap

Secret store checkers (for example Vault), cloud provider resources,
virtualization platform certificates and licences, container images and
infrastructure-as-code packaging.

## License

[MIT](LICENSE)
