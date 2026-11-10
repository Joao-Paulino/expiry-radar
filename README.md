<div align="center">

# 📡 Expiry Radar

### Know what expires before it breaks production · Saiba o que expira antes de parar a produção

![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white)
![Status](https://img.shields.io/badge/status-milestone%201-orange)
![Platforms](https://img.shields.io/badge/agent-Windows%20%7C%20Linux%20amd64%20%7C%20arm64-blue)
![Lang](https://img.shields.io/badge/lang-PT%20%7C%20EN-green)
![Licence](https://img.shields.io/badge/licence-MIT-lightgrey)

</div>

---

## 🎯 What is this? / O que é isto?

An expired certificate is one of the most avoidable outages there is, and one of
the most common. Expiry Radar is a self-hosted, open-source tool that keeps an
inventory of what expires across your infrastructure. Small agents check
certificates where they live, a central collector stores the results, shows
them on a dashboard and alerts you on Slack, Teams, a webhook or email before
anything runs out.

Um certificado expirado é uma das falhas mais fáceis de evitar e, mesmo assim,
das mais comuns. O Expiry Radar é uma ferramenta open-source, alojada por ti,
que mantém um inventário de tudo o que expira na tua infraestrutura. Agentes
leves verificam os certificados onde eles estão, um collector central guarda os
resultados, mostra-os num painel e avisa-te por Slack, Teams, webhook ou email
antes que algo expire.

> **Milestone 1:** TLS certificates end to end. Secrets, cloud resources and
> virtualization platforms come next.
> **Milestone 1:** certificados TLS de ponta a ponta. Segredos, recursos de cloud
> e plataformas de virtualização vêm a seguir.

## ✨ Features / Funcionalidades

| | EN | PT |
|---|---|---|
| 🔐 | TLS checks, including SMTP STARTTLS | Verificação TLS, incluindo SMTP STARTTLS |
| 🚨 | Expired and untrusted certificates are reported, never skipped | Certificados expirados ou não confiáveis são reportados, nunca ignorados |
| 📦 | Single Go binary agent, no dependencies | Agente num único binário Go, sem dependências |
| 📴 | Local queue when the collector is down, sent later | Fila local quando o collector está em baixo, enviada depois |
| 📊 | Dashboard with history, mute and owner per record | Painel com histórico, silenciamento e responsável por registo |
| 📤 | JSON and CSV export | Exportação em JSON e CSV |
| 🔔 | Alerts: Slack, Microsoft Teams, webhook, email | Alertas: Slack, Microsoft Teams, webhook, email |
| 🔑 | Separate agent and admin tokens, HTTPS only | Tokens separados para agentes e administração, só HTTPS |
| 🙈 | Never stores secret values, only names and dates | Nunca guarda valores secretos, só nomes e datas |

## 🧭 How it works / Como funciona

```
 hosts / VMs                                 central
┌────────────┐   HTTPS + bearer token   ┌──────────────────────┐
│   agent    │ ───────────────────────▶ │      collector       │
│ TLS checks │   (local queue if the    │ SQLite · dashboard   │
└────────────┘    collector is down)    │ alerts · JSON/CSV    │
                                        └──────────────────────┘
```

## 🚀 Quick start / Início rápido

Requires Go 1.24 · Requer Go 1.24

```bash
git clone https://github.com/Joao-Paulino/expiry-radar.git
cd expiry-radar
go test ./...
go build -o collector ./cmd/collector
./scripts/build-agent.sh   # dist/agent-{windows-amd64.exe,linux-amd64,linux-arm64}
```

### 🖥️ Collector

`collector.json`

```json
{
  "db_path": "/var/lib/expiry-radar/radar.db",
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_file": "/etc/expiry-radar/collector.crt",
  "tls_key_file": "/etc/expiry-radar/collector.key",
  "auth_tokens": ["<agent token>"],
  "admin_tokens": ["<admin token>"],
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

Open `https://<collector>:8443/` with `Authorization: Bearer <admin token>`.
Abre `https://<collector>:8443/` com `Authorization: Bearer <admin token>`.

### 🛰️ Agent / Agente

`agent.json`

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

`collector_ca_file` is only needed for a self-signed collector certificate.
`collector_ca_file` só é necessário se o collector usar um certificado autoassinado.

## ⚠️ Known limitations / Limitações conhecidas

| EN | PT |
|---|---|
| No alert yet when a checker keeps failing or an agent goes silent | Ainda não há alerta quando um verificador falha repetidamente ou um agente deixa de reportar |
| Alerts are re-sent every cycle; mute a record to stop them | Os alertas repetem-se em cada ciclo; silencia o registo para os parar |
| Two agents checking the same `host:port` overwrite each other; use fully qualified names | Dois agentes que verificam o mesmo `host:porta` sobrepõem-se; usa nomes totalmente qualificados |
| `go install ...@latest` is not supported yet; build from source | `go install ...@latest` ainda não é suportado; compila a partir do código |

## 🗺️ Roadmap

- [x] TLS certificates, agent, collector, dashboard, alerts / Certificados TLS, agente, collector, painel, alertas
- [ ] Checker health and silent agent alerts, alert deduplication / Alertas de saúde e de agentes silenciosos, deduplicação
- [ ] Secret stores such as Vault / Cofres de segredos como o Vault
- [ ] Cloud resources (Azure, AWS, GCP) / Recursos de cloud (Azure, AWS, GCP)
- [ ] Virtualization certificates and licences / Certificados e licenças de virtualização
- [ ] Docker, Helm, Terraform packaging / Empacotamento em Docker, Helm, Terraform

## 🛡️ Security / Segurança

Agents only read expiry metadata and never send private keys or secret values.
Found a vulnerability? Please open a private security advisory on this repository.

Os agentes só leem metadados de expiração e nunca enviam chaves privadas nem
valores secretos. Encontraste uma vulnerabilidade? Abre um security advisory
privado neste repositório.

## 📜 Licence / Licença

MIT: free to use, change and share, including commercially. See [LICENSE](LICENSE).
MIT: livre para usar, alterar e partilhar, incluindo uso comercial. Ver [LICENSE](LICENSE).
