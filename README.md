<div align="center">

# 📡 Expiry Radar

### Know what expires before it breaks production · Saiba o que expira antes de parar a produção

![CI](https://github.com/Joao-Paulino/expiry-radar/actions/workflows/ci.yml/badge.svg)
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
| 🔔 | Alerts: Slack, Microsoft Teams, webhook, encrypted email | Alertas: Slack, Microsoft Teams, webhook, email encriptado |
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

Or install directly / Ou instala diretamente:

```bash
go install github.com/Joao-Paulino/expiry-radar/cmd/collector@latest
go install github.com/Joao-Paulino/expiry-radar/cmd/agent@latest
```

### 🖥️ Collector

`collector.json`

```json
{
  "db_path": "/var/lib/expiry-radar/radar.db",
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_file": "/etc/expiry-radar/collector.crt",
  "tls_key_file": "/etc/expiry-radar/collector.key",
  "auth_tokens": ["<agent token, see Tokens below>"],
  "admin_tokens": ["<admin token, see Tokens below>"],
  "alert_interval_seconds": 3600,
  "slack_webhook_url": "",
  "teams_webhook_url": "",
  "webhook_url": "",
  "email": {
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "security": "starttls",
    "username": "alerts@example.com",
    "password": "<smtp password>",
    "from": "alerts@example.com",
    "to": "secops@example.com"
  }
}
```

Leave `smtp_host` empty to disable email. Deixa `smtp_host` vazio para desligar o email.

```bash
chmod 600 collector.json      # it holds tokens and the SMTP password
./collector collector.json
```

### 🔑 Tokens

Tokens are shared secrets, so generate them randomly; never invent them.
Os tokens são segredos partilhados, por isso gera-os aleatoriamente; nunca os inventes.

```bash
# Linux / macOS
openssl rand -hex 32
```

```powershell
# Windows (PowerShell 7+)
[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLower()
```

Each command prints a 64-character token. Run it once per token.
Cada comando gera um token de 64 caracteres. Corre-o uma vez por token.

| | EN | PT |
|---|---|---|
| `auth_tokens` | Tokens agents use to send results. Use one per agent (or per group of agents) and copy it into that agent's `token`. | Tokens que os agentes usam para enviar resultados. Usa um por agente (ou por grupo) e copia-o para o `token` desse agente. |
| `admin_tokens` | Tokens for the dashboard, mute and export. Must be different from every agent token. | Tokens para o painel, silenciamento e exportação. Têm de ser diferentes de todos os tokens de agente. |
| Rules | At least 32 characters; empty, short or shared tokens stop the collector from starting. | Mínimo de 32 caracteres; tokens vazios, curtos ou repetidos impedem o collector de arrancar. |
| Rotate | Add the new token, update the agents, then remove the old one. Both work in between. | Adiciona o novo token, atualiza os agentes e depois remove o antigo. Ambos funcionam entretanto. |
| Revoke | Remove the token from the list and restart the collector. | Remove o token da lista e reinicia o collector. |

To open the dashboard, send the admin token as a header (for example with
`curl`, or a header extension in your browser):
Para abrir o painel, envia o token de administração num cabeçalho (por
exemplo com `curl`, ou com uma extensão de cabeçalhos no browser):

```bash
curl -H "Authorization: Bearer <admin token>" https://<collector>:8443/export.json
```

### 📧 Email

Email is always encrypted; there is no plaintext mode.
O email é sempre encriptado; não existe modo sem encriptação.

| `security` | Port / Porta | EN | PT |
|---|---|---|---|
| `starttls` (default) | 587 | Upgrades to TLS and refuses to send if the server does not offer STARTTLS | Passa a TLS e recusa enviar se o servidor não suportar STARTTLS |
| `tls` | 465 | TLS from the first byte | TLS desde o primeiro byte |

`username` and `password` are optional (SMTP AUTH), and are only sent after the
connection is encrypted. The server certificate is verified, TLS 1.2 minimum.
`username` e `password` são opcionais (SMTP AUTH) e só são enviados depois de a
ligação estar encriptada. O certificado do servidor é verificado, com TLS 1.2 no mínimo.

### 🛰️ Agent / Agente

`agent.json`

```json
{
  "collector_url": "https://collector.example.com:8443/ingest",
  "collector_ca_file": "/etc/expiry-radar/collector-ca.pem",
  "token": "<one of the collector's auth_tokens>",
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
chmod 600 agent.json          # it holds the agent token
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

## 🗺️ Roadmap

Full vision / Visão completa: [design spec §4](docs/superpowers/specs/2026-11-10-expiry-radar-design.md#4-scope-and-phasing)

| | Milestone | EN | PT |
|---|---|---|---|
| 🟡 | **M1** | TLS certificates + core platform (agent, collector, alerts, dashboard, export) | Certificados TLS + plataforma base (agente, collector, alertas, painel, exportação) |
| ⚪ | **M2** | HashiCorp Vault: secrets, leases, token TTLs | HashiCorp Vault: segredos, leases, TTL de tokens |
| ⚪ | **M3** | Azure: Key Vault, App Registration credentials, managed certificates | Azure: Key Vault, credenciais de App Registrations, certificados geridos |
| ⚪ | **M4** | AWS: ACM, IAM access keys, Secrets Manager rotation | AWS: ACM, access keys IAM, rotação no Secrets Manager |
| ⚪ | **M5** | GCP: Certificate Manager, Secret Manager, service account keys | GCP: Certificate Manager, Secret Manager, chaves de service accounts |
| ⚪ | **M6** | VMware: vCenter/ESXi certificates and licences | VMware: certificados e licenças vCenter/ESXi |
| ⚪ | Later / Depois | Software licences, SaaS subscriptions, then OT/ICS | Licenças de software, subscrições SaaS e depois OT/ICS |

🟡 in progress / em curso · ⚪ planned / planeado

**Still open in M1 / Ainda em aberto no M1**

- [ ] Dashboard login page / Página de login no painel
- [ ] Alert deduplication / Deduplicação de alertas
- [ ] Alerts for failing checkers and silent agents / Alertas de verificadores em falha e agentes silenciosos
- [ ] Agent validated on RedHat, Debian, Arch / Agente validado em RedHat, Debian, Arch
- [ ] GitHub release with binaries per platform / Release no GitHub com binários por plataforma
- [ ] Docker images for agent and collector / Imagens Docker do agente e do collector

## 🛡️ Security / Segurança

Agents only read expiry metadata and never send private keys or secret values.
Found a vulnerability? Please open a private security advisory on this repository.

Os agentes só leem metadados de expiração e nunca enviam chaves privadas nem
valores secretos. Encontraste uma vulnerabilidade? Abre um security advisory
privado neste repositório.

## 📜 Licence / Licença

MIT: free to use, change and share, including commercially. See [LICENSE](LICENSE).
MIT: livre para usar, alterar e partilhar, incluindo uso comercial. Ver [LICENSE](LICENSE).
