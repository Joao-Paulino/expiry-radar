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

## 📦 Install / Instalar

**Binaries / Binários:** download from [Releases](https://github.com/Joao-Paulino/expiry-radar/releases) and check them:
descarrega de [Releases](https://github.com/Joao-Paulino/expiry-radar/releases) e verifica:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify expiry-radar-agent-<version>-linux-amd64 --repo Joao-Paulino/expiry-radar   # build provenance
./expiry-radar-agent-<version>-linux-amd64 version
```

| Binary / Binário | Platforms / Plataformas |
|---|---|
| `expiry-radar-collector` | Linux amd64, arm64 |
| `expiry-radar-agent` | Linux amd64, arm64 · Windows amd64 |

**Docker:** multi-arch images (amd64, arm64), distroless, non-root / imagens multi-arquitetura, distroless, sem root:

```bash
docker pull ghcr.io/joao-paulino/expiry-radar-collector:latest
docker pull ghcr.io/joao-paulino/expiry-radar-agent:latest
```

Full example / Exemplo completo: [`deploy/docker-compose.example.yml`](deploy/docker-compose.example.yml).
The images have no `stty`, so `set-admin-password` shows the password while you type (it warns you).
As imagens não têm `stty`, por isso o `set-admin-password` mostra a password enquanto escreves (e avisa).

## 🚀 Quick start / Início rápido

Requires Go 1.24 · Requer Go 1.24

```bash
git clone https://github.com/Joao-Paulino/expiry-radar.git
cd expiry-radar
go test ./...
go build -o collector ./cmd/collector
./scripts/build-release.sh   # all binaries + SHA256SUMS in dist/ / todos os binários + SHA256SUMS em dist/
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

| Field / Campo | EN | PT |
|---|---|---|
| `db_path` | SQLite database file, created if missing | Ficheiro da base de dados SQLite, criado se não existir |
| `listen_addr` | Address and port the collector listens on (HTTPS only) | Endereço e porta onde o collector escuta (só HTTPS) |
| `tls_cert_file` | Collector certificate, PEM. See [🔒 Collector certificate](#-collector-certificate--certificado-do-collector) | Certificado do collector, em PEM. Ver [🔒 Certificado](#-collector-certificate--certificado-do-collector) |
| `tls_key_file` | Private key of that certificate, PEM | Chave privada desse certificado, em PEM |
| `auth_tokens` | Tokens agents use to send results. See [🔑 Tokens](#-tokens) | Tokens que os agentes usam para enviar resultados. Ver [🔑 Tokens](#-tokens) |
| `admin_tokens` | Tokens for the dashboard, mute and export. See [🔑 Tokens](#-tokens) | Tokens para o painel, silenciamento e exportação. Ver [🔑 Tokens](#-tokens) |
| `alert_interval_seconds` | How often alerts are evaluated; `0` disables alerting | De quanto em quanto tempo os alertas são avaliados; `0` desliga os alertas |
| `reminder_critical_hours` | Re-send an unchanged critical alert after this many hours (default 24, `0` = never) | Reenvia um alerta crítico inalterado ao fim destas horas (por omissão 24, `0` = nunca) |
| `reminder_warning_hours` | Same for warnings (default `0` = never) | O mesmo para avisos (por omissão `0` = nunca) |
| `checker_fail_threshold` | Consecutive failures before a checker alerts (default 3) | Falhas seguidas até um verificador alertar (por omissão 3) |
| `agent_stale_hours` | Hours without a report before an agent alerts as silent (default 3). Keep it about 2× the longest agent `interval_seconds` | Horas sem reportar até um agente alertar como silencioso (por omissão 3). Mantém cerca de 2× o maior `interval_seconds` dos agentes |
| `slack_webhook_url` / `teams_webhook_url` / `webhook_url` | Incoming webhook URLs; leave empty to disable | URLs de webhook; vazio desliga |
| `email` | SMTP settings. See [📧 Email](#-email). Empty `smtp_host` disables email | Definições SMTP. Ver [📧 Email](#-email). `smtp_host` vazio desliga o email |

```bash
chmod 600 collector.json      # it holds tokens and the SMTP password
./collector collector.json
```

### 🔒 Collector certificate / Certificado do collector

The collector only speaks HTTPS, so it needs a certificate (`tls_cert_file`) and
its private key (`tls_key_file`), both in PEM format. The certificate must name
the address agents use in `collector_url` in its Subject Alternative Name (SAN):
Go ignores the CN.

O collector só fala HTTPS, por isso precisa de um certificado (`tls_cert_file`)
e da respetiva chave privada (`tls_key_file`), ambos em PEM. O certificado tem
de incluir no Subject Alternative Name (SAN) o endereço que os agentes usam em
`collector_url`: o Go ignora o CN.

| Option / Opção | EN | PT |
|---|---|---|
| **A. Public CA** (e.g. Let's Encrypt) | Best when the collector has a public DNS name. Agents trust it with no extra setting. | O melhor quando o collector tem nome DNS público. Os agentes confiam sem configuração extra. |
| **B. Internal CA** | Use your company PKI. Give agents the CA certificate in `collector_ca_file` unless it is already in the system trust store. | Usa a PKI da empresa. Dá aos agentes o certificado da CA em `collector_ca_file`, se ainda não estiver no repositório de confiança do sistema. |
| **C. Self-signed** | Quick for labs and small setups. Copy the certificate to every agent as `collector_ca_file`. | Rápido para laboratórios e instalações pequenas. Copia o certificado para cada agente como `collector_ca_file`. |

**A. Let's Encrypt**

```bash
sudo certbot certonly --standalone -d collector.example.com
# tls_cert_file: /etc/letsencrypt/live/collector.example.com/fullchain.pem
# tls_key_file:  /etc/letsencrypt/live/collector.example.com/privkey.pem
```

**C. Self-signed / Autoassinado** (OpenSSL 1.1.1+; on Windows use the `openssl` bundled with Git for Windows)

```bash
sudo mkdir -p /etc/expiry-radar
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 \
  -days 365 -nodes \
  -keyout /etc/expiry-radar/collector.key \
  -out    /etc/expiry-radar/collector.crt \
  -subj   "/CN=collector.example.com" \
  -addext "subjectAltName=DNS:collector.example.com,IP:10.0.0.10"
sudo chmod 600 /etc/expiry-radar/collector.key
```

Replace the DNS name and IP with the ones agents will use. Then copy
`collector.crt` (never the `.key`) to each agent and point `collector_ca_file` to it.

Substitui o nome DNS e o IP pelos que os agentes vão usar. Depois copia o
`collector.crt` (nunca o `.key`) para cada agente e aponta o `collector_ca_file` para ele.

> 💡 The collector loads its certificate at startup: restart it after renewing.
> Add the collector itself to an agent's `tls_targets` and Expiry Radar will warn
> you before its own certificate expires.
>
> 💡 O collector carrega o certificado no arranque: reinicia-o depois de o renovar.
> Junta o próprio collector aos `tls_targets` de um agente e o Expiry Radar avisa-te
> antes de o seu próprio certificado expirar.

### 🔔 Alerts / Alertas

| | EN | PT |
|---|---|---|
| 🆕 New or changed | Sent when something becomes a problem or its severity changes | Enviado quando algo passa a ser problema ou muda de severidade |
| ✅ Resolved | One message when it is back to OK (e.g. certificate renewed) | Uma mensagem quando volta a OK (por exemplo, certificado renovado) |
| 🔁 Reminders | Critical alerts repeat every `reminder_critical_hours`; nothing repeats every cycle | Alertas críticos repetem a cada `reminder_critical_hours`; nada se repete em cada ciclo |
| 🔇 Muted | Muted records send nothing; unmuting a still-failing record alerts again | Registos silenciados não enviam nada; ao tirar o silêncio, se ainda houver problema, volta a alertar |
| 🩺 Checker failing | A checker failing `checker_fail_threshold` times in a row on an agent | Um verificador que falha `checker_fail_threshold` vezes seguidas num agente |
| 📴 Agent silent | An agent with no report for `agent_stale_hours` | Um agente sem reportar há `agent_stale_hours` |
| 🗑️ Retired agent | **Forget** on the dashboard removes it and stops its alerts; it comes back if it reports again | **Esquecer** no painel remove-o e para os alertas; volta se reportar de novo |
| 📮 Delivery | An alert is only marked as sent when at least one channel delivered it; otherwise it is retried next cycle | Um alerta só fica marcado como enviado quando pelo menos um canal o entregou; senão é tentado no ciclo seguinte |

The dashboard's **Agents** section shows every agent and checker with last seen, last success and failures.
A secção **Agents** do painel mostra cada agente e verificador com a última vez visto, último sucesso e falhas.

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

Scripts use the admin token as a header; people use the login page below.
Os scripts usam o token de administração num cabeçalho; as pessoas usam a página de login abaixo.

```bash
curl -H "Authorization: Bearer <admin token>" https://<collector>:8443/export.json
```

### 🔐 Dashboard login / Login no painel

The dashboard has one **Administrator** account protected by a password **and**
an authenticator app (TOTP). Both are set on the collector server, never in a
config file. Login stays disabled until both are set.

O painel tem uma conta **Administrator** protegida por password **e** por uma
app de autenticação (TOTP). As duas são definidas no servidor do collector,
nunca num ficheiro de configuração. O login só fica ativo depois de ambas
estarem definidas.

```bash
# 1. Password (min. 12 characters, typed twice, not shown)
./collector set-admin-password collector.json

# 2. Authenticator app: scan the key, type the 6-digit code, save the 8 recovery codes
./collector set-admin-totp collector.json
#    optional QR code in the terminal / QR opcional no terminal:
#    qrencode -t ansiutf8 '<otpauth URI printed above>'
```

Then open `https://<collector>:8443/`, sign in with the password and the current
code (or a recovery code).
Depois abre `https://<collector>:8443/` e entra com a password e o código atual
(ou um código de recuperação).

| | EN | PT |
|---|---|---|
| 🔒 Lockout | 5 failed logins from one address block that address for 15 minutes; 20 failures in a row from anywhere lock the account for 15 minutes | 5 tentativas falhadas do mesmo endereço bloqueiam esse endereço durante 15 minutos; 20 falhas seguidas, de qualquer origem, bloqueiam a conta durante 15 minutos |
| 🧰 Locked out? | The admin token still works with `curl`, and `set-admin-password` clears the lock | O token de administração continua a funcionar com `curl`, e o `set-admin-password` limpa o bloqueio |
| ⏱️ Session | Ends after 30 min idle or 8 h in total; **Sign out** ends it now | Termina após 30 min sem atividade ou 8 h no total; **Sair** termina-a já |
| 🔁 Codes | Each authenticator code and each recovery code works only once | Cada código da app e cada código de recuperação só funciona uma vez |
| 🆘 Lost phone | Run `set-admin-totp` again on the server (new key, new recovery codes) | Corre de novo `set-admin-totp` no servidor (nova chave, novos códigos) |
| 🚪 Sign out everyone | Running either command signs out every open session | Correr qualquer um dos comandos termina todas as sessões abertas |
| 🔀 Reverse proxy | Login limits and logs use the client address the collector sees; behind a proxy that is the proxy's address, so expose the collector directly | Os limites de login e os logs usam o endereço que o collector vê; atrás de um proxy é o do proxy, por isso expõe o collector diretamente |
| 📝 Audit | Logins, failures, lockouts, recovery-code use (with codes left) and CSRF rejections are logged; secrets never are | Logins, falhas, bloqueios, uso de códigos de recuperação (com os que restam) e rejeições CSRF ficam no log; segredos nunca |
| 🕒 Clock | The server clock must be correct (NTP) for codes to match | O relógio do servidor tem de estar certo (NTP) para os códigos baterem certo |

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
  "collector_url": "https://collector.example.com:8443",
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

| Field / Campo | EN | PT |
|---|---|---|
| `collector_url` | Collector address, e.g. `https://collector:8443` (`/ingest` is added automatically); must use `https://` | Endereço do collector, por exemplo `https://collector:8443` (o `/ingest` é acrescentado automaticamente); tem de usar `https://` |
| `collector_ca_file` | Collector CA certificate, PEM; only for internal CA or self-signed (options B and C above) | Certificado da CA do collector, em PEM; só para CA interna ou autoassinado (opções B e C acima) |
| `token` | One of the collector's `auth_tokens` | Um dos `auth_tokens` do collector |
| `agent_id` | Name of this agent, shown on the dashboard | Nome deste agente, mostrado no painel |
| `queue_path` | Local file where results wait while the collector is unreachable | Ficheiro local onde os resultados esperam enquanto o collector não responde |
| `interval_seconds` | Seconds between checks; the first check runs at startup | Segundos entre verificações; a primeira corre no arranque |
| `tls_targets` | Hosts to check: `host`, `port`, and `start_tls: "smtp"` for mail servers | Servidores a verificar: `host`, `port`, e `start_tls: "smtp"` para servidores de email |

## ⚠️ Known limitations / Limitações conhecidas

| EN | PT |
|---|---|
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

- [x] Dashboard login (password + TOTP) / Login no painel (password + TOTP)
- [ ] SSO via OIDC (Entra ID, Google) / SSO via OIDC (Entra ID, Google)
- [x] Alert deduplication / Deduplicação de alertas
- [x] Alerts for failing checkers and silent agents / Alertas de verificadores em falha e agentes silenciosos
- [ ] Agent validated on RedHat, Debian, Arch / Agente validado em RedHat, Debian, Arch
- [x] GitHub release with binaries per platform / Release no GitHub com binários por plataforma
- [x] Docker images for agent and collector / Imagens Docker do agente e do collector

## 🛡️ Security / Segurança

Agents only read expiry metadata and never send private keys or secret values.
Found a vulnerability? Please open a private security advisory on this repository.

Os agentes só leem metadados de expiração e nunca enviam chaves privadas nem
valores secretos. Encontraste uma vulnerabilidade? Abre um security advisory
privado neste repositório.

## 📜 Licence / Licença

MIT: free to use, change and share, including commercially. See [LICENSE](LICENSE).
MIT: livre para usar, alterar e partilhar, incluindo uso comercial. Ver [LICENSE](LICENSE).
