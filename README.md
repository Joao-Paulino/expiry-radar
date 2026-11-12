<div align="center">

# 📡 Expiry Radar

### Know what expires before it breaks production · Saiba o que expira antes de parar a produção

![CI](https://github.com/Joao-Paulino/expiry-radar/actions/workflows/ci.yml/badge.svg)
![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
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

Requires Go 1.25 or newer (releases are built with Go 1.26) · Requer Go 1.25 ou mais recente (as releases são compiladas com Go 1.26)

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
| 👻 Gone items | An item missing from **two** later error-free runs of the same agent and checker (deleted, renamed, rotated away) leaves the dashboard, and its open alert gets one "no longer reported, verify it was removed on purpose" notification. Runs with errors never hide anything, and an item another agent still reports stays. `agent_id` must be unique per agent: two hosts sharing one would hide each other's items | Um item que falta em **duas** execuções posteriores sem erros do mesmo agente e checker (apagado, renomeado, rodado) sai do painel, e o alerta aberto recebe uma notificação "já não é reportado, confirma que foi removido de propósito". Execuções com erros nunca escondem nada, e um item que outro agente ainda reporta fica. O `agent_id` tem de ser único por agente: dois hosts com o mesmo esconderiam os itens um do outro |
| 📮 Delivery | An alert is only marked as sent when at least one channel delivered it; otherwise it is retried next cycle | Um alerta só fica marcado como enviado quando pelo menos um canal o entregou; senão é tentado no ciclo seguinte |

The dashboard's **Agents** section shows every agent and checker with last seen, last success and failures.
A secção **Agents** do painel mostra cada agente e verificador com a última vez visto, último sucesso e falhas.

### 🪪 SSO (Microsoft Entra ID, Google)

Any OpenID Connect provider can be added, several at once; each gets a button on the login page. The local Administrator (password + TOTP) stays as the break-glass account.
Qualquer fornecedor OpenID Connect pode ser adicionado, vários ao mesmo tempo; cada um tem um botão na página de login. O Administrator local (password + TOTP) fica como conta de emergência.

```json
"public_url": "https://collector.example.com:8443",
"sso_session_hours": 1,
"oidc_providers": [
  { "name": "microsoft", "display_name": "Microsoft",
    "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "client_id": "<application (client) id>", "client_secret_file": "/etc/expiry-radar/entra.secret",
    "allowed_groups": ["<group object id>"], "allowed_roles": ["ExpiryRadar.Admin"] },
  { "name": "google", "display_name": "Google",
    "issuer": "https://accounts.google.com",
    "client_id": "<client id>", "client_secret_file": "/etc/expiry-radar/google.secret",
    "allowed_emails": ["joao@example.com"] }
]
```

| | EN | PT |
|---|---|---|
| ↩️ Redirect URI | Register `<public_url>/auth/<name>/callback` with the provider | Regista `<public_url>/auth/<name>/callback` no fornecedor |
| 🏢 Entra ID | App registration (single tenant), web redirect URI, client secret in a file (`chmod 600`). Authorize with **groups** (`groups` claim: token configuration → groups) or **app roles** (`roles` claim). Microsoft advises against authorizing on email | Registo de aplicação (single tenant), redirect URI web, client secret num ficheiro (`chmod 600`). Autoriza por **grupos** (claim `groups`: token configuration → groups) ou **app roles** (claim `roles`). A Microsoft desaconselha autorizar pelo email |
| 🔵 Google | OAuth client (web application). Google tokens carry no groups: use `allowed_emails` (only **verified** emails count) | Cliente OAuth (aplicação web). Os tokens Google não trazem grupos: usa `allowed_emails` (só contam emails **verificados**) |
| 🚫 Multi-tenant | `/common`, `/organizations` and `/consumers` issuers are refused: use your tenant ID | Emissores `/common`, `/organizations` e `/consumers` são recusados: usa o ID do teu tenant |
| 👥 200+ groups | Entra omits `groups` when a user has more than 200: use app roles or assign groups to the application | O Entra omite `groups` quando o utilizador tem mais de 200: usa app roles ou atribui grupos à aplicação |
| ⏱️ Sessions | SSO sessions last at most `sso_session_hours` (default 1, max 24); removing someone from the allowed Entra group/role, or from `allowed_emails`, blocks their next login | As sessões SSO duram no máximo `sso_session_hours` (por omissão 1, máx. 24); retirar alguém do grupo/role do Entra autorizado, ou de `allowed_emails`, bloqueia o login seguinte |
| ✂️ Cut access now | **Sign out all sessions** on the dashboard ends every session immediately | **Terminar todas as sessões** no painel termina todas as sessões de imediato |
| 🔐 Protections | Authorization Code + PKCE, `state` and `nonce` (single use, 10 min), browser-bound callback, ID token signature/issuer/audience/expiry checks | Authorization Code + PKCE, `state` e `nonce` (uso único, 10 min), callback ligado ao browser, verificação de assinatura/emissor/destinatário/validade do ID token |
| 🌐 Provider down | The collector and the local login keep working; the SSO button shows an error until the provider is back | O collector e o login local continuam a funcionar; o botão SSO mostra erro até o fornecedor voltar |
| 🚦 Limits | 20 login starts per address per 10 min; at most 10 000 pending logins | 20 inícios de login por endereço a cada 10 min; no máximo 10 000 logins pendentes |

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

### 🔒 HashiCorp Vault (PKI, KV v2, tokens, AppRole, leases)

The agent can also check a Vault: certificates issued by PKI mounts and the mounts' CAs, KV v2 secrets with an expiry date in their metadata (e.g. a third-party API key), AppRole secret IDs and, optionally, tokens and dynamic secret leases (databases, cloud credentials). It only reads certificate data, metadata and accessor lookups, never secret values, tokens or secret IDs.
O agente também pode verificar um Vault: certificados emitidos pelos mounts PKI e as respetivas CAs, segredos KV v2 com data de validade nos metadados (ex.: uma API key de terceiros), secret IDs de AppRole e, opcionalmente, tokens e leases de segredos dinâmicos (bases de dados, credenciais cloud). Só lê dados de certificados, metadados e consultas por accessor, nunca valores de segredos, tokens ou secret IDs.

Add to `agent.json` / Acrescenta ao `agent.json`:

```json
"vault": {
  "address": "https://vault.example.com:8200",
  "ca_file": "/etc/expiry-radar/vault-ca.pem",
  "namespace": "",
  "auth": { "approle": { "role_id": "<role id>", "secret_id_file": "/etc/expiry-radar/vault-secret-id" } },
  "pki_mounts": ["pki", "pki_int"],
  "kv_mounts": ["secret"],
  "kv_expiry_key": "expires_at",
  "approle_mounts": ["approle"],
  "check_tokens": false,
  "token_min_ttl_hours": 24,
  "lease_prefixes": [],
  "lease_min_ttl_hours": 24
}
```

Set at least one of `pki_mounts` / `kv_mounts` / `approle_mounts` / `check_tokens` / `lease_prefixes` · Define pelo menos um destes. `kv_expiry_key` is optional (default `expires_at`) · é opcional (por omissão `expires_at`).

Mark a KV secret with its expiry date / Marca um segredo KV com a data de validade (`2027-03-31` or RFC 3339 `2027-03-31T00:00:00Z`):

```bash
vault kv metadata put -custom-metadata=expires_at=2027-03-31 secret/apps/stripe/api-key
```

Least-privilege policy and AppRole / Policy de privilégio mínimo e AppRole (repeat the paths for each mount / repete os caminhos para cada mount). KV: metadata only, no access to `secret/data/*` · KV: só metadados, sem acesso a `secret/data/*`:

```bash
vault policy write expiry-radar - <<'HCL'
path "pki/certs"    { capabilities = ["list"] }
path "pki/cert/*"   { capabilities = ["read"] }
path "pki/issuers"  { capabilities = ["list"] }
path "pki/issuer/*" { capabilities = ["read"] }
path "secret/metadata/*" { capabilities = ["list", "read"] }
path "auth/approle/role"                             { capabilities = ["list"] }
path "auth/approle/role/+/secret-id"                 { capabilities = ["list"] }
path "auth/approle/role/+/secret-id-accessor/lookup" { capabilities = ["update"] }
HCL
vault auth enable approle
vault write auth/approle/role/expiry-radar token_policies=expiry-radar token_ttl=5m
vault read -field=role_id auth/approle/role/expiry-radar/role-id
vault write -f -field=secret_id auth/approle/role/expiry-radar/secret-id > vault-secret-id && chmod 600 vault-secret-id
```

| | EN | PT |
|---|---|---|
| 🔑 Auth | AppRole (logs in every run and revokes the token afterwards) or `"token_file"` | AppRole (faz login a cada verificação e revoga o token no fim) ou `"token_file"` |
| 🔁 Renewed certificates | Vault keeps old certificates listed until `tidy`; only the latest per name is reported | O Vault mantém certificados antigos até ao `tidy`; só o mais recente por nome é reportado |
| 🚫 Skipped | Revoked certificates and ones expired more than 30 days ago | Certificados revogados e expirados há mais de 30 dias |
| 🎫 Tokens (`check_tokens`) | Off by default. Listing token accessors is root-protected in Vault and needs `sudo` (add the two paths below). With it, a compromised agent could map every token and its policies (not read or revoke them). Skips tokens without expiry, the agent's own and those created with a TTL below `token_min_ttl_hours` | Desligado por omissão. Listar accessors de tokens é protegido no Vault e exige `sudo` (acrescenta os dois caminhos abaixo). Com isso, um agente comprometido conseguiria mapear todos os tokens e as políticas (não lê-los nem revogá-los). Ignora tokens sem expiração, o do próprio agente e os criados com TTL abaixo de `token_min_ttl_hours` |
| ⏳ Leases (`lease_prefixes`) | Off by default. Lease ID prefixes such as `database/creds/`; listing leases needs `sudo`, scoped to those prefixes only (policy below). Skips leases granted for less than `lease_min_ttl_hours` (short credentials meant to be re-issued). Vault does not expose a lease's max TTL: the current expiry is reported | Desligado por omissão. Prefixos de lease como `database/creds/`; listar leases exige `sudo`, limitado a esses prefixos (policy abaixo). Ignora leases concedidos por menos de `lease_min_ttl_hours` (credenciais curtas para reemitir). O Vault não expõe o max TTL de um lease: é reportada a expiração atual |
| 🔐 AppRole secret IDs | Secret IDs with a TTL; names show only the first 8 characters of the accessor | Secret IDs com TTL; os nomes mostram só os 8 primeiros caracteres do accessor |
| 🗝️ KV secrets | Only secrets with the expiry key; deleted current versions and invalid dates are skipped (invalid dates are logged). KV v2 only | Só segredos com a chave de validade; versões atuais apagadas e datas inválidas são ignoradas (as inválidas ficam no log). Só KV v2 |
| 🏢 Enterprise | Set `namespace` for Vault Enterprise / HCP namespaces | Define `namespace` para namespaces do Vault Enterprise / HCP |

Policy for `check_tokens` / Policy para `check_tokens` (⚠️ `sudo`):

```hcl
path "auth/token/accessors"       { capabilities = ["list", "sudo"] }
path "auth/token/lookup-accessor" { capabilities = ["update"] }
```

Policy for `lease_prefixes` / Policy para `lease_prefixes` (⚠️ `sudo`, one line per prefix / uma linha por prefixo):

```hcl
path "sys/leases/lookup/database/creds/*" { capabilities = ["list", "sudo"] }
path "sys/leases/lookup"                  { capabilities = ["update"] }
```

### 🔷 Azure (Key Vault, App Registrations, Enterprise Apps, managed certificates)

The agent can also check Azure Key Vaults (certificates, secrets and keys with an expiry date) and, via Microsoft Graph, the client secrets and certificates of App Registrations and the SAML signing certificates of Enterprise Apps. It only calls list endpoints, which return attributes, never values. No Azure SDK: plain REST, so no extra dependencies.
O agente também pode verificar Azure Key Vaults (certificados, segredos e chaves com data de validade) e, via Microsoft Graph, os client secrets e certificados das App Registrations e os certificados de assinatura SAML das Enterprise Apps. Só chama endpoints de listagem, que devolvem atributos, nunca valores. Sem SDK do Azure: REST direto, sem dependências extra.

```json
"azure": {
  "tenant_id": "<tenant id>",
  "client_id": "<client id>",
  "auth": "managed_identity",
  "certificate_file": "/etc/expiry-radar/azure-sp.pem",
  "token_file": "",
  "key_vaults": ["kv-prod-weu", "kv-shared"],
  "subscriptions": ["<subscription id>"],
  "discover_key_vaults": false,
  "app_registrations": true,
  "service_principals": true,
  "managed_certificates": true
}
```

| | EN | PT |
|---|---|---|
| 🔑 `managed_identity` | VM, VMSS, AKS node, App Service, Container Apps or Azure Arc server; detected from the environment. `client_id` only for a user-assigned identity | VM, VMSS, nó AKS, App Service, Container Apps ou servidor Azure Arc; detetado pelo ambiente. `client_id` só para identidade user-assigned |
| 📜 `certificate` | Service principal with a certificate: `certificate_file` = PEM with the certificate (a chain is fine; the one matching the key is used) and its unencrypted RSA key (`chmod 600`). The key never leaves the agent | Service principal com certificado: `certificate_file` = PEM com o certificado (pode ter a cadeia; é usado o que corresponde à chave) e a chave RSA sem password (`chmod 600`). A chave nunca sai do agente |
| 🔗 `workload_identity` | Federated token (AKS workload identity, GitHub Actions, other clouds). `token_file`, `tenant_id`, `client_id` default to `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` | Token federado (workload identity do AKS, GitHub Actions, outras clouds). `token_file`, `tenant_id`, `client_id` usam por omissão `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` |
| 🖥️ Azure Arc | The agent's user must be in the `himds` group (Linux) or Administrators / *Hybrid agent extension applications* (Windows), and `IDENTITY_ENDPOINT` + `IMDS_ENDPOINT` must be in the service environment (e.g. systemd `Environment=`); without them the agent uses 169.254.169.254, which outside Azure is another cloud's metadata service | O utilizador do agente tem de estar no grupo `himds` (Linux) ou Administrators / *Hybrid agent extension applications* (Windows), e `IDENTITY_ENDPOINT` + `IMDS_ENDPOINT` têm de estar no ambiente do serviço (ex.: `Environment=` do systemd); sem elas o agente usa 169.254.169.254, que fora do Azure é o serviço de metadados de outra cloud |
| 🗂️ Vaults | `key_vaults` (least privilege) and/or `discover_key_vaults: true` (every vault in `subscriptions`, any region; adds `location`, `resource_group`, `subscription` to the records; each vault then needs Key Vault Reader, or list on access-policy vaults, otherwise every run reports an error) | `key_vaults` (privilégio mínimo) e/ou `discover_key_vaults: true` (todos os vaults das `subscriptions`, qualquer região; acrescenta `location`, `resource_group`, `subscription` aos registos; cada vault precisa então de Key Vault Reader, ou list nos vaults com access policies, senão cada execução reporta erro) |
| 🪪 `app_registrations` / `service_principals` | Client secrets (kind `secret`) and certificates (kind `certificate`) of every App Registration; SAML signing and other certificates of Enterprise Apps (listed once, not per usage; the PFX password Azure adds is not a separate secret). Managed identities and Microsoft's own service principals are skipped. Names end with the first 8 characters of the key id, so a rotation pair with the same description stays two items. Public cloud only. Needs Graph `Application.Read.All` (application permission, admin consent; reads metadata of every app, nothing narrower exists). Secret values are never returned by Graph and the hint is not stored. Credentials expired more than 30 days ago are skipped | Client secrets (kind `secret`) e certificados (kind `certificate`) de todas as App Registrations; certificados SAML e outros das Enterprise Apps (uma vez, não por utilização; a password do PFX que o Azure acrescenta não conta como secret). Managed identities e service principals da própria Microsoft são ignorados. Os nomes terminam com os 8 primeiros caracteres do key id, para que um par em rotação com a mesma descrição continue a ser dois itens. Só cloud pública. Exige `Application.Read.All` no Graph (permissão de aplicação, admin consent; lê metadados de todas as apps, não existe nada mais restrito). O Graph nunca devolve valores de secrets e o hint não é guardado. Credenciais expiradas há mais de 30 dias são ignoradas |
| 📜 `managed_certificates` | Needs `subscriptions` (Reader). App Service certificates (managed, imported, Key Vault-linked), App Service Certificate orders (`auto_renew` in metadata), Front Door Standard/Premium certificates (managed and customer) and Application Gateway listener certificates (read from the public certificate). A certificate in a Key Vault **and** on an Application Gateway shows twice on purpose: a gateway pinned to an old secret version keeps serving the old certificate after the vault is renewed. Expired certificates keep alerting (they may still be served). Providers never registered in a subscription are skipped. A purchased App Service Certificate imported into an app shows as the order and as the app certificate. Front Door classic / CDN classic are not checked | Exige `subscriptions` (Reader). Certificados do App Service (managed, importados, ligados ao Key Vault), App Service Certificates comprados (`auto_renew` nos metadados), certificados do Front Door Standard/Premium (managed e do cliente) e certificados dos listeners do Application Gateway (lidos do certificado público). Um certificado num Key Vault **e** num Application Gateway aparece duas vezes de propósito: um gateway preso a uma versão antiga do segredo continua a servir o certificado antigo depois de o vault ser renovado. Certificados expirados continuam a alertar (podem ainda estar em uso). Providers nunca registados numa subscrição são ignorados. Um App Service Certificate comprado e importado numa app aparece como encomenda e como certificado da app. Front Door clássico / CDN clássico não são verificados |
| 🚫 Skipped | Items without an expiry date, disabled items, and the secret and key Key Vault creates behind each certificate | Itens sem data de validade, itens desativados e o segredo e a chave que o Key Vault cria por trás de cada certificado |
| 🌐 Networks | One agent covers every region. A vault with private endpoint / firewall must be reachable (VNet + `privatelink.vaultcore.azure.net` DNS, or an allowed IP); otherwise that vault reports `403 ForbiddenByFirewall` or a DNS error and the others still count. Isolated networks: one agent per VNet/hub | Um agente cobre todas as regiões. Um vault com private endpoint / firewall tem de estar acessível (VNet + DNS `privatelink.vaultcore.azure.net`, ou IP permitido); senão esse vault dá `403 ForbiddenByFirewall` ou erro de DNS e os outros continuam. Redes isoladas: um agente por VNet/hub |

Permissions / Permissões (`<principal>` = the identity's object id / object id da identidade):

```bash
# RBAC vaults: Key Vault Reader (metadata only, no values) on each vault
az role assignment create --assignee-object-id <principal> --assignee-principal-type ServicePrincipal --role "Key Vault Reader" \
  --scope "$(az keyvault show -n kv-prod-weu --query id -o tsv)"
# Vaults with access policies: list only (list never returns values)
az keyvault set-policy -n kv-prod-weu --object-id <principal> \
  --certificate-permissions list --secret-permissions list --key-permissions list
# discover_key_vaults / managed_certificates: Reader on the subscription
az role assignment create --assignee-object-id <principal> --assignee-principal-type ServicePrincipal --role Reader --scope /subscriptions/<subscription id>
```

Graph permission / Permissão no Graph (`app_registrations`, `service_principals`):

```bash
GRAPH=00000003-0000-0000-c000-000000000000; ROLE=9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30   # Application.Read.All
# service principal (certificate / workload identity)
az ad app permission add --id <app id> --api $GRAPH --api-permissions $ROLE=Role
az ad app permission admin-consent --id <app id>
# managed identity (no portal button): assign the Graph app role
az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/<identity object id>/appRoleAssignments" \
  --body "{\"principalId\":\"<identity object id>\",\"resourceId\":\"$(az ad sp show --id $GRAPH --query id -o tsv)\",\"appRoleId\":\"$ROLE\"}"
```

Set-up per auth / Configuração por autenticação:

```bash
# certificate: creates the app + service principal and a PEM with cert and key
az ad sp create-for-rbac --name expiry-radar --create-cert   # "fileWithCertAndPrivateKey" -> certificate_file
# workload_identity on AKS: federate a user-assigned identity with the agent's service account
az identity federated-credential create --name expiry-radar --identity-name expiry-radar -g <rg> \
  --issuer "$(az aks show -n <aks> -g <rg> --query oidcIssuerProfile.issuerUrl -o tsv)" \
  --subject system:serviceaccount:<namespace>:expiry-radar
```

<details><summary>CI against a real Key Vault (optional) / CI contra um Key Vault real (opcional)</summary>

GitHub Actions is the workload identity, no secret stored. The `azure` CI job runs only when these repository variables exist. One command does it all: `scripts/azure-ci-setup.sh <resource-group> <location> <vault-name>` (e.g. in Azure Cloud Shell); the steps it runs:
O GitHub Actions é a workload identity, sem segredos guardados. O job `azure` do CI só corre quando estas variáveis existem no repositório. Um só comando faz tudo: `scripts/azure-ci-setup.sh <resource-group> <location> <nome-do-vault>` (ex.: no Azure Cloud Shell); os passos que executa:

```bash
APP=$(az ad app create --display-name expiry-radar-ci --query appId -o tsv)
az ad sp create --id "$APP"
for s in ref:refs/heads/main pull_request; do
  az ad app federated-credential create --id "$APP" --parameters "{\"name\":\"gh-${s//[:\/]/-}\",\"issuer\":\"https://token.actions.githubusercontent.com\",\"subject\":\"repo:Joao-Paulino/expiry-radar:$s\",\"audiences\":[\"api://AzureADTokenExchange\"]}"
done
az keyvault create -n <test vault> -g <rg> -l westeurope --enable-rbac-authorization true
az role assignment create --assignee "$APP" --role "Key Vault Reader" --scope "$(az keyvault show -n <test vault> --query id -o tsv)"
# test items (you need Key Vault Administrator on the vault for this)
az keyvault certificate create --vault-name <test vault> -n er-test-cert -p "$(az keyvault certificate get-default-policy)"
az keyvault secret set --vault-name <test vault> -n er-test-secret --value dummy --expires 2027-12-31T00:00:00Z
az keyvault key create --vault-name <test vault> -n er-test-key --expires 2027-12-31T00:00:00Z
gh variable set AZURE_TEST_TENANT_ID -b "$(az account show --query tenantId -o tsv)"
gh variable set AZURE_TEST_CLIENT_ID -b "$APP"
gh variable set AZURE_TEST_VAULT -b <test vault>
# optional: also test App Registrations (grant Application.Read.All to the CI app as above)
gh variable set AZURE_TEST_GRAPH -b 1
```
</details>

### 🟧 AWS (ACM, IAM server certificates, access keys)

The agent can also check AWS: ACM certificates (issued, **imported** and **ACME** — the last two never renew on their own) and IAM server certificates, in several regions and accounts. Requests are signed with SigV4 by the agent itself (no AWS SDK). Static access keys are not supported, on purpose.
O agente também pode verificar a AWS: certificados do ACM (emitidos, **importados** e **ACME** — os dois últimos nunca renovam sozinhos) e IAM server certificates, em várias regiões e contas. Os pedidos são assinados com SigV4 pelo próprio agente (sem SDK da AWS). Access keys estáticas não são suportadas, de propósito.

```json
"aws": {
  "auth": "instance_role",
  "regions": ["eu-west-1", "us-east-1"],
  "assume_roles": [{ "role_arn": "arn:aws:iam::222222222222:role/expiry-radar-read", "external_id": "optional" }],
  "services": ["acm", "iam_server_certificates", "access_keys"],
  "access_key_max_age_days": 90
}
```

| | EN | PT |
|---|---|---|
| 🖥️ `instance_role` | EC2 (IMDSv2 only), ECS / Fargate task role, EKS Pod Identity; detected from the environment | EC2 (só IMDSv2), task role ECS / Fargate, EKS Pod Identity; detetado pelo ambiente |
| 🔗 `web_identity` | EKS IRSA or any platform that keeps a fresh OIDC token in a file: `token_file` + `role_arn` (default `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`). The file is re-read on every refresh | EKS IRSA ou qualquer plataforma que mantenha um token OIDC atualizado num ficheiro: `token_file` + `role_arn` (por omissão `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`). O ficheiro é relido em cada renovação |
| 📜 `roles_anywhere` | On-premises servers: IAM Roles Anywhere with an X.509 certificate (`certificate_file` PEM with certificate, optional chain and RSA/ECDSA key; `trust_anchor_arn`, `profile_arn` in the same region, which is used; `role_arn`) | Servidores on-prem: IAM Roles Anywhere com certificado X.509 (`certificate_file` PEM com certificado, cadeia opcional e chave RSA/ECDSA; `trust_anchor_arn`, `profile_arn` na mesma região, que é a usada; `role_arn`) |
| 🏢 Multi-account | `assume_roles`: a read-only role in each account (`sts:AssumeRole`, optional `external_id`); `skip_base_account: true` to check only those | `assume_roles`: uma role só de leitura em cada conta (`sts:AssumeRole`, `external_id` opcional); `skip_base_account: true` para verificar só essas |
| 🌍 Regions | `regions` for ACM (only regions enabled in every account: a disabled one is reported as an error); IAM is global. `region` (STS) defaults to the first one. Standard `aws` partition only (not China / GovCloud / ISO yet). The host clock must be right (SigV4 allows 5 minutes) | `regions` para o ACM (só regiões ativas em todas as contas: uma desativada aparece como erro); o IAM é global. `region` (STS) é por omissão a primeira. Só a partição `aws` standard (ainda não China / GovCloud / ISO). O relógio do servidor tem de estar certo (o SigV4 tolera 5 minutos) |
| 🔑 `access_keys` | From the IAM credential report (one per account, up to 4 hours old; the keys are never seen), as a separate checker `aws-access-keys`. Access keys never expire: an active key is due `access_key_max_age_days` (default 90, CIS) after its last rotation; a rotated key is a new item. Any root key is due at once (root should have none). **Inactive** keys are shown as `inactive (no alerts)` on the dashboard and in exports and never alert: they cannot be used, but should be deleted | Do credential report do IAM (um por conta, até 4 horas de idade; as chaves nunca são vistas), como checker separado `aws-access-keys`. As access keys não expiram: uma chave ativa vence `access_key_max_age_days` (por omissão 90, CIS) depois da última rotação; uma chave rodada é um item novo. Qualquer chave root vence logo (a root não devia ter nenhuma). Chaves **inativas** aparecem como `inactive (no alerts)` no painel e nos exports e nunca alertam: não podem ser usadas, mas devem ser apagadas |
| 🚫 Skipped | ACM certificates pending validation (no date yet), revoked, failed, timed out or inactive. Expired ones keep alerting (they may still be served) | Certificados ACM à espera de validação (ainda sem data), revogados, falhados, expirados por timeout ou inativos. Os expirados continuam a alertar (podem ainda estar em uso) |

Read-only policy / Policy só de leitura (in each account / em cada conta):

```json
{ "Version": "2012-10-17", "Statement": [{ "Effect": "Allow",
  "Action": ["acm:ListCertificates", "iam:ListServerCertificates",
             "iam:GenerateCredentialReport", "iam:GetCredentialReport"], "Resource": "*" }] }
```

Multi-account / Multi-conta: the base role also needs `sts:AssumeRole` on the `assume_roles` ARNs; each target role trusts the base role (`"Principal": {"AWS": "<base role ARN>"}`, with an `sts:ExternalId` condition if you set `external_id`) / a role base precisa também de `sts:AssumeRole` sobre os ARNs de `assume_roles`; cada role de destino confia na role base (com a condição `sts:ExternalId` se definires `external_id`).

Trust for the agent's own role / Confiança da role do próprio agente: IRSA → the cluster's OIDC provider with an `aud`/`sub` condition; Roles Anywhere → `"Service": "rolesanywhere.amazonaws.com"` with `sts:AssumeRole`, `sts:TagSession`, `sts:SetSourceIdentity`. `sts:GetCallerIdentity` needs no permission.

## ⚠️ Known limitations / Limitações conhecidas

| EN | PT |
|---|---|
| Two agents checking the same `host:port` overwrite each other; use fully qualified names | Dois agentes que verificam o mesmo `host:porta` sobrepõem-se; usa nomes totalmente qualificados |

## 🗺️ Roadmap

Full vision / Visão completa: [design spec §4](docs/superpowers/specs/2026-11-10-expiry-radar-design.md#4-scope-and-phasing)

| | Milestone | EN | PT |
|---|---|---|---|
| ✅ | **M1** | TLS certificates + core platform (agent, collector, alerts, dashboard, export) | Certificados TLS + plataforma base (agente, collector, alertas, painel, exportação) |
| ✅ | **M2** | HashiCorp Vault: secrets, leases, token TTLs | HashiCorp Vault: segredos, leases, TTL de tokens |
| ✅ | **M3** | Azure: Key Vault, App Registration credentials, managed certificates | Azure: Key Vault, credenciais de App Registrations, certificados geridos |
| 🟡 | **M4** | AWS: ACM, IAM access keys, Secrets Manager rotation | AWS: ACM, access keys IAM, rotação no Secrets Manager |
| ⚪ | **M5** | GCP: Certificate Manager, Secret Manager, service account keys | GCP: Certificate Manager, Secret Manager, chaves de service accounts |
| ⚪ | **M6** | VMware: vCenter/ESXi certificates and licences | VMware: certificados e licenças vCenter/ESXi |
| ⚪ | Later / Depois | Software licences, SaaS subscriptions, then OT/ICS | Licenças de software, subscrições SaaS e depois OT/ICS |

✅ done / concluído · 🟡 in progress / em curso · ⚪ planned / planeado

**Done in M1 / Concluído no M1**

- [x] Dashboard login (password + TOTP) / Login no painel (password + TOTP)
- [x] SSO via OIDC (Entra ID, Google) / SSO via OIDC (Entra ID, Google)
- [x] Alert deduplication / Deduplicação de alertas
- [x] Alerts for failing checkers and silent agents / Alertas de verificadores em falha e agentes silenciosos
- [x] Agent validated on Rocky Linux 9 (RedHat family), Debian 12, Arch in CI / Agente validado em Rocky Linux 9 (família RedHat), Debian 12, Arch no CI
- [x] GitHub release with binaries per platform / Release no GitHub com binários por plataforma
- [x] Docker images for agent and collector / Imagens Docker do agente e do collector

**Done in M2 / Concluído no M2**

- [x] Vault PKI certificates and CA issuers / Certificados PKI e CAs do Vault
- [x] KV v2 secrets with an expiry date in metadata / Segredos KV v2 com data de validade nos metadados
- [x] AppRole secret IDs and (opt-in) tokens / Secret IDs de AppRole e tokens (opcional)
- [x] Dynamic secret leases (opt-in) / Leases de segredos dinâmicos (opcional)
- [x] Release gate: no binary or image ships with a known vulnerability / Bloqueio no release: nenhum binário ou imagem sai com vulnerabilidades conhecidas

**Done in M3 / Concluído no M3**

- [x] Azure auth without stored secrets: managed identity, certificate, workload identity / Autenticação Azure sem segredos guardados: managed identity, certificado, workload identity
- [x] Key Vault certificates, secrets and keys (list or discovery) / Certificados, segredos e chaves do Key Vault (lista ou descoberta)
- [x] App Registration secrets and certificates, Enterprise App SAML certificates / Secrets e certificados das App Registrations, certificados SAML das Enterprise Apps
- [x] Managed certificates: App Service, Front Door, Application Gateway / Certificados geridos: App Service, Front Door, Application Gateway
- [x] Items that disappear stop alerting and resolve once / Itens que desaparecem deixam de alertar e são resolvidos uma vez

## 🛡️ Security / Segurança

Agents only read expiry metadata and never send private keys or secret values.
Found a vulnerability? Please open a private security advisory on this repository.

Os agentes só leem metadados de expiração e nunca enviam chaves privadas nem
valores secretos. Encontraste uma vulnerabilidade? Abre um security advisory
privado neste repositório.

## 📜 Licence / Licença

MIT: free to use, change and share, including commercially. See [LICENSE](LICENSE).
MIT: livre para usar, alterar e partilhar, incluindo uso comercial. Ver [LICENSE](LICENSE).
