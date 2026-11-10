# Expiry Radar

[English](README.md) · **Português (PT-PT)**

Saiba o que está prestes a expirar antes que cause um incidente.

O Expiry Radar é uma ferramenta open-source, alojada por si, que acompanha as
datas de expiração em toda a sua infraestrutura. Agentes leves verificam o que
conseguem ver localmente e enviam os resultados para um collector central, que
os guarda, os mostra num painel e envia alertas antes que algo expire.

> **Estado: milestone 1 (fase inicial).** O verificador de certificados TLS e a
> plataforma base (agente, collector, painel, alertas) funcionam de ponta a
> ponta. Segredos, recursos de cloud e plataformas de virtualização estão
> planeados. Consulte as [Limitações conhecidas](#limitações-conhecidas).

## Como funciona

```
 servidores / VMs                           central
┌────────────┐   HTTPS + bearer token   ┌──────────────────────┐
│   agente   │ ───────────────────────▶ │      collector       │
│ TLS checks │   (fila local se o       │ SQLite · painel      │
└────────────┘    collector falhar)     │ alertas · JSON/CSV   │
                                        └──────────────────────┘
```

- **Agente**: um único binário Go, sem dependências (Windows, Linux amd64 e
  arm64). Verifica certificados TLS periodicamente, incluindo SMTP STARTTLS,
  e regista certificados expirados ou não confiáveis em vez de os ignorar.
- **Collector**: um único serviço Go. Recebe os resultados por HTTPS, guarda-os
  em SQLite (Go puro, sem CGO), disponibiliza o painel e a exportação, e envia
  alertas para um webhook, Slack, Microsoft Teams ou email.
- **Tokens separados**: os agentes usam tokens de ingestão; o painel, o
  silenciamento e a exportação exigem um token de administração diferente.
- **Nunca guarda valores secretos**: apenas nomes, origens e datas de expiração.

## Compilar

Requer Go 1.24.

```bash
git clone https://github.com/Joao-Paulino/expiry-radar.git
cd expiry-radar
go test ./...
go build -o collector ./cmd/collector
./scripts/build-agent.sh   # dist/agent-{windows-amd64.exe,linux-amd64,linux-arm64}
```

## Configurar o collector

`collector.json`:

```json
{
  "db_path": "/var/lib/expiry-radar/radar.db",
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_file": "/etc/expiry-radar/collector.crt",
  "tls_key_file": "/etc/expiry-radar/collector.key",
  "auth_tokens": ["<token longo e aleatório para os agentes>"],
  "admin_tokens": ["<outro token longo e aleatório para administração>"],
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

Abra `https://<collector>:8443/` e envie o token de administração no cabeçalho
`Authorization: Bearer <token de administração>`.

## Configurar um agente

`agent.json`:

```json
{
  "collector_url": "https://collector.example.com:8443/ingest",
  "collector_ca_file": "/etc/expiry-radar/collector-ca.pem",
  "token": "<token do agente>",
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

O `collector_ca_file` só é necessário quando o collector usa um certificado
autoassinado. O agente recusa endereços `http://` sem encriptação.

## Limitações conhecidas

O milestone 1 deixa estes pontos, de forma deliberada, para o próximo milestone:

- Ainda não há alerta quando um verificador falha repetidamente ou um agente
  deixa de reportar.
- Os alertas não são deduplicados: cada ciclo volta a enviar todos os registos
  que não estão OK. Silencie um registo para parar os alertas.
- Os registos são identificados por `host:porta`, nome e tipo, por isso dois
  agentes que verificam o mesmo endereço (por exemplo `localhost:443`)
  sobrepõem-se. Use nomes de alvo totalmente qualificados.
- `go install ...@latest` ainda não funciona; compile a partir do código-fonte
  como indicado acima.

## Roadmap

Verificadores de cofres de segredos (por exemplo Vault), recursos de
fornecedores de cloud, certificados e licenças de plataformas de
virtualização, imagens de contentores e empacotamento como infraestrutura
como código.

## Licença

[MIT](LICENSE)
