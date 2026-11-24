#!/usr/bin/env bash
# Expiry Radar installer (Linux, systemd) / Instalador Expiry Radar (Linux, systemd)
# Collector and/or agent as hardened systemd services under a dedicated user.
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

VERSION="v1.3.0"
REPO="Joao-Paulino/expiry-radar"
BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
SVC_USER="expiry-radar"
DEFAULT_COL_DIR="/opt/expiry-radar/collector"
DEFAULT_AGENT_DIR="/opt/expiry-radar/agent"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo -e "${RED}[PT] Arquitetura não suportada: $(uname -m) / [EN] Unsupported architecture${NC}"; exit 1 ;;
esac

if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[PT] Por favor, corre este script como root (sudo). / [EN] Please run this script as root (sudo).${NC}"
  exit 1
fi
for tool in systemctl sha256sum; do
  command -v "$tool" >/dev/null || { echo -e "${RED}[PT] Falta o comando $tool / [EN] Missing command $tool${NC}"; exit 1; }
done
if command -v curl >/dev/null; then fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null; then fetch() { wget -q "$1" -O "$2"; }
else echo -e "${RED}[PT] É preciso curl ou wget / [EN] curl or wget is required${NC}"; exit 1; fi

echo -e "${GREEN}=== Instalador Expiry Radar / Expiry Radar Installer (Linux $ARCH, $VERSION) ===${NC}"
echo "1) Instalar Collector / Install Collector"
echo "2) Instalar Agent / Install Agent"
echo "3) Instalar Ambos / Install Both"
read -rp "Escolha uma opção / Choose an option [1-3]: " OPTION
[[ "$OPTION" =~ ^[123]$ ]] || { echo -e "${RED}[PT] Opção inválida / [EN] Invalid option${NC}"; exit 1; }

# --- helpers ---

ensure_user() {
  if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  fi
}

check_and_clean_install() {
  local DIR=$1 SERVICE=$2 NAME=$3
  if { [ -d "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; } || systemctl list-unit-files | grep -q "^$SERVICE.service"; then
    echo -e "${RED}[PT] Aviso: já existe uma instalação do $NAME em $DIR ou o serviço $SERVICE."
    echo -e "[EN] Warning: an installation of $NAME already exists in $DIR or service $SERVICE.${NC}"
    read -rp "[PT] Guardar a antiga e continuar? (s/n) / [EN] Keep the old one aside and continue? (y/n): " CONFIRM
    if [[ "$CONFIRM" =~ ^[sSyY]$ ]]; then
      systemctl stop "$SERVICE" 2>/dev/null || true
      systemctl disable "$SERVICE" 2>/dev/null || true
      rm -f "/etc/systemd/system/$SERVICE.service"
      if [ -d "$DIR" ]; then
        # Never delete: the database and config are kept / Nunca apagar: base de dados e config ficam guardadas
        local BACKUP="$DIR.bak-$(date +%Y%m%d-%H%M%S)"
        mv "$DIR" "$BACKUP"
        echo -e "${GREEN}[PT] Instalação antiga guardada em $BACKUP / [EN] Old installation kept in $BACKUP${NC}"
      fi
    else
      echo -e "${RED}[PT] Instalação do $NAME cancelada. / [EN] $NAME installation cancelled.${NC}"
      exit 1
    fi
  fi
}

download_binary() {
  local BIN_NAME=$1 DEST_DIR=$2
  local DEST_FILE="$DEST_DIR/$BIN_NAME"
  local ASSET="$BIN_NAME-$VERSION-linux-$ARCH"
  echo -e "${YELLOW}[PT] A descarregar: $BASE_URL/$ASSET / [EN] Downloading${NC}" >&2
  fetch "$BASE_URL/$ASSET" "$DEST_FILE" || { echo -e "${RED}[PT] Falha no download / [EN] Download failed${NC}" >&2; exit 1; }
  fetch "$BASE_URL/SHA256SUMS" "$DEST_DIR/SHA256SUMS" || { echo -e "${RED}[PT] Falha ao obter SHA256SUMS / [EN] Could not fetch SHA256SUMS${NC}" >&2; exit 1; }
  local EXPECTED ACTUAL
  EXPECTED=$(awk -v f="$ASSET" '$2==f {print $1}' "$DEST_DIR/SHA256SUMS")
  ACTUAL=$(sha256sum "$DEST_FILE" | awk '{print $1}')
  if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    rm -f "$DEST_FILE"
    echo -e "${RED}[PT] SHA-256 não confere: download rejeitado / [EN] SHA-256 mismatch: download rejected${NC}" >&2
    exit 1
  fi
  chmod 755 "$DEST_FILE"
  echo -e "${GREEN}[PT] Download verificado (SHA-256): $DEST_FILE / [EN] Download verified${NC}" >&2
  echo "$DEST_FILE"
}

new_token() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

generate_certs() {
  local DIR=$1 BIN=$2
  CERT_MODE="selfsigned" # default; dns01_setup overrides to "acme"
  echo "[PT] Certificado do Collector: / [EN] Collector certificate:"
  echo "  1) Self-signed (rápido, laboratório / quick, lab)"
  echo "  2) CA interna própria (sem domínio público / no public domain)"
  echo "  3) Let's Encrypt via DNS-01 (domínio público, sem precisar da porta 80 / public domain, no port 80 needed)"
  read -rp "[1-3, Enter=2]: " CERT_CHOICE
  CERT_CHOICE=${CERT_CHOICE:-2}
  case "$CERT_CHOICE" in
    3)
      dns01_setup "$DIR"
      ;;
    1)
      local IP
      IP=$(hostname -I 2>/dev/null | awk '{print $1}')
      read -rp "[PT] IP/nome que os agentes usam [Enter para ${IP:-localhost}] / [EN] IP/name agents will use: " ANSWER
      COL_HOST=${ANSWER:-${IP:-localhost}}
      "$BIN" gen-cert "$DIR" --host "$COL_HOST"
      ;;
    *)
      local IP
      IP=$(hostname -I 2>/dev/null | awk '{print $1}')
      read -rp "[PT] IP/nome que os agentes usam [Enter para ${IP:-localhost}] / [EN] IP/name agents will use: " ANSWER
      COL_HOST=${ANSWER:-${IP:-localhost}}
      "$BIN" gen-cert "$DIR" --host "$COL_HOST" --ca "$DIR/ca"
      ;;
  esac
  TOKEN_ADMIN=$(new_token)
  echo -e "${GREEN}[PT] Certificado emitido para: $COL_HOST / [EN] Certificate issued for: $COL_HOST${NC}"
}

# trust_cert_for <collector-dir>: the file agents must trust — the internal
# CA's ca.crt when gen-cert created one, otherwise the self-signed leaf.
# Never called when CERT_MODE=acme: a publicly-trusted certificate needs no
# trust file distributed to agents at all.
trust_cert_for() {
  if [ -f "$1/ca/ca.crt" ]; then echo "$1/ca/ca.crt"; else echo "$1/collector.crt"; fi
}

# dns01_setup <collector-dir>: issues a publicly-trusted certificate via
# certbot's DNS-01 challenge (no inbound port 80/443 needed during
# validation, unlike --standalone). Never installs certbot or any plugin
# itself — only checks for them and prints the exact command to run when
# missing, so re-running this installer after installing them picks up
# right here. Writes collector.crt/collector.key the same way every other
# option does, plus a certbot renewal deploy hook so future renewals keep
# them current with no collector restart (certwatch.go reloads on change).
dns01_setup() {
  local DIR=$1
  read -rp "[PT] Domínio público do Collector (ex: collector.example.com) / [EN] Collector's public domain: " DOMAIN
  [ -n "$DOMAIN" ] || { echo -e "${RED}[PT] Domínio é obrigatório / [EN] Domain is required${NC}"; exit 1; }
  read -rp "[PT] Email de contacto (para o Let's Encrypt/ACME) / [EN] Contact email (for Let's Encrypt/ACME): " LE_EMAIL
  [ -n "$LE_EMAIL" ] || { echo -e "${RED}[PT] Email é obrigatório / [EN] Email is required${NC}"; exit 1; }

  echo "[PT] Fornecedor de DNS: / [EN] DNS provider:"
  echo "  1) Cloudflare"
  echo "  2) Route53 (AWS)"
  echo "  3) Google Cloud DNS"
  echo "  4) DigitalOcean"
  echo "  5) Azure DNS (plugin de terceiros / third-party plugin)"
  echo "  6) GoDaddy (plugin de terceiros / third-party plugin)"
  echo "  7) Outro / Other"
  read -rp "[1-7]: " DNS_PROVIDER

  if ! command -v certbot >/dev/null; then
    echo -e "${RED}[PT] certbot não está instalado. Instala-o (ex: sudo apt install certbot, ou sudo pip3 install certbot) e volta a correr este instalador."
    echo -e "[EN] certbot is not installed. Install it (e.g. sudo apt install certbot, or sudo pip3 install certbot) and re-run this installer.${NC}"
    exit 1
  fi

  local CERTBOT_ARGS=(certonly --non-interactive --agree-tos -m "$LE_EMAIL" -d "$DOMAIN")
  case "$DNS_PROVIDER" in
    1) # Cloudflare — official plugin
      certbot plugins --text 2>/dev/null | grep -qi dns-cloudflare || {
        echo -e "${RED}[PT] Falta o plugin certbot-dns-cloudflare. Instala (ex: sudo apt install python3-certbot-dns-cloudflare) e volta a correr."
        echo -e "[EN] Missing the certbot-dns-cloudflare plugin. Install it (e.g. sudo apt install python3-certbot-dns-cloudflare) and re-run.${NC}"
        exit 1
      }
      read -rsp "[PT] Cloudflare API token (com permissão DNS:Edit na zona) / [EN] Cloudflare API token (DNS:Edit on the zone): " CF_TOKEN; echo
      local CRED_DIR="$DIR/dns01-credentials"; mkdir -p "$CRED_DIR"; chmod 700 "$CRED_DIR"
      printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > "$CRED_DIR/cloudflare.ini"
      chmod 600 "$CRED_DIR/cloudflare.ini"
      CERTBOT_ARGS+=(--dns-cloudflare --dns-cloudflare-credentials "$CRED_DIR/cloudflare.ini")
      ;;
    2) # Route53 — official plugin, no credentials file: AWS's own chain
      certbot plugins --text 2>/dev/null | grep -qi dns-route53 || {
        echo -e "${RED}[PT] Falta o plugin certbot-dns-route53. Instala (ex: sudo apt install python3-certbot-dns-route53) e volta a correr."
        echo -e "[EN] Missing the certbot-dns-route53 plugin. Install it (e.g. sudo apt install python3-certbot-dns-route53) and re-run.${NC}"
        exit 1
      }
      read -rp "[PT] AWS Access Key ID / [EN] AWS Access Key ID: " AWS_ID
      read -rsp "[PT] AWS Secret Access Key / [EN] AWS Secret Access Key: " AWS_SECRET; echo
      export AWS_ACCESS_KEY_ID="$AWS_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET"
      echo -e "${YELLOW}[PT] Para as renovações automáticas (certbot renew) também funcionarem, estas credenciais têm de estar acessíveis ao root depois (ex: ~/.aws/credentials). Esta emissão agora usa-as só nesta chamada."
      echo -e "[EN] For automatic renewals (certbot renew) to keep working, these credentials must stay available to root afterwards (e.g. ~/.aws/credentials). This issuance only uses them for this one call.${NC}"
      CERTBOT_ARGS+=(--dns-route53)
      ;;
    3) # Google Cloud DNS — official plugin, existing service-account JSON
      certbot plugins --text 2>/dev/null | grep -qi dns-google || {
        echo -e "${RED}[PT] Falta o plugin certbot-dns-google. Instala (ex: sudo apt install python3-certbot-dns-google) e volta a correr."
        echo -e "[EN] Missing the certbot-dns-google plugin. Install it (e.g. sudo apt install python3-certbot-dns-google) and re-run.${NC}"
        exit 1
      }
      read -rp "[PT] Caminho da chave JSON da service account (com permissão dns.admin) / [EN] Path to the service account JSON key (dns.admin permission): " GCP_JSON
      [ -f "$GCP_JSON" ] || { echo -e "${RED}[PT] Ficheiro não encontrado: $GCP_JSON / [EN] File not found${NC}"; exit 1; }
      CERTBOT_ARGS+=(--dns-google --dns-google-credentials "$GCP_JSON")
      ;;
    4) # DigitalOcean — official plugin
      certbot plugins --text 2>/dev/null | grep -qi dns-digitalocean || {
        echo -e "${RED}[PT] Falta o plugin certbot-dns-digitalocean. Instala (ex: sudo apt install python3-certbot-dns-digitalocean) e volta a correr."
        echo -e "[EN] Missing the certbot-dns-digitalocean plugin. Install it (e.g. sudo apt install python3-certbot-dns-digitalocean) and re-run.${NC}"
        exit 1
      }
      read -rsp "[PT] DigitalOcean API token / [EN] DigitalOcean API token: " DO_TOKEN; echo
      local CRED_DIR="$DIR/dns01-credentials"; mkdir -p "$CRED_DIR"; chmod 700 "$CRED_DIR"
      printf 'dns_digitalocean_token = %s\n' "$DO_TOKEN" > "$CRED_DIR/digitalocean.ini"
      chmod 600 "$CRED_DIR/digitalocean.ini"
      CERTBOT_ARGS+=(--dns-digitalocean --dns-digitalocean-credentials "$CRED_DIR/digitalocean.ini")
      ;;
    5|6|7) # Azure/GoDaddy (third-party) / other: run certbot yourself, we just pick up the result
      local NAME="outro fornecedor / other provider"
      [ "$DNS_PROVIDER" = "5" ] && NAME="Azure DNS (certbot-dns-azure, https://docs.certbot-dns-azure.co.uk/)"
      [ "$DNS_PROVIDER" = "6" ] && NAME="GoDaddy (certbot-dns-godaddy, procura no PyPI / search PyPI)"
      echo -e "${YELLOW}[PT] $NAME não tem um comando automático aqui (plugin de terceiros ou sem suporte direto). Instala o plugin certo e corre tu mesmo, por exemplo:"
      echo -e "  sudo certbot certonly --agree-tos -m $LE_EMAIL -a <nome-do-plugin> -d $DOMAIN"
      echo -e "[EN] $NAME has no automatic command here (third-party plugin, or not directly supported). Install the right plugin and run it yourself, for example:"
      echo -e "  sudo certbot certonly --agree-tos -m $LE_EMAIL -a <plugin-name> -d $DOMAIN${NC}"
      read -rp "[PT] Prime Enter quando o certificado estiver emitido para $DOMAIN / [EN] Press Enter once the certificate is issued for $DOMAIN: " _
      CERTBOT_ARGS=()
      ;;
    *)
      echo -e "${RED}[PT] Opção inválida / [EN] Invalid option${NC}"; exit 1 ;;
  esac

  if [ ${#CERTBOT_ARGS[@]} -gt 0 ]; then
    certbot "${CERTBOT_ARGS[@]}" || { echo -e "${RED}[PT] certbot falhou / [EN] certbot failed${NC}"; exit 1; }
  fi

  local LIVE_DIR="/etc/letsencrypt/live/$DOMAIN"
  if [ ! -f "$LIVE_DIR/fullchain.pem" ] || [ ! -f "$LIVE_DIR/privkey.pem" ]; then
    echo -e "${RED}[PT] Certificado não encontrado em $LIVE_DIR / [EN] Certificate not found at $LIVE_DIR${NC}"
    exit 1
  fi
  cp -f "$LIVE_DIR/fullchain.pem" "$DIR/collector.crt"
  cp -f "$LIVE_DIR/privkey.pem" "$DIR/collector.key"

  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/expiry-radar.sh <<HOOK
#!/bin/sh
# Installed by the Expiry Radar installer: copies the renewed certificate
# where the collector reads it. No restart needed — the collector notices
# the change and reloads it in memory within a minute.
install -o root -g $SVC_USER -m 640 "\$RENEWED_LINEAGE/fullchain.pem" "$DIR/collector.crt"
install -o root -g $SVC_USER -m 640 "\$RENEWED_LINEAGE/privkey.pem"   "$DIR/collector.key"
HOOK
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/expiry-radar.sh

  CERT_MODE="acme"
  COL_HOST="$DOMAIN"
}

add_agent() { # add_agent <collector-bin> <collector.json> <agent-id>: prints the new token
  local out
  out=$("$1" add-agent "$2" "$3") || { echo -e "${RED}[PT] Não foi possível criar o token do agente $3 / [EN] Could not create the token for agent $3${NC}" >&2; exit 1; }
  echo "$out" | grep -E '^[[:space:]]*[0-9a-f]{64}[[:space:]]*$' | head -1 | tr -d '[:space:]'
}

define_admin_password() {
  local BIN=$1 JSON=$2
  echo -e "${YELLOW}[PT] Password de administrador: mínimo 12 caracteres, pedida duas vezes, não aparece no ecrã."
  echo -e "[EN] Administrator password: at least 12 characters, asked twice, not shown on screen.${NC}"
  for _ in 1 2 3 4 5; do
    if "$BIN" set-admin-password "$JSON"; then
      echo -e "${GREEN}[PT] Password definida. / [EN] Password set.${NC}"
      return 0
    fi
    read -rp "[PT] Tentar de novo? (s/n) / [EN] Try again? (y/n): " AGAIN
    [[ "$AGAIN" =~ ^[sSyY]$ ]] || break
  done
  echo -e "${RED}[PT] Password não definida. Mais tarde: sudo $BIN set-admin-password $JSON"
  echo -e "[EN] Password not set. Later: sudo $BIN set-admin-password $JSON${NC}"
  exit 1
}

write_unit() {
  local SERVICE=$1 DESC=$2 BIN=$3 JSON=$4 DIR=$5
  cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=$DESC
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
ExecStart=$BIN $JSON
WorkingDirectory=$DIR
Restart=on-failure
RestartSec=60
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$DIR

[Install]
WantedBy=multi-user.target
EOF
}

ensure_user

# --- COLLECTOR ---
if [ "$OPTION" = "1" ] || [ "$OPTION" = "3" ]; then
  read -rp "[PT] Pasta do Collector [Enter para $DEFAULT_COL_DIR] / [EN] Collector directory: " COL_DIR
  COL_DIR=${COL_DIR:-$DEFAULT_COL_DIR}
  check_and_clean_install "$COL_DIR" "expiry-radar-collector" "Collector"
  mkdir -p "$COL_DIR"

  COL_BIN=$(download_binary "expiry-radar-collector" "$COL_DIR")
  generate_certs "$COL_DIR" "$COL_BIN"

  cat > "$COL_DIR/collector.json" <<EOF
{
  "listen_addr": "0.0.0.0:8443",
  "db_path": "$COL_DIR/radar.db",
  "tls_cert_file": "$COL_DIR/collector.crt",
  "tls_key_file": "$COL_DIR/collector.key",
  "admin_tokens": ["$TOKEN_ADMIN"],
  "alert_interval_seconds": 3000,
  "theme": "dark"
}
EOF

  # One token per agent: each may only report as itself / Um token por agente
  if [ "$OPTION" = "3" ]; then DEFAULT_ID="agent-$(hostname)"; else DEFAULT_ID="agent-01"; fi
  read -rp "[PT] ID do primeiro agente [Enter para $DEFAULT_ID] / [EN] First agent ID: " FIRST_AGENT_ID
  FIRST_AGENT_ID=${FIRST_AGENT_ID:-$DEFAULT_ID}
  FIRST_AGENT_TOKEN=$(add_agent "$COL_BIN" "$COL_DIR/collector.json" "$FIRST_AGENT_ID")
  if [ "$OPTION" = "1" ]; then
    echo -e "${YELLOW}[PT] Token do agente $FIRST_AGENT_ID (guarda-o para instalar esse agente) / [EN] Token for agent $FIRST_AGENT_ID:${NC}"
    echo "  $FIRST_AGENT_TOKEN"
    echo -e "${YELLOW}[PT] Mais agentes / [EN] More agents: sudo $COL_BIN add-agent $COL_DIR/collector.json <id> && sudo systemctl restart expiry-radar-collector${NC}"
  fi

  define_admin_password "$COL_BIN" "$COL_DIR/collector.json"
  echo -e "${YELLOW}[PT] A configurar TOTP do admin... / [EN] Setting admin TOTP...${NC}"
  "$COL_BIN" set-admin-totp "$COL_DIR/collector.json" || {
    echo -e "${RED}[PT] TOTP não configurado. Mais tarde: sudo $COL_BIN set-admin-totp $COL_DIR/collector.json${NC}"; exit 1; }

  # Service user owns the data; secrets readable by root and the service only
  chown -R "$SVC_USER:$SVC_USER" "$COL_DIR"
  chmod 750 "$COL_DIR"
  chmod 600 "$COL_DIR/collector.json" "$COL_DIR/collector.key"
  chmod 644 "$COL_DIR/collector.crt"

  write_unit expiry-radar-collector "Expiry Radar Collector" "$COL_BIN" "$COL_DIR/collector.json" "$COL_DIR"
  systemctl daemon-reload
  systemctl enable --now expiry-radar-collector
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 8443/tcp >/dev/null || true; fi
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --permanent --add-port=8443/tcp >/dev/null && firewall-cmd --reload >/dev/null || true; fi
  echo -e "${GREEN}[PT] Collector instalado e a correr: https://$COL_HOST:8443 / [EN] Collector installed and running${NC}"
fi

# --- AGENT ---
if [ "$OPTION" = "2" ] || [ "$OPTION" = "3" ]; then
  read -rp "[PT] Pasta do Agent [Enter para $DEFAULT_AGENT_DIR] / [EN] Agent directory: " AGENT_DIR
  AGENT_DIR=${AGENT_DIR:-$DEFAULT_AGENT_DIR}
  check_and_clean_install "$AGENT_DIR" "expiry-radar-agent" "Agent"
  mkdir -p "$AGENT_DIR"

  AGENT_BIN=$(download_binary "expiry-radar-agent" "$AGENT_DIR")

  CHECK_COL_DIR=${COL_DIR:-$DEFAULT_COL_DIR}
  if [ -f "$CHECK_COL_DIR/collector.json" ] && [ -f "$CHECK_COL_DIR/collector.crt" ]; then
    if [ "${CERT_MODE:-}" = "acme" ]; then
      echo -e "${GREEN}[PT] Collector encontrado nesta máquina (CA pública): sem ficheiro de confiança a copiar, token só deste agente. / [EN] Local collector found (public CA): no trust file to copy, token for this agent only.${NC}"
      COL_CRT=""
    else
      echo -e "${GREEN}[PT] Collector encontrado nesta máquina: certificado copiado, token só deste agente. / [EN] Local collector found: certificate copied, token for this agent only.${NC}"
      cp -f "$(trust_cert_for "$CHECK_COL_DIR")" "$AGENT_DIR/collector.crt"
      COL_CRT="$AGENT_DIR/collector.crt"
    fi
    if [ -n "${FIRST_AGENT_TOKEN:-}" ]; then
      AGENT_ID=$FIRST_AGENT_ID; AGENT_TOKEN=$FIRST_AGENT_TOKEN
    else
      # Collector installed earlier: add a token for this agent and reload it
      AGENT_ID="agent-$(hostname)"
      AGENT_TOKEN=$(add_agent "$CHECK_COL_DIR/expiry-radar-collector" "$CHECK_COL_DIR/collector.json" "$AGENT_ID")
      systemctl restart expiry-radar-collector 2>/dev/null || true
    fi
    COL_IP=${COL_HOST:-localhost}
  else
    echo -e "${YELLOW}[PT] Collector não encontrado localmente; assume-se remoto. / [EN] Collector not found locally; assuming remote.${NC}"
    read -rp "[PT] IP/nome do Collector / [EN] Collector IP/name: " COL_IP
    echo -e "${YELLOW}[PT] No collector: sudo expiry-radar-collector add-agent collector.json <id> dá o token deste agente. / [EN] On the collector, add-agent gives this agent's token.${NC}"
    read -rsp "[PT] Token do agente / [EN] Agent token: " AGENT_TOKEN; echo
    read -rp "[PT] Caminho do certificado de confiança (collector.crt, ou ca.crt se o collector usa CA interna; deixa em branco se o collector usa CA pública, ex: Let's Encrypt) / [EN] Path to the trust certificate (collector.crt, or ca.crt if the collector uses an internal CA; leave blank if the collector uses a public CA, e.g. Let's Encrypt): " COL_CRT
    read -rp "[PT] ID do agente (ex: linux-web-01) / [EN] Agent ID: " AGENT_ID
    if [ -n "$COL_CRT" ]; then
      [ -f "$COL_CRT" ] || { echo -e "${RED}[PT] Certificado não encontrado: $COL_CRT / [EN] Certificate not found${NC}"; exit 1; }
      cp -f "$COL_CRT" "$AGENT_DIR/collector.crt"; COL_CRT="$AGENT_DIR/collector.crt"
    fi
  fi

  # Local certificate folders that exist and the service user can read
  # (letsencrypt/live is root-only by default: grant read access and add it to local.cert_paths if you want it)
  CERT_PATHS=""
  for d in /etc/pki/tls/certs /etc/letsencrypt/live /etc/nginx/ssl /etc/apache2/ssl /etc/httpd/ssl; do
    [ -d "$d" ] && runuser -u "$SVC_USER" -- test -r "$d" -a -x "$d" 2>/dev/null && CERT_PATHS="$CERT_PATHS\"$d\", "
  done
  CERT_PATHS=${CERT_PATHS%, }

  cat > "$AGENT_DIR/agent.json" <<EOF
{
  "collector_url": "https://$COL_IP:8443",
  "collector_ca_file": "$COL_CRT",
  "token": "$AGENT_TOKEN",
  "agent_id": "$AGENT_ID",
  "queue_path": "$AGENT_DIR/queue.jsonl",
  "interval_seconds": 300,
  "local": { "cert_paths": [$CERT_PATHS] },
  "tls_targets": [
    { "host": "www.google.com", "port": 443 },
    { "host": "github.com", "port": 443 },
    { "host": "linkedin.com", "port": 443 },
    { "host": "azure.microsoft.com", "port": 443 },
    { "host": "aws.amazon.com", "port": 443 },
    { "host": "cloud.google.com", "port": 443 },
    { "host": "vmware.com", "port": 443 }
  ]
}
EOF
  chown -R "$SVC_USER:$SVC_USER" "$AGENT_DIR"
  chmod 750 "$AGENT_DIR"
  chmod 600 "$AGENT_DIR/agent.json"

  write_unit expiry-radar-agent "Expiry Radar Agent" "$AGENT_BIN" "$AGENT_DIR/agent.json" "$AGENT_DIR"
  systemctl daemon-reload
  systemctl enable --now expiry-radar-agent
  echo -e "${GREEN}[PT] Agent instalado e a correr em $AGENT_DIR / [EN] Agent installed and running${NC}"
  if [ -n "$CERT_PATHS" ]; then
    echo -e "${YELLOW}[PT] Certificados locais: $CERT_PATHS. Se alguma pasta não for legível pelo utilizador $SVC_USER, o checker local-certs reporta erro; ajusta local.cert_paths em agent.json."
    echo -e "[EN] Local certificates: $CERT_PATHS. If a folder is not readable by $SVC_USER, the local-certs checker reports an error; adjust local.cert_paths in agent.json.${NC}"
  fi
fi

echo -e "${GREEN}[PT] Logs: journalctl -u expiry-radar-collector -u expiry-radar-agent -f / [EN] Logs: same command${NC}"
