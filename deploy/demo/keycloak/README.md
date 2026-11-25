# Demo SSO viewer (Keycloak) / Login SSO só de leitura no demo

EN: a public, read-only login for the demo. Keycloak has one user
(`viewer` / `ExpiryRadarViewer!2026`, published on purpose). The collector
maps every SSO user to the **viewer** role because `admin_groups` is set to a
value no one can match. The local Administrator (password + TOTP) is unchanged.

PT: um login público só de leitura para o demo. O Keycloak tem um só utilizador
(`viewer` / `ExpiryRadarViewer!2026`, publicado de propósito). O collector dá o
papel **viewer** a todos os utilizadores SSO porque `admin_groups` tem um valor
que ninguém consegue ter. O Administrator local (password + TOTP) não muda.

## Steps / Passos

```bash
cd deploy
export KC_PUBLIC_URL=https://login.example.com        # HTTPS host of Keycloak (proxy -> 127.0.0.1:8080)
export KC_ADMIN_PASSWORD="$(openssl rand -base64 32)"  # keep it; never publish / guarda; nunca publiques
SECRET="$(openssl rand -hex 32)"

# 1. Render the realm with the client secret / Gerar o realm com o segredo do cliente
mkdir -p demo/keycloak/rendered
sed "s|__CLIENT_SECRET__|$SECRET|" demo/keycloak/expiry-demo-realm.json.tpl \
  > demo/keycloak/rendered/expiry-demo-realm.json
chmod 644 demo/keycloak/rendered/expiry-demo-realm.json   # the Keycloak user must read it

# 2. Put the secret in the collector volume (0600, owner 65532) / Segredo no volume do collector
printf '%s' "$SECRET" | docker run --rm -i --user 65532:65532 -v deploy_demo-data:/data alpine \
  sh -c 'umask 177; cat > /data/keycloak.secret'

# 3. Collector config in the volume / Config do collector no volume
sed "s|__KC_PUBLIC_URL__|$KC_PUBLIC_URL|" demo/keycloak/collector.sso.json.tpl \
  | docker run --rm -i --user 65532:65532 -v deploy_demo-data:/data alpine \
      sh -c 'umask 177; cat > /data/collector.json'

# 4. Start (no -v: keeps the data and the admin credentials) / Arrancar (sem -v)
docker compose -f docker-compose.demo.yml -f docker-compose.demo-sso.yml up -d
```

Check / Verificar: `curl -s "$KC_PUBLIC_URL/realms/expiry-demo/.well-known/openid-configuration"`
must answer with `"issuer": "$KC_PUBLIC_URL/realms/expiry-demo"`.
The login page then shows a **Keycloak** button; the viewer sees no mute /
forget actions.

## Caddy (reverse proxy) / Caddy (proxy inverso)

EN: Keycloak must be reachable over HTTPS at `KC_PUBLIC_URL` (the collector refuses a
plain-HTTP issuer). Point a DNS record (`login`) at the server, then add this to the
`Caddyfile` and reload (`sudo caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy`).
Caddy gets the certificate by itself and sends the `X-Forwarded-*` headers Keycloak expects.

PT: O Keycloak tem de estar acessível por HTTPS em `KC_PUBLIC_URL` (o collector recusa um
issuer em HTTP simples). Cria um registo DNS (`login`) para o servidor, acrescenta isto ao
`Caddyfile` e recarrega (`sudo caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy`).
O Caddy obtém o certificado sozinho e envia os cabeçalhos `X-Forwarded-*` que o Keycloak espera.

```caddyfile
# The demo collector itself (self-signed certificate on 8443) / O próprio collector do demo
expiry.example.com {
	reverse_proxy https://127.0.0.1:8443 {
		transport http {
			tls_insecure_skip_verify
		}
	}
}

# Keycloak: only what the OIDC login needs / só o que o login OIDC precisa
login.example.com {
	# Block the account console first: it would let a visitor change the shared password
	# Bloquear primeiro a consola de conta: deixaria um visitante mudar a password partilhada
	handle /realms/expiry-demo/account* {
		respond 404
	}
	handle /realms/expiry-demo/* {
		reverse_proxy 127.0.0.1:8080
	}
	handle /resources/* {
		reverse_proxy 127.0.0.1:8080
	}
	# Everything else (/admin, /realms/master, ...) stays closed / O resto fica fechado
	handle {
		respond 404
	}
}
```

If Caddy runs in a container, replace `127.0.0.1:8080` with `keycloak:8080` and attach it to the
compose network. / Se o Caddy corre num container, troca `127.0.0.1:8080` por `keycloak:8080`
e liga-o à rede do compose.

Check / Verificar:

```bash
curl -s https://login.example.com/realms/expiry-demo/.well-known/openid-configuration | grep -o '"issuer":"[^"]*"'
curl -s -o /dev/null -w '%{http_code}\n' https://login.example.com/admin/                       # 404
curl -s -o /dev/null -w '%{http_code}\n' https://login.example.com/realms/expiry-demo/account   # 404
```

The first start takes about 2 minutes; the issuer answers empty until Keycloak is up.
O primeiro arranque demora cerca de 2 minutos; o issuer responde vazio até o Keycloak estar pronto.
