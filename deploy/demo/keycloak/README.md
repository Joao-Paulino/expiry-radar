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

Reverse proxy: expose only `/realms/expiry-demo/` and `/resources/`. Block
`/admin`, `/realms/master` and `/realms/*/account` (otherwise a visitor could
change the shared password).
