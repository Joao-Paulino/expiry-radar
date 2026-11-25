{
  "db_path": "/data/radar.db",
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_file": "/data/collector.crt",
  "tls_key_file": "/data/collector.key",
  "auth_tokens": ["ExpiryRadarDemoTLSAgentToken2026NotASecretJustADemo"],
  "admin_tokens": ["demo-unused-admin-token-not-needed-for-the-dashboard-login"],
  "public_url": "https://expiry.viperspartatech.com",
  "sso_session_hours": 1,
  "oidc_providers": [
    {
      "name": "keycloak",
      "display_name": "Keycloak",
      "issuer": "__KC_PUBLIC_URL__/realms/expiry-demo",
      "client_id": "expiry-radar-demo",
      "client_secret_file": "/data/keycloak.secret",
      "allowed_emails": ["viewer@demo.invalid"],
      "admin_groups": ["unused-forces-the-viewer-role"]
    }
  ]
}
