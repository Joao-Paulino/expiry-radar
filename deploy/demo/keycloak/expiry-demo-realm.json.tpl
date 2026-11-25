{
  "realm": "expiry-demo",
  "displayName": "Expiry Radar demo (read-only)",
  "displayNameHtml": "Expiry Radar demo<br><small>user: viewer &nbsp;·&nbsp; password: ExpiryRadarViewer!2026</small>",
  "enabled": true,
  "sslRequired": "external",
  "registrationAllowed": false,
  "resetPasswordAllowed": false,
  "editUsernameAllowed": false,
  "rememberMe": false,
  "bruteForceProtected": true,
  "failureFactor": 10,
  "clients": [
    {
      "clientId": "expiry-radar-demo",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "secret": "__CLIENT_SECRET__",
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": false,
      "implicitFlowEnabled": false,
      "serviceAccountsEnabled": false,
      "redirectUris": [
        "https://expiry.viperspartatech.com/auth/keycloak/callback"
      ],
      "webOrigins": [],
      "attributes": {
        "pkce.code.challenge.method": "S256"
      }
    }
  ],
  "users": [
    {
      "username": "viewer",
      "enabled": true,
      "email": "viewer@demo.invalid",
      "emailVerified": true,
      "firstName": "Demo",
      "lastName": "Viewer",
      "requiredActions": [],
      "credentials": [
        {
          "type": "password",
          "value": "ExpiryRadarViewer!2026",
          "temporary": false
        }
      ]
    }
  ]
}
