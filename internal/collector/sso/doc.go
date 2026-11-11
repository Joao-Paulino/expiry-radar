// Package sso implements dashboard login through OpenID Connect
// providers (Microsoft Entra ID, Google, ...).
package sso

import (
	_ "github.com/coreos/go-oidc/v3/oidc"
	_ "golang.org/x/oauth2"
)
