// Package sso implements dashboard login through OpenID Connect
// providers (Microsoft Entra ID, Google, ...).
package sso

import (
	"context"
	"crypto/subtle"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// BindCookieName binds a callback to the browser that started the
// login. SameSite=Lax so it survives the top-level redirect back from
// the provider.
const BindCookieName = "__Host-er_sso"

const discoveryTimeout = 10 * time.Second

// Handlers serves /auth/<name>/login and /auth/<name>/callback.
type Handlers struct {
	Providers       []ProviderConfig
	PublicURL       string
	Flows           *FlowStore
	Sessions        *session.Store
	SessionLifetime time.Duration
	HTTPClient      *http.Client // for provider calls; nil = default

	mu      sync.Mutex
	clients map[string]*providerClient // discovered lazily, so an IdP outage never blocks startup
}

type providerClient struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// Button is a login button for the login page.
type Button struct{ Label, URL string }

// Buttons lists one login button per configured provider.
func (h *Handlers) Buttons() []Button {
	var b []Button
	for _, p := range h.Providers {
		label := p.DisplayName
		if label == "" {
			label = p.Name
		}
		b = append(b, Button{Label: label, URL: "/auth/" + p.Name + "/login"})
	}
	return b
}

// Register adds the SSO routes to mux.
func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/{name}/login", h.login)
	mux.HandleFunc("GET /auth/{name}/callback", h.callback)
}

func (h *Handlers) provider(name string) (ProviderConfig, bool) {
	for _, p := range h.Providers {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderConfig{}, false
}

func (h *Handlers) ctx(ctx context.Context) context.Context {
	if h.HTTPClient != nil {
		return oidc.ClientContext(ctx, h.HTTPClient)
	}
	return ctx
}

// client discovers the provider on first use and caches only success,
// so a provider that was down is retried on the next login.
func (h *Handlers) client(ctx context.Context, p ProviderConfig) (*providerClient, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.clients[p.Name]; ok {
		return c, nil
	}
	dctx, cancel := context.WithTimeout(h.ctx(ctx), discoveryTimeout)
	defer cancel()
	op, err := oidc.NewProvider(dctx, p.Issuer)
	if err != nil {
		return nil, err
	}
	secret, err := p.ClientSecret()
	if err != nil {
		return nil, err
	}
	c := &providerClient{
		oauth: &oauth2.Config{ClientID: p.ClientID, ClientSecret: secret, Endpoint: op.Endpoint(),
			RedirectURL: RedirectURL(h.PublicURL, p.Name), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}},
		verifier: op.Verifier(&oidc.Config{ClientID: p.ClientID}),
	}
	if h.clients == nil {
		h.clients = map[string]*providerClient{}
	}
	h.clients[p.Name] = c
	return c, nil
}

func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	p, ok := h.provider(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, err := h.client(r.Context(), p)
	if err != nil {
		log.Printf("sso: provider %s unavailable: %s", p.Name, logging.Sanitize(err.Error()))
		http.Error(w, "The sign-in provider is unavailable; try again later or use the local login.", http.StatusBadGateway)
		return
	}
	state, f, err := h.Flows.Put(r.Context(), p.Name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: BindCookieName, Value: state, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(flowLifetime / time.Second)})
	http.Redirect(w, r, c.oauth.AuthCodeURL(state, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier)), http.StatusFound)
}

func (h *Handlers) refuse(w http.ResponseWriter, p, subject, reason string) {
	log.Printf("sso: login refused via %s (subject %q): %s", p, logging.Sanitize(subject), logging.Sanitize(reason))
	http.SetCookie(w, &http.Cookie{Name: BindCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "Sign-in refused. / Acesso recusado.", http.StatusForbidden)
}

func (h *Handlers) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, ok := h.provider(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	bind, err := r.Cookie(BindCookieName)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(bind.Value), []byte(state)) != 1 {
		h.refuse(w, p.Name, "", "state does not match this browser")
		return
	}
	f, ok, err := h.Flows.Take(ctx, state, p.Name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		h.refuse(w, p.Name, "", "unknown, expired or reused state")
		return
	}
	if e := q.Get("error"); e != "" {
		h.refuse(w, p.Name, "", "provider returned error: "+e)
		return
	}
	c, err := h.client(ctx, p)
	if err != nil {
		log.Printf("sso: provider %s unavailable: %s", p.Name, logging.Sanitize(err.Error()))
		http.Error(w, "The sign-in provider is unavailable.", http.StatusBadGateway)
		return
	}
	pctx, cancel := context.WithTimeout(h.ctx(ctx), discoveryTimeout)
	defer cancel()
	tok, err := c.oauth.Exchange(pctx, q.Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		h.refuse(w, p.Name, "", "code exchange failed: "+err.Error())
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := c.verifier.Verify(pctx, raw)
	if err != nil {
		h.refuse(w, p.Name, "", "ID token rejected: "+err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(f.Nonce)) != 1 {
		h.refuse(w, p.Name, idt.Subject, "nonce mismatch")
		return
	}
	var claims Claims
	if err := idt.Claims(&claims); err != nil {
		h.refuse(w, p.Name, idt.Subject, "unreadable claims")
		return
	}
	if ok, reason := Authorize(p, claims); !ok {
		h.refuse(w, p.Name, idt.Subject, reason)
		return
	}

	if old, err := r.Cookie(session.CookieName); err == nil && old.Value != "" {
		h.Sessions.Delete(ctx, old.Value)
	}
	id, _, err := h.Sessions.CreateWithLifetime(ctx, h.SessionLifetime)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	who := claims.Email
	if who == "" {
		who = idt.Subject
	}
	log.Printf("sso: login success via %s (%s, from %s)", p.Name, logging.Sanitize(who), logging.Sanitize(r.RemoteAddr))
	http.SetCookie(w, &http.Cookie{Name: BindCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	http.SetCookie(w, session.Cookie(id))
	// A same-site navigation from this page, not an HTTP redirect: the
	// session cookie is SameSite=Strict, and a redirect still counts as
	// part of the cross-site navigation coming from the provider.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	continuePage.Execute(w, nil)
}

var continuePage = template.Must(template.New("c").Parse(`<!DOCTYPE html>
<html><head><meta http-equiv="refresh" content="0;url=/"><title>Expiry Radar</title></head>
<body><p>Signed in. <a href="/">Continue / Continuar</a></p></body></html>`))
