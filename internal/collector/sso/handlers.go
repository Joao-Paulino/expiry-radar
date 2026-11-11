// Package sso implements dashboard login through OpenID Connect
// providers (Microsoft Entra ID, Google, ...).
package sso

import (
	"context"
	"crypto/subtle"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
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

	// MaxPendingFlows caps unfinished logins across all providers
	// (default 10000), so anonymous requests cannot fill the database.
	MaxPendingFlows int

	mu       sync.Mutex
	clients  map[string]*providerClient // discovered lazily, so an IdP outage never blocks startup
	locks    map[string]*sync.Mutex     // one per provider: a slow provider only delays itself
	failedAt map[string]time.Time       // recent discovery failures, retried after failureBackoff
	starts   *admin.Throttle
}

// LoginStartsPerAddress is how many SSO logins one client address may
// start per 10 minutes.
const LoginStartsPerAddress = 20

const failureBackoff = 30 * time.Second

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

// client discovers the provider on first use and caches only success.
// Discovery runs under a per-provider lock, so a slow or dead provider
// never delays another one, and a recent failure is returned at once
// for failureBackoff instead of hammering the provider.
func (h *Handlers) client(ctx context.Context, p ProviderConfig) (*providerClient, error) {
	h.mu.Lock()
	if c, ok := h.clients[p.Name]; ok {
		h.mu.Unlock()
		return c, nil
	}
	if t, ok := h.failedAt[p.Name]; ok && time.Since(t) < failureBackoff {
		h.mu.Unlock()
		return nil, errors.New("provider discovery failed recently; retrying shortly")
	}
	if h.locks == nil {
		h.locks = map[string]*sync.Mutex{}
	}
	l, ok := h.locks[p.Name]
	if !ok {
		l = &sync.Mutex{}
		h.locks[p.Name] = l
	}
	h.mu.Unlock()

	l.Lock()
	defer l.Unlock()
	h.mu.Lock()
	if c, ok := h.clients[p.Name]; ok { // another request finished discovery meanwhile
		h.mu.Unlock()
		return c, nil
	}
	h.mu.Unlock()

	c, err := h.discover(ctx, p)
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		if h.failedAt == nil {
			h.failedAt = map[string]time.Time{}
		}
		h.failedAt[p.Name] = time.Now()
		return nil, err
	}
	if h.clients == nil {
		h.clients = map[string]*providerClient{}
	}
	delete(h.failedAt, p.Name)
	h.clients[p.Name] = c
	return c, nil
}

func (h *Handlers) discover(ctx context.Context, p ProviderConfig) (*providerClient, error) {
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
	return &providerClient{
		oauth: &oauth2.Config{ClientID: p.ClientID, ClientSecret: secret, Endpoint: op.Endpoint(),
			RedirectURL: RedirectURL(h.PublicURL, p.Name), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}},
		verifier: op.Verifier(&oidc.Config{ClientID: p.ClientID}),
	}, nil
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	p, ok := h.provider(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	addr := clientAddress(r)
	h.mu.Lock()
	if h.starts == nil {
		h.starts = admin.NewThrottle(LoginStartsPerAddress, 10*time.Minute)
	}
	starts := h.starts
	h.mu.Unlock()
	if starts.Blocked(addr, time.Now()) {
		log.Printf("sso: login starts throttled (from %s)", logging.Sanitize(addr))
		http.Error(w, "Too many sign-in attempts; try again later.", http.StatusTooManyRequests)
		return
	}
	starts.Fail(addr, time.Now()) // every start counts
	max := h.MaxPendingFlows
	if max <= 0 {
		max = 10000
	}
	if n, err := h.Flows.Pending(r.Context()); err != nil || n >= max {
		log.Printf("sso: too many pending logins (%d), refusing new ones", n)
		http.Error(w, "Sign-in is temporarily unavailable; try again later.", http.StatusServiceUnavailable)
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
