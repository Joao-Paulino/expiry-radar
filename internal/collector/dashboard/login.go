package dashboard

import (
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/sso"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// PerAddressLimit is how many failed logins one client address may make
// per 15 minutes before its attempts are refused without being checked.
const PerAddressLimit = 5

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type loginView struct {
	Error   string
	Buttons []sso.Button
	Theme   string
}

// renderLogin writes the login page with an optional error message.
func renderLogin(w http.ResponseWriter, msg string, buttons []sso.Button, theme string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, "login.html", loginView{Error: msg, Buttons: buttons, Theme: themeOrAuto(theme)}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// genericLoginError is shown for every failure, so the page never
// reveals whether the password, the code, the lockout or the setup
// was the problem.
const genericLoginError = "Invalid credentials. / Credenciais inválidas."

// LoginHandlers returns the login page (GET), the login form handler
// (POST) and the logout handler. get and post are public; logout must
// be wrapped in session.Middleware so it is CSRF-protected.
// buttons are the SSO providers shown on the login page. revokeAll
// ends every session and, like logout, must sit behind session.Middleware.
func LoginHandlers(auth *admin.Authenticator, sessions *session.Store, buttons []sso.Button, opts ...Options) (get, post, logout, revokeAll http.Handler) {
	theme := optionsOf(opts).Theme
	render := func(w http.ResponseWriter, msg string) { renderLogin(w, msg, buttons, theme) }

	throttle := admin.NewThrottle(PerAddressLimit, 15*time.Minute)

	get = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { render(w, "") })

	post = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		addr := clientAddress(r)
		if throttle.Blocked(addr, time.Now()) {
			log.Printf("dashboard: login throttled (from %s)", logging.Sanitize(addr))
			render(w, genericLoginError)
			return
		}
		if err := r.ParseForm(); err != nil {
			render(w, genericLoginError)
			return
		}
		res, err := auth.Authenticate(ctx, r.PostFormValue("password"), r.PostFormValue("code"))
		if errors.Is(err, admin.ErrInvalidCredentials) || errors.Is(err, admin.ErrLocked) {
			throttle.Fail(addr, time.Now())
		}
		switch {
		case err == nil:
			throttle.Reset(addr)
		case errors.Is(err, admin.ErrLocked):
			log.Printf("dashboard: account locked (from %s)", logging.Sanitize(r.RemoteAddr))
			render(w, genericLoginError)
			return
		case errors.Is(err, admin.ErrNotConfigured):
			log.Printf("dashboard: login failed, administrator not configured (from %s)", logging.Sanitize(r.RemoteAddr))
			render(w, genericLoginError)
			return
		case errors.Is(err, admin.ErrInvalidCredentials):
			log.Printf("dashboard: login failed (from %s)", logging.Sanitize(r.RemoteAddr))
			render(w, genericLoginError)
			return
		default:
			log.Printf("dashboard: login error: %s", logging.Sanitize(err.Error()))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Never reuse a session id that existed before login.
		if c, err := r.Cookie(session.CookieName); err == nil && c.Value != "" {
			sessions.Delete(ctx, c.Value)
		}
		id, _, err := sessions.Create(ctx)
		if err != nil {
			log.Printf("dashboard: session create error: %s", logging.Sanitize(err.Error()))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if res.RecoveryCode {
			log.Printf("dashboard: login success with a recovery code, %d left (from %s)", res.RecoveryCodesLeft, logging.Sanitize(r.RemoteAddr))
		} else {
			log.Printf("dashboard: login success (from %s)", logging.Sanitize(r.RemoteAddr))
		}
		http.SetCookie(w, session.Cookie(id))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	logout = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(session.CookieName); err == nil && c.Value != "" {
			if err := sessions.Delete(r.Context(), c.Value); err != nil {
				log.Printf("dashboard: logout error: %s", logging.Sanitize(err.Error()))
			}
		}
		log.Printf("dashboard: logout (from %s)", logging.Sanitize(r.RemoteAddr))
		http.SetCookie(w, session.ExpiredCookie())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	revokeAll = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := sessions.DeleteAll(r.Context()); err != nil {
			log.Printf("dashboard: revoke-all error: %s", logging.Sanitize(err.Error()))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("dashboard: all sessions signed out (from %s)", logging.Sanitize(r.RemoteAddr))
		http.SetCookie(w, session.ExpiredCookie())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	return get, post, logout, revokeAll
}
