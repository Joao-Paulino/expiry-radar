// Package session implements the dashboard's server-side sessions,
// session cookie, CSRF tokens, and the middleware that accepts either a
// session or an admin bearer token.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"
)

const (
	// CookieName uses the __Host- prefix: browsers only accept it with
	// Secure, Path=/ and no Domain, so subdomains cannot overwrite it.
	CookieName = "__Host-er_session"

	idleTimeout      = 30 * time.Minute
	absoluteLifetime = 8 * time.Hour
)

// Session is the server-side state of one logged-in browser.
type Session struct {
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// Store keeps sessions in SQLite, indexed by the SHA-256 of their id.
type Store struct {
	DB  *sql.DB
	Now func() time.Time
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// Create starts a new session and returns its id (for the cookie).
func (s *Store) Create(ctx context.Context) (string, Session, error) {
	id, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	now := s.Now()
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO admin_sessions (id_hash, csrf_token, created_at, last_seen_at)
		VALUES (?, ?, ?, ?)`, hashID(id), csrf, now.Unix(), now.Unix()); err != nil {
		return "", Session{}, err
	}
	return id, Session{CSRFToken: csrf, CreatedAt: now, LastSeenAt: now}, nil
}

// Lookup returns the session for id if it exists and has not passed
// its idle or absolute timeout; it refreshes the activity time and
// deletes the session when expired.
func (s *Store) Lookup(ctx context.Context, id string) (Session, bool, error) {
	if id == "" {
		return Session{}, false, nil
	}
	h := hashID(id)
	var sess Session
	var created, lastSeen int64
	err := s.DB.QueryRowContext(ctx, `SELECT csrf_token, created_at, last_seen_at FROM admin_sessions WHERE id_hash = ?`, h).
		Scan(&sess.CSRFToken, &created, &lastSeen)
	if err == sql.ErrNoRows {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	sess.CreatedAt, sess.LastSeenAt = time.Unix(created, 0), time.Unix(lastSeen, 0)
	now := s.Now()
	if now.Sub(sess.LastSeenAt) > idleTimeout || now.Sub(sess.CreatedAt) > absoluteLifetime {
		_, err := s.DB.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id_hash = ?`, h)
		return Session{}, false, err
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE admin_sessions SET last_seen_at = ? WHERE id_hash = ?`, now.Unix(), h); err != nil {
		return Session{}, false, err
	}
	sess.LastSeenAt = now
	return sess, true, nil
}

// Delete ends one session.
func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id_hash = ?`, hashID(id))
	return err
}

// DeleteAll ends every session (password or TOTP change).
func (s *Store) DeleteAll(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM admin_sessions`)
	return err
}

// Cookie returns the session cookie for id.
func Cookie(id string) *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// ExpiredCookie returns a cookie that removes the session cookie.
func ExpiredCookie() *http.Cookie {
	c := Cookie("")
	c.MaxAge = -1
	return c
}
