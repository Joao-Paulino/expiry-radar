package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"time"
)

const flowLifetime = 10 * time.Minute

// Flow is the secret state of one pending SSO login.
type Flow struct {
	Nonce    string
	Verifier string // PKCE code verifier
}

// FlowStore keeps pending SSO logins server-side (state hashed), each
// valid for 10 minutes and usable once.
type FlowStore struct {
	DB  *sql.DB
	Now func() time.Time
}

func random32() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashState(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// Put starts a flow for provider and returns its state.
func (s *FlowStore) Put(ctx context.Context, provider string) (string, Flow, error) {
	var vals [3]string
	for i := range vals {
		v, err := random32()
		if err != nil {
			return "", Flow{}, err
		}
		vals[i] = v
	}
	state, f := vals[0], Flow{Nonce: vals[1], Verifier: vals[2]}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sso_flows (state_hash, provider, nonce, verifier, created_at) VALUES (?, ?, ?, ?, ?)`,
		hashState(state), provider, f.Nonce, f.Verifier, s.Now().Unix())
	return state, f, err
}

// Take consumes the flow for state. It succeeds only once, only for the
// provider that started it, and only within 10 minutes.
func (s *FlowStore) Take(ctx context.Context, state, provider string) (Flow, bool, error) {
	var f Flow
	var p string
	var created int64
	err := s.DB.QueryRowContext(ctx, `DELETE FROM sso_flows WHERE state_hash = ? RETURNING provider, nonce, verifier, created_at`,
		hashState(state)).Scan(&p, &f.Nonce, &f.Verifier, &created)
	if err == sql.ErrNoRows {
		return Flow{}, false, nil
	}
	if err != nil {
		return Flow{}, false, err
	}
	if p != provider || s.Now().Sub(time.Unix(created, 0)) > flowLifetime {
		return Flow{}, false, nil
	}
	return f, true, nil
}

// DeleteExpired removes abandoned flows and returns how many.
func (s *FlowStore) DeleteExpired(ctx context.Context) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM sso_flows WHERE created_at < ?`, s.Now().Add(-flowLifetime).Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
