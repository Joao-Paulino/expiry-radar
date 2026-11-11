package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// shortAccessor identifies a token or secret ID without exposing the
// full accessor, which (with the right policy) can revoke it.
func shortAccessor(a string) string {
	if len(a) > 8 {
		return a[:8]
	}
	return a
}

// forEach runs fn for every item, maxParallel at a time, and returns
// the first error.
func forEach(items []string, fn func(string) error) error {
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, maxParallel)
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it string) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(it); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(it)
	}
	wg.Wait()
	return firstErr
}

// checkTokens reports tokens that expire, looked up by accessor (the
// token itself is never returned). Tokens without expiry, the agent's
// own token and tokens created with a TTL below token_min_ttl_hours
// (short-lived login tokens) are skipped.
func (c *Checker) checkTokens(ctx context.Context, s *session, source string) ([]checker.ExpiryRecord, error) {
	var self struct {
		Data struct {
			Accessor string `json:"accessor"`
		} `json:"data"`
	}
	if err := s.call(ctx, http.MethodGet, "auth/token/lookup-self", nil, &self); err != nil {
		return nil, err
	}
	accessors, err := s.list(ctx, "auth/token/accessors")
	if err != nil && !isEmptyList(err) {
		return nil, err
	}
	minTTL := c.cfg.TokenMinTTLHours
	if minTTL == 0 {
		minTTL = 24
	}
	var (
		mu      sync.Mutex
		records []checker.ExpiryRecord
	)
	err = forEach(accessors, func(acc string) error {
		if acc == self.Data.Accessor {
			return nil
		}
		var r struct {
			Data struct {
				DisplayName string   `json:"display_name"`
				CreationTTL int64    `json:"creation_ttl"`
				ExpireTime  *string  `json:"expire_time"`
				Policies    []string `json:"policies"`
				Renewable   bool     `json:"renewable"`
			} `json:"data"`
		}
		if err := s.call(ctx, http.MethodPost, "auth/token/lookup-accessor", map[string]string{"accessor": acc}, &r); err != nil {
			var e *apiError
			if errors.As(err, &e) && e.status == http.StatusBadRequest {
				return nil // expired or revoked since the list
			}
			return fmt.Errorf("token %s: %w", shortAccessor(acc), err)
		}
		d := r.Data
		if d.ExpireTime == nil || *d.ExpireTime == "" || d.CreationTTL < int64(minTTL)*3600 {
			return nil
		}
		exp, err := time.Parse(time.RFC3339, *d.ExpireTime)
		if err != nil {
			return fmt.Errorf("token %s: expire_time: %w", shortAccessor(acc), err)
		}
		name := d.DisplayName
		if name == "" {
			name = "token"
		}
		mu.Lock()
		records = append(records, checker.ExpiryRecord{Source: source, Name: name + " · " + shortAccessor(acc), Kind: "token", ExpiresAt: exp,
			Metadata: map[string]string{"policies": strings.Join(d.Policies, ","), "renewable": fmt.Sprint(d.Renewable)}})
		mu.Unlock()
		return nil
	})
	return records, err
}

// checkSecretIDs reports AppRole secret IDs that expire, looked up by
// accessor (the secret ID itself is never returned).
func (c *Checker) checkSecretIDs(ctx context.Context, s *session, source, mount string) ([]checker.ExpiryRecord, error) {
	roles, err := s.list(ctx, "auth/"+mount+"/role")
	if err != nil {
		if isEmptyList(err) {
			return nil, nil
		}
		return nil, err
	}
	var (
		mu      sync.Mutex
		records []checker.ExpiryRecord
		errs    []error
	)
	for _, role := range roles {
		base := "auth/" + mount + "/role/" + url.PathEscape(role)
		accessors, err := s.list(ctx, base+"/secret-id")
		if err != nil {
			if !isEmptyList(err) {
				errs = append(errs, fmt.Errorf("role %s: %w", role, err))
			}
			continue
		}
		err = forEach(accessors, func(acc string) error {
			var r struct {
				Data struct {
					TTL        int64  `json:"secret_id_ttl"`
					Expiration string `json:"expiration_time"`
				} `json:"data"`
			}
			if err := s.call(ctx, http.MethodPost, base+"/secret-id-accessor/lookup", map[string]string{"secret_id_accessor": acc}, &r); err != nil {
				var e *apiError
				if errors.As(err, &e) && e.status == http.StatusNotFound {
					return nil // expired and removed since the list
				}
				return fmt.Errorf("role %s secret-id %s: %w", role, shortAccessor(acc), err)
			}
			if r.Data.TTL == 0 {
				return nil // never expires
			}
			exp, err := time.Parse(time.RFC3339, r.Data.Expiration)
			if err != nil || exp.Year() < 2 {
				return nil
			}
			mu.Lock()
			records = append(records, checker.ExpiryRecord{Source: source, Name: role + " secret-id · " + shortAccessor(acc), Kind: "secret", ExpiresAt: exp,
				Metadata: map[string]string{"role": role, "mount": mount}})
			mu.Unlock()
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return records, errors.Join(errs...)
}
