package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

const scopeCloudPlatform = "https://www.googleapis.com/auth/cloud-platform"

type endpoints struct {
	metadata string // http://metadata.google.internal
	api      func(service string) string
	// allowed reports whether a token endpoint from a credential file may
	// receive the subject token (tests allow the fake).
	allowed func(u *url.URL, host string) bool
}

func defaultEndpoints() endpoints {
	return endpoints{
		metadata: "http://metadata.google.internal",
		api:      func(s string) string { return "https://" + s + ".googleapis.com" },
		allowed:  func(u *url.URL, host string) bool { return u.Scheme == "https" && u.User == nil && u.Host == host },
	}
}

type token struct {
	value   string
	expires time.Time
}

type tokenSource struct {
	fetch func(ctx context.Context) (token, error)
	mu    sync.Mutex
	tok   token
}

func (t *tokenSource) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tok.value != "" && time.Until(t.tok.expires) > 5*time.Minute {
		return t.tok.value, nil
	}
	tok, err := t.fetch(ctx)
	if err != nil {
		return "", err
	}
	t.tok = tok
	return tok.value, nil
}

func readBody(resp *http.Response, what string) ([]byte, error) {
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode/100 != 2 {
		msg := []rune(strings.TrimSpace(string(data)))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, &apiError{what, resp.StatusCode, logging.Sanitize(string(msg))}
	}
	return data, nil
}

type apiError struct {
	what   string
	status int
	msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("%s: HTTP %d %s", e.what, e.status, e.msg) }

// disabled: the API is not enabled in that project (nothing of that
// kind can exist there).
func (e *apiError) disabled() bool {
	return e.status == 403 && (strings.Contains(e.msg, "SERVICE_DISABLED") || strings.Contains(e.msg, "accessNotConfigured") || strings.Contains(e.msg, "has not been used in project"))
}

func (e *apiError) retryable() bool {
	return e.status == 429 || e.status >= 500
}

var retryWait = time.Second

// do sends a request built by build (rebuilt per attempt) and retries
// 429/5xx/network errors twice. Redirects are never followed.
func do(ctx context.Context, hc *http.Client, what string, build func() (*http.Request, error)) ([]byte, error) {
	var last error
	for i := 0; i < 3; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryWait * time.Duration(i)):
			}
		}
		req, err := build()
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			last = err
			continue
		}
		data, err := readBody(resp, what)
		var ae *apiError
		if err != nil && errors.As(err, &ae) && ae.retryable() {
			last = err
			continue
		}
		return data, err
	}
	return nil, last
}

func noProxy(hc *http.Client) *http.Client {
	c := *hc
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		tr = http.DefaultTransport.(*http.Transport)
	}
	tr = tr.Clone()
	tr.Proxy = nil
	c.Transport = tr
	return &c
}

func newTokenSource(cfg Config, hc *http.Client, ep endpoints) (*tokenSource, error) {
	switch cfg.Auth {
	case "metadata":
		local := noProxy(hc)
		return &tokenSource{fetch: func(ctx context.Context) (token, error) { return metadataToken(ctx, local, ep) }}, nil
	case "external_account":
		return &tokenSource{fetch: func(ctx context.Context) (token, error) { return externalAccount(ctx, hc, ep, cfg.CredentialFile) }}, nil
	}
	return nil, fmt.Errorf("gcp: unknown auth %q", cfg.Auth)
}

// metadataToken: Compute Engine, GKE Workload Identity, Cloud Run.
func metadataToken(ctx context.Context, hc *http.Client, ep endpoints) (token, error) {
	data, err := do(ctx, hc, "metadata token", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.metadata+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
		if err == nil {
			req.Header.Set("Metadata-Flavor", "Google")
		}
		return req, err
	})
	if err != nil {
		return token{}, fmt.Errorf("gcp: %w", err)
	}
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.Unmarshal(data, &r) != nil || r.AccessToken == "" {
		return token{}, errors.New("gcp: metadata server returned no token")
	}
	return token{r.AccessToken, time.Now().Add(time.Duration(r.ExpiresIn) * time.Second)}, nil
}

type externalConfig struct {
	Type                           string `json:"type"`
	Audience                       string `json:"audience"`
	SubjectTokenType               string `json:"subject_token_type"`
	TokenURL                       string `json:"token_url"`
	ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	CredentialSource               struct {
		File   string `json:"file"`
		URL    string `json:"url"`
		Format struct {
			Type                  string `json:"type"`
			SubjectTokenFieldName string `json:"subject_token_field_name"`
		} `json:"format"`
	} `json:"credential_source"`
}

// externalAccount: workload identity federation from a Google
// "external_account" file with a file-sourced subject token: STS token
// exchange, then optional service account impersonation. The token
// endpoints must be Google's (a crafted file must not send the subject
// token or the federated token elsewhere).
func externalAccount(ctx context.Context, hc *http.Client, ep endpoints, file string) (token, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return token{}, fmt.Errorf("gcp: credential_file: %w", err)
	}
	var cfg externalConfig
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.Type != "external_account" {
		return token{}, errors.New("gcp: credential_file is not an external_account configuration")
	}
	if cfg.CredentialSource.File == "" {
		return token{}, errors.New("gcp: only file-sourced subject tokens are supported (credential_source.file)")
	}
	tokURL, err := url.Parse(cfg.TokenURL)
	if err != nil || !ep.allowed(tokURL, "sts.googleapis.com") {
		return token{}, errors.New("gcp: token_url must be https://sts.googleapis.com")
	}
	subj, err := os.ReadFile(cfg.CredentialSource.File) // rotated by the platform: read every time
	if err != nil {
		return token{}, fmt.Errorf("gcp: subject token: %w", err)
	}
	subject := strings.TrimSpace(string(subj))
	if cfg.CredentialSource.Format.Type == "json" {
		var m map[string]any
		json.Unmarshal(subj, &m)
		s, _ := m[cfg.CredentialSource.Format.SubjectTokenFieldName].(string)
		subject = s
	}
	if subject == "" {
		return token{}, errors.New("gcp: empty subject token")
	}
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {cfg.Audience},
		"scope":                {scopeCloudPlatform},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {subject},
		"subject_token_type":   {cfg.SubjectTokenType},
	}
	data, err := do(ctx, hc, "gcp STS token exchange", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokURL.String(), strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		return req, err
	})
	if err != nil {
		return token{}, err
	}
	var fed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.Unmarshal(data, &fed) != nil || fed.AccessToken == "" {
		return token{}, errors.New("gcp: STS returned no token")
	}
	if cfg.ServiceAccountImpersonationURL == "" {
		return token{fed.AccessToken, time.Now().Add(time.Duration(fed.ExpiresIn) * time.Second)}, nil
	}
	impURL, err := url.Parse(cfg.ServiceAccountImpersonationURL)
	if err != nil || !ep.allowed(impURL, "iamcredentials.googleapis.com") || !strings.HasSuffix(impURL.Path, ":generateAccessToken") {
		return token{}, errors.New("gcp: service_account_impersonation_url must be https://iamcredentials.googleapis.com/...:generateAccessToken")
	}
	body := `{"scope":["` + scopeCloudPlatform + `"],"lifetime":"3600s"}`
	data, err = do(ctx, hc, "gcp service account impersonation", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, impURL.String(), strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+fed.AccessToken)
		}
		return req, err
	})
	if err != nil {
		return token{}, err
	}
	var imp struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if json.Unmarshal(data, &imp) != nil || imp.AccessToken == "" {
		return token{}, errors.New("gcp: impersonation returned no token")
	}
	exp, perr := time.Parse(time.RFC3339, imp.ExpireTime)
	if perr != nil {
		exp = time.Now().Add(time.Hour)
	}
	return token{imp.AccessToken, exp}, nil
}
