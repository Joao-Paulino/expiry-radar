// Package certwatch reloads the collector's own TLS certificate and
// key from disk when they change on an external renewal (for
// example, certbot renewing a Let's Encrypt certificate), so the
// collector picks up the new certificate without a restart. It never
// executes anything: it only reads the two files it is told to
// serve.
package certwatch

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Watcher serves the current certificate/key pair loaded from
// certFile/keyFile, and can Reload them when either file's
// modification time changes. It is safe for concurrent use.
type Watcher struct {
	certFile, keyFile string

	mu      sync.Mutex
	certMod time.Time
	keyMod  time.Time

	cur atomic.Pointer[tls.Certificate]
}

// New loads the certificate/key pair at certFile/keyFile and returns
// a Watcher serving it. It fails the same way tls.LoadX509KeyPair
// does if the files are missing or invalid.
func New(certFile, keyFile string) (*Watcher, error) {
	w := &Watcher{certFile: certFile, keyFile: keyFile}
	cert, certMod, keyMod, err := load(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	w.cur.Store(cert)
	w.certMod, w.keyMod = certMod, keyMod
	return w, nil
}

func load(certFile, keyFile string) (*tls.Certificate, time.Time, time.Time, error) {
	certInfo, err := os.Stat(certFile)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("certwatch: stat cert: %w", err)
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("certwatch: stat key: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("certwatch: load certificate: %w", err)
	}
	return &cert, certInfo.ModTime(), keyInfo.ModTime(), nil
}

// GetCertificate implements the signature tls.Config.GetCertificate
// expects: it always returns the most recently loaded certificate,
// regardless of the ClientHelloInfo (the collector serves one name).
func (w *Watcher) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := w.cur.Load()
	if cert == nil {
		return nil, fmt.Errorf("certwatch: no certificate loaded")
	}
	return cert, nil
}

// Reload re-reads certFile/keyFile if either's modification time has
// changed since the last successful load, and swaps in the new
// certificate. It reports whether a reload happened.
//
// On a bad new pair (for example a renewal that has written a fresh
// certificate file but not yet its key), it keeps serving the
// previous, still-valid certificate and returns the error: one
// renewal mistake must not take the collector's dashboard or /ingest
// offline.
func (w *Watcher) Reload() (bool, error) {
	certInfo, err := os.Stat(w.certFile)
	if err != nil {
		return false, fmt.Errorf("certwatch: stat cert: %w", err)
	}
	keyInfo, err := os.Stat(w.keyFile)
	if err != nil {
		return false, fmt.Errorf("certwatch: stat key: %w", err)
	}

	w.mu.Lock()
	changed := !certInfo.ModTime().Equal(w.certMod) || !keyInfo.ModTime().Equal(w.keyMod)
	w.mu.Unlock()
	if !changed {
		return false, nil
	}

	cert, certMod, keyMod, err := load(w.certFile, w.keyFile)
	if err != nil {
		return false, err
	}

	w.mu.Lock()
	w.certMod, w.keyMod = certMod, keyMod
	w.mu.Unlock()
	w.cur.Store(cert)
	return true, nil
}

// Watch calls Reload every interval until done is closed, reporting
// reloads and errors through logf (for example log.Printf). A nil
// logf discards them.
func (w *Watcher) Watch(interval time.Duration, done <-chan struct{}, logf func(format string, args ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			reloaded, err := w.Reload()
			if err != nil {
				logf("certwatch: reload failed, keeping the previous certificate: %s", err)
				continue
			}
			if reloaded {
				logf("certwatch: reloaded TLS certificate from %s", w.certFile)
			}
		case <-done:
			return
		}
	}
}
