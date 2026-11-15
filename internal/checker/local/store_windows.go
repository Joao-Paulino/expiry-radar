//go:build windows

package local

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

type storeChecker struct{ stores []string }

func (s *storeChecker) Name() string { return "windows-certstore" }
func (s *storeChecker) Kind() string { return "certificate" }

// Check enumerates the LocalMachine stores read-only. Source is
// certstore://LocalMachine/<store>.
func (s *storeChecker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	var recs []checker.ExpiryRecord
	var errs []error
	for _, name := range s.stores {
		certs, err := readStore(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("store %s: %w", name, err))
			continue
		}
		recs = append(recs, records("certstore://LocalMachine/"+name, certs)...)
	}
	return recs, errors.Join(errs...)
}

func readStore(name string) ([]*x509.Certificate, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG,
		uintptr(unsafe.Pointer(n)))
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(h, 0)
	var out []*x509.Certificate
	var cc *windows.CertContext
	for {
		cc, err = windows.CertEnumCertificatesInStore(h, cc)
		if err != nil || cc == nil {
			break
		}
		der := make([]byte, cc.Length)
		copy(der, unsafe.Slice(cc.EncodedCert, cc.Length))
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			continue // not something Go understands; the store keeps odd entries
		}
		out = append(out, c)
	}
	return out, nil
}
