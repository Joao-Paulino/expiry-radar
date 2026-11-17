//go:build !windows

package local

import (
	"context"
	"errors"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

type storeChecker struct{ stores []string }

// Name is the checker name reported to the collector.
func (s *storeChecker) Name() string { return "windows-certstore" }

// Kind is the record kind this checker produces.
func (s *storeChecker) Kind() string { return "certificate" }

// Check always fails: certificate stores exist only on Windows, and
// Checkers never creates this checker elsewhere.
func (s *storeChecker) Check(context.Context) ([]checker.ExpiryRecord, error) {
	return nil, errors.New("windows certificate stores exist only on Windows")
}
