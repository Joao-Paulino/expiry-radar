//go:build !windows

package local

import (
	"context"
	"errors"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

type storeChecker struct{ stores []string }

func (s *storeChecker) Name() string { return "windows-certstore" }
func (s *storeChecker) Kind() string { return "certificate" }
func (s *storeChecker) Check(context.Context) ([]checker.ExpiryRecord, error) {
	return nil, errors.New("windows certificate stores exist only on Windows")
}
