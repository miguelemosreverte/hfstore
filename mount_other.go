//go:build !linux

package main

import (
	"context"
	"errors"
)

// Macs read the backup with ls and get; the mount is Linux only.
func (s *Store) Serve(ctx context.Context) error {
	return errors.New("serve is only available on Linux")
}
