// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build debug

package stun

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// assertIntegrityMismatch verifies that err is the debug-build integrity
// mismatch error (*IntegrityErr), which replaces the production sentinel.
func assertIntegrityMismatch(t *testing.T, err error) {
	t.Helper()
	var debugErr *IntegrityErr
	assert.True(t, errors.As(err, &debugErr), "expected integrity mismatch, got %v", err)
}
