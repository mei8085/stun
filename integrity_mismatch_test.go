// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !debug

package stun

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// assertIntegrityMismatch verifies that err is the production integrity
// mismatch sentinel.
func assertIntegrityMismatch(t *testing.T, err error) {
	t.Helper()
	assert.True(t, errors.Is(err, ErrIntegrityMismatch), "expected integrity mismatch, got %v", err)
}
