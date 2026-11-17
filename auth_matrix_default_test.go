// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !debug

package stun

import "errors"

// isIntegrityFailure reports whether err means an integrity check failed.
func isIntegrityFailure(err error) bool {
	return errors.Is(err, ErrIntegrityMismatch)
}

// isFingerprintFailure reports whether err means a fingerprint check failed.
func isFingerprintFailure(err error) bool {
	return errors.Is(err, ErrFingerprintMismatch)
}
