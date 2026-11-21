// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"encoding/base64"
	"errors"
)

// STUN Security Feature bits, as defined by RFC 8489 Section 18.1.
//
// The 24-bit STUN Security Feature set is encoded as three bytes with bit 0
// being the most significant bit of the first byte and bit 23 the least
// significant bit of the third byte.
const (
	// SecurityFeaturePasswordAlgorithms is bit 0 of the STUN Security
	// Feature set. It signals that the peer supports the
	// PASSWORD-ALGORITHMS / PASSWORD-ALGORITHM negotiation.
	SecurityFeaturePasswordAlgorithms SecurityFeature = 0
	// SecurityFeatureUsernameAnonymity is bit 1 of the STUN Security
	// Feature set. It signals that the peer supports the USERHASH
	// attribute.
	SecurityFeatureUsernameAnonymity SecurityFeature = 1
)

// SecurityFeature is a bit number (0..23) of the 24-bit STUN Security
// Feature set defined by RFC 8489 Section 18.1.
type SecurityFeature uint8

// mask returns the wire byte and the bit mask representing the feature bit.
func (f SecurityFeature) mask() (index, mask byte) {
	return byte(f) / 8, byte(1) << (7 - byte(f)%8)
}

// SecurityFeatures is a 24-bit STUN Security Feature set.
type SecurityFeatures [3]byte

// Set sets feature bit f.
func (s *SecurityFeatures) Set(f SecurityFeature) {
	index, mask := f.mask()
	s[index] |= mask
}

// Has reports whether feature bit f is set.
func (s SecurityFeatures) Has(f SecurityFeature) bool {
	index, mask := f.mask()

	return s[index]&mask != 0
}

// nonceCookiePrefix is the fixed 9-character string that starts every
// RFC 8489 nonce cookie.
const nonceCookiePrefix = "obMatJos2"

// nonceCookieLen is the length of the nonce cookie: the 9-character
// "obMatJos2" prefix followed by the 4-character base64 encoding of the
// 24-bit STUN Security Feature set.
const nonceCookieLen = len(nonceCookiePrefix) + 4

// ErrInvalidNonceCookie means that a NONCE attribute value was expected to
// start with the RFC 8489 nonce cookie, but does not, or its encoded
// security features cannot be parsed.
var ErrInvalidNonceCookie = errors.New("invalid nonce cookie")

// EncodeNonceCookie returns the RFC 8489 nonce cookie (the 13-character
// "obMatJos2" prefix followed by the base64-encoded security features) that
// MUST be prepended to a NONCE attribute value when the matching security
// features are used.
//
// RFC 8489 Section 9.2.
func EncodeNonceCookie(features SecurityFeatures) string {
	return nonceCookiePrefix + base64.StdEncoding.EncodeToString(features[:])
}

// NewNonceWithFeatures returns a NONCE value that starts with the RFC 8489
// nonce cookie advertising features, followed by the opaque nonce material.
func NewNonceWithFeatures(features SecurityFeatures, nonce string) Nonce {
	return Nonce(EncodeNonceCookie(features) + nonce)
}

// ParseNonceCookie checks that nonce starts with the RFC 8489 nonce cookie
// and, on success, returns the STUN Security Feature set it carries.
//
// ErrInvalidNonceCookie is returned if nonce does not contain a valid nonce
// cookie.
func ParseNonceCookie(nonce []byte) (SecurityFeatures, error) {
	if len(nonce) < nonceCookieLen || string(nonce[:len(nonceCookiePrefix)]) != nonceCookiePrefix {
		return SecurityFeatures{}, ErrInvalidNonceCookie
	}
	raw, err := base64.StdEncoding.DecodeString(string(nonce[len(nonceCookiePrefix):nonceCookieLen]))
	if err != nil || len(raw) != 3 {
		return SecurityFeatures{}, ErrInvalidNonceCookie
	}

	return SecurityFeatures{raw[0], raw[1], raw[2]}, nil
}
