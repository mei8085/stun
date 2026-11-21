// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testUsername = "user"
	testRealm    = "example.org"
	testPassword = "TheMatrIX"
)

func newTestChallenge(t *testing.T, algorithms PasswordAlgorithms, useUserhash bool) (*Message, LongTermChallenge) {
	features := SecurityFeatures{}
	if len(algorithms) > 0 {
		features.Set(SecurityFeaturePasswordAlgorithms)
	}
	if useUserhash {
		features.Set(SecurityFeatureUsernameAnonymity)
	}
	nonce := NewNonceWithFeatures(features, "9k954d6OL34oL9FSTvy64sA")
	challenge := LongTermChallenge{
		Realm:       NewRealm(testRealm),
		Nonce:       nonce,
		Algorithms:  algorithms,
		UseUserhash: useUserhash,
	}
	msg := New()
	msg.Type = BindingError
	msg.WriteHeader()
	assert.NoError(t, CodeUnauthorized.AddTo(msg))
	assert.NoError(t, challenge.AddTo(msg))

	return msg, challenge
}

// buildAuthenticatedRequest performs the full client-side retry flow of
// RFC 8489 Section 9.2.5.
func buildAuthenticatedRequest(t *testing.T, challenge *Message) (*Message, LongTermCredentials) {
	t.Helper()
	creds, err := ParseLongTermChallenge(challenge)
	assert.NoError(t, err)
	creds.Username = testUsername
	creds.Password = testPassword

	request := New()
	request.Type = BindingRequest
	request.WriteHeader()
	assert.NoError(t, creds.AddTo(request))

	return request, creds
}

func lookupTestUser(_ Username, _ Realm, _ Userhash) (string, bool) {
	return testPassword, true
}

func TestLongTermAuthSHA256RoundTrip(t *testing.T) {
	advertised := PasswordAlgorithms{{Algorithm: PasswordAlgorithmSHA256}}
	challengeMsg, challenge := newTestChallenge(t, advertised, false)
	request, creds := buildAuthenticatedRequest(t, challengeMsg)

	// The request carries the negotiated algorithm attributes.
	assert.True(t, request.Contains(AttrPasswordAlgorithm))
	assert.True(t, request.Contains(AttrPasswordAlgorithms))
	assert.True(t, request.Contains(AttrMessageIntegritySHA256))
	assert.False(t, request.Contains(AttrMessageIntegrity))

	result, err := AuthenticateLongTermRequest(request, challenge.Algorithms, lookupTestUser)
	assert.NoError(t, err)
	assert.Equal(t, IntegritySHA256, result.Algorithm)
	assert.Equal(t, PasswordAlgorithmSHA256, result.PasswordAlgorithm)
	assert.Equal(t, testUsername, result.Username.String())
	assert.Equal(t, testRealm, result.Realm.String())
	assert.Equal(t, creds.Nonce, result.Nonce)
}

func TestLongTermAuthUserhash(t *testing.T) {
	advertised := PasswordAlgorithms{{Algorithm: PasswordAlgorithmSHA256}}
	challengeMsg, challenge := newTestChallenge(t, advertised, true)
	request, _ := buildAuthenticatedRequest(t, challengeMsg)

	assert.True(t, request.Contains(AttrUserhash))
	assert.False(t, request.Contains(AttrUsername))

	result, err := AuthenticateLongTermRequestWithResolver(request, challenge.Algorithms,
		func(_ Username, realm Realm, userhash Userhash) (string, bool) {
			assert.Equal(t, NewUserhash(testUsername, testRealm), userhash)
			assert.Equal(t, testRealm, realm.String())

			return testPassword, true
		},
		func(userhash Userhash, realm Realm) (string, bool) {
			assert.Equal(t, NewUserhash(testUsername, testRealm), userhash)
			assert.Equal(t, testRealm, realm.String())

			return testUsername, true
		})
	assert.NoError(t, err)
	assert.Equal(t, IntegritySHA256, result.Algorithm)
	assert.Equal(t, NewUserhash(testUsername, testRealm), result.Userhash)

	// Without a resolver, USERHASH messages cannot derive the key and are
	// rejected rather than authenticated against an empty username.
	_, err = AuthenticateLongTermRequest(request, challenge.Algorithms, lookupTestUser)
	assert.ErrorIs(t, err, ErrMissingAuthAttribute)
}

func TestLongTermAuthLegacyMD5NoNegotiation(t *testing.T) {
	// A legacy challenge with no nonce cookie and no PASSWORD-ALGORITHMS.
	challenge := LongTermChallenge{
		Realm: NewRealm(testRealm),
		Nonce: NewNonce("f//499k954d6OL34oL9FSTvy64sA"),
	}
	challengeMsg := New()
	challengeMsg.Type = BindingError
	challengeMsg.WriteHeader()
	assert.NoError(t, CodeUnauthorized.AddTo(challengeMsg))
	assert.NoError(t, challenge.AddTo(challengeMsg))

	request, _ := buildAuthenticatedRequest(t, challengeMsg)
	assert.False(t, request.Contains(AttrPasswordAlgorithm))
	// Legacy flow uses HMAC-SHA1 MESSAGE-INTEGRITY.
	assert.True(t, request.Contains(AttrMessageIntegrity))
	assert.False(t, request.Contains(AttrMessageIntegritySHA256))

	result, err := AuthenticateLongTermRequest(request, nil, lookupTestUser)
	assert.NoError(t, err)
	assert.Equal(t, IntegritySHA1, result.Algorithm)
	assert.Equal(t, PasswordAlgorithmMD5, result.PasswordAlgorithm)
}

func TestLongTermAuthWrongPassword(t *testing.T) {
	advertised := PasswordAlgorithms{{Algorithm: PasswordAlgorithmSHA256}}
	challengeMsg, challenge := newTestChallenge(t, advertised, false)
	request, _ := buildAuthenticatedRequest(t, challengeMsg)

	_, err := AuthenticateLongTermRequest(request, challenge.Algorithms,
		func(_ Username, _ Realm, _ Userhash) (string, bool) { return "different-password", true })
	assertIntegrityMismatch(t, err)

	// Unknown username: same error classification. The sentinel is returned
	// directly for unknown credentials.
	_, err = AuthenticateLongTermRequest(request, challenge.Algorithms,
		func(_ Username, _ Realm, _ Userhash) (string, bool) { return "", false })
	assert.Error(t, err)
}

func TestLongTermAuthMissingIntegrity(t *testing.T) {
	request := New()
	request.Type = BindingRequest
	request.WriteHeader()
	NewUsername(testUsername).AddTo(request) //nolint:errcheck,gosec
	NewRealm(testRealm).AddTo(request)       //nolint:errcheck,gosec

	_, err := AuthenticateLongTermRequest(request, nil, lookupTestUser)
	assert.ErrorIs(t, err, ErrNoIntegrity)
}

func TestLongTermAuthMissingAuthAttributes(t *testing.T) {
	request := New()
	request.Type = BindingRequest
	request.WriteHeader()
	integrity := NewShortTermIntegrity("password")
	assert.NoError(t, integrity.AddTo(request))

	_, err := AuthenticateLongTermRequest(request, nil, lookupTestUser)
	assert.ErrorIs(t, err, ErrMissingAuthAttribute)
}

// TestBidDownStripPasswordAlgorithms verifies that an on-path attacker
// stripping PASSWORD-ALGORITHMS from the authenticated request cannot make
// the server fall back to MD5: the nonce cookie marks the feature as
// negotiated, so the altered request is rejected with a 400-class error.
func TestBidDownStripPasswordAlgorithms(t *testing.T) {
	advertised := PasswordAlgorithms{{Algorithm: PasswordAlgorithmSHA256}}
	challengeMsg, challenge := newTestChallenge(t, advertised, false)
	request, _ := buildAuthenticatedRequest(t, challengeMsg)

	// Attacker strips both algorithm attributes but leaves the nonce cookie.
	stripped := New()
	stripped.Type = BindingRequest
	stripped.WriteHeader()
	for _, attr := range request.Attributes {
		if attr.Type == AttrPasswordAlgorithm || attr.Type == AttrPasswordAlgorithms {
			continue
		}
		stripped.Add(attr.Type, attr.Value)
	}
	// Re-sign is impossible without the key, so the original MI256 now
	// covers a different message; the negotiation violation must be
	// reported before the HMAC mismatch anyway.
	_, err := AuthenticateLongTermRequest(stripped, challenge.Algorithms, lookupTestUser)
	assert.ErrorIs(t, err, ErrNoPasswordAlgorithm)
}

func TestBidDownWeakAlgorithmNotAdvertised(t *testing.T) {
	advertised := PasswordAlgorithms{{Algorithm: PasswordAlgorithmSHA256}}
	challengeMsg, challenge := newTestChallenge(t, advertised, false)
	request, _ := buildAuthenticatedRequest(t, challengeMsg)

	// Attacker rewrites PASSWORD-ALGORITHM to MD5, which the server never
	// advertised.
	rewritten := New()
	rewritten.Type = BindingRequest
	rewritten.WriteHeader()
	for _, attr := range request.Attributes {
		switch attr.Type {
		case AttrPasswordAlgorithm:
			assert.NoError(t, NewPasswordAlgorithm(PasswordAlgorithmMD5).AddTo(rewritten))
		default:
			rewritten.Add(attr.Type, attr.Value)
		}
	}
	_, err := AuthenticateLongTermRequest(rewritten, challenge.Algorithms, lookupTestUser)
	assert.ErrorIs(t, err, ErrPasswordAlgorithmsMismatch)
}

func TestBidDownTamperedPasswordAlgorithms(t *testing.T) {
	advertised := PasswordAlgorithms{{Algorithm: PasswordAlgorithmSHA256}}
	challengeMsg, challenge := newTestChallenge(t, advertised, false)
	request, _ := buildAuthenticatedRequest(t, challengeMsg)

	tampered := New()
	tampered.Type = BindingRequest
	tampered.WriteHeader()
	for _, attr := range request.Attributes {
		switch attr.Type {
		case AttrPasswordAlgorithms:
			// Attacker drops SHA-256 and offers only MD5.
			weak := PasswordAlgorithms{{Algorithm: PasswordAlgorithmMD5}}
			assert.NoError(t, weak.AddTo(tampered))
		default:
			tampered.Add(attr.Type, attr.Value)
		}
	}
	_, err := AuthenticateLongTermRequest(tampered, challenge.Algorithms, lookupTestUser)
	assert.ErrorIs(t, err, ErrPasswordAlgorithmsMismatch)
}

// TestClientRejectsDowngradedChallenge verifies the client-side rule of
// RFC 8489 Section 9.2.5: a nonce cookie advertising password algorithms
// without the matching PASSWORD-ALGORITHMS attribute must not be retried.
func TestClientRejectsDowngradedChallenge(t *testing.T) {
	features := SecurityFeatures{}
	features.Set(SecurityFeaturePasswordAlgorithms)
	msg := New()
	msg.Type = BindingError
	msg.WriteHeader()
	assert.NoError(t, CodeUnauthorized.AddTo(msg))
	assert.NoError(t, NewRealm(testRealm).AddTo(msg))
	assert.NoError(t, NewNonceWithFeatures(features, "opaque").AddTo(msg))
	// Deliberately no PASSWORD-ALGORITHMS attribute.

	_, err := ParseLongTermChallenge(msg)
	assert.ErrorIs(t, err, ErrNoPasswordAlgorithm)
}

func TestClientRejectsUnsupportedAlgorithm(t *testing.T) {
	features := SecurityFeatures{}
	features.Set(SecurityFeaturePasswordAlgorithms)
	msg := New()
	msg.Type = BindingError
	msg.WriteHeader()
	assert.NoError(t, CodeUnauthorized.AddTo(msg))
	assert.NoError(t, NewRealm(testRealm).AddTo(msg))
	assert.NoError(t, NewNonceWithFeatures(features, "opaque").AddTo(msg))
	unsupported := PasswordAlgorithms{{Algorithm: PasswordAlgorithm(0x0009)}}
	assert.NoError(t, unsupported.AddTo(msg))

	_, err := ParseLongTermChallenge(msg)
	assert.ErrorIs(t, err, ErrNoSupportedPasswordAlgorithm)
}

func TestChallengeSelectsFirstSupportedAlgorithm(t *testing.T) {
	advertised := PasswordAlgorithms{
		{Algorithm: PasswordAlgorithm(0x0009)}, // unknown, skipped
		{Algorithm: PasswordAlgorithmSHA256},
		{Algorithm: PasswordAlgorithmMD5},
	}
	challengeMsg, challenge := newTestChallenge(t, advertised, false)
	request, _ := buildAuthenticatedRequest(t, challengeMsg)
	var chosen PasswordAlgorithmAttr
	assert.NoError(t, chosen.GetFrom(request))
	assert.Equal(t, PasswordAlgorithmSHA256, chosen.Algorithm)

	result, err := AuthenticateLongTermRequest(request, challenge.Algorithms, lookupTestUser)
	assert.NoError(t, err)
	assert.Equal(t, PasswordAlgorithmSHA256, result.PasswordAlgorithm)
}

func TestChallengeNonceCookieFeatures(t *testing.T) {
	advertised := PasswordAlgorithms{{Algorithm: PasswordAlgorithmSHA256}}
	_, challenge := newTestChallenge(t, advertised, true)
	features, err := ParseNonceCookie(challenge.Nonce)
	assert.NoError(t, err)
	assert.True(t, features.Has(SecurityFeaturePasswordAlgorithms))
	assert.True(t, features.Has(SecurityFeatureUsernameAnonymity))
}

func TestLegacyMD5ChallengeHasNoCookie(t *testing.T) {
	challenge := LongTermChallenge{
		Realm: NewRealm(testRealm),
		Nonce: NewNonce("plain-legacy-nonce"),
	}
	msg := New()
	msg.Type = BindingError
	msg.WriteHeader()
	assert.NoError(t, challenge.AddTo(msg))

	var nonce Nonce
	assert.NoError(t, nonce.GetFrom(msg))
	_, err := ParseNonceCookie(nonce)
	assert.ErrorIs(t, err, ErrInvalidNonceCookie)
}
