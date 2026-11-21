// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNonceCookieRoundTrip(t *testing.T) {
	// All-zero feature set: 3 zero bytes base64-encode to "AAAA".
	assert.Equal(t, "obMatJos2AAAA", EncodeNonceCookie(SecurityFeatures{}))

	features := SecurityFeatures{}
	features.Set(SecurityFeaturePasswordAlgorithms)
	cookie := EncodeNonceCookie(features)
	assert.Len(t, cookie, nonceCookieLen)
	// Bit 0 is the most significant bit of the first feature byte.
	assert.Equal(t, "gAAA", cookie[len(nonceCookiePrefix):])

	parsed, err := ParseNonceCookie([]byte(cookie + "opaque-nonce-material"))
	assert.NoError(t, err)
	assert.True(t, parsed.Has(SecurityFeaturePasswordAlgorithms))
	assert.False(t, parsed.Has(SecurityFeatureUsernameAnonymity))

	anonymity := SecurityFeatures{}
	anonymity.Set(SecurityFeatureUsernameAnonymity)
	parsedAnon, err := ParseNonceCookie(NewNonceWithFeatures(anonymity, "xyz"))
	assert.NoError(t, err)
	assert.True(t, parsedAnon.Has(SecurityFeatureUsernameAnonymity))
	assert.False(t, parsedAnon.Has(SecurityFeaturePasswordAlgorithms))
}

func TestParseNonceCookieErrors(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		[]byte("short"),
		[]byte("xxMatJos2AAAA-suffix"),
		[]byte("obMatJos2!!!!-suffix"), // invalid base64
	} {
		_, err := ParseNonceCookie(raw)
		assert.ErrorIs(t, err, ErrInvalidNonceCookie)
	}

	// A plain legacy nonce without the cookie is not an error for the
	// caller's protocol flow, but ParseNonceCookie must report it.
	_, err := ParseNonceCookie([]byte("f//499k954d6OL34oL9FSTvy64sA"))
	assert.ErrorIs(t, err, ErrInvalidNonceCookie)
}

func TestPasswordAlgorithmAttrRoundTrip(t *testing.T) {
	m := New()
	m.WriteHeader()
	alg := NewPasswordAlgorithm(PasswordAlgorithmSHA256)
	assert.NoError(t, alg.AddTo(m))

	decoded := New()
	assert.NoError(t, Decode(m.Raw, decoded))
	var got PasswordAlgorithmAttr
	assert.NoError(t, got.GetFrom(decoded))
	assert.Equal(t, PasswordAlgorithmSHA256, got.Algorithm)
	assert.Empty(t, got.Parameters)
}

func TestPasswordAlgorithmWithParameters(t *testing.T) {
	params := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	m := New()
	m.WriteHeader()
	alg := PasswordAlgorithmAttr{Algorithm: PasswordAlgorithm(0x0003), Parameters: params}
	assert.NoError(t, alg.AddTo(m))

	decoded := New()
	assert.NoError(t, Decode(m.Raw, decoded))
	var got PasswordAlgorithmAttr
	assert.NoError(t, got.GetFrom(decoded))
	assert.Equal(t, PasswordAlgorithm(0x0003), got.Algorithm)
	assert.Equal(t, params, got.Parameters)

	// Malformed attribute values are rejected.
	bad := New()
	bad.WriteHeader()
	bad.Add(AttrPasswordAlgorithm, []byte{0x00, 0x02})
	var badAttr PasswordAlgorithmAttr
	assert.ErrorIs(t, badAttr.GetFrom(bad), ErrPasswordAlgorithmSize)
}

func TestPasswordAlgorithmsRoundTrip(t *testing.T) {
	advertised := PasswordAlgorithms{
		{Algorithm: PasswordAlgorithmSHA256},
		{Algorithm: PasswordAlgorithmMD5},
	}
	m := New()
	m.WriteHeader()
	assert.NoError(t, advertised.AddTo(m))

	decoded := New()
	assert.NoError(t, Decode(m.Raw, decoded))
	var got PasswordAlgorithms
	assert.NoError(t, got.GetFrom(decoded))
	assert.Len(t, got, 2)
	assert.Equal(t, PasswordAlgorithmSHA256, got[0].Algorithm)
	assert.Equal(t, PasswordAlgorithmMD5, got[1].Algorithm)
	assert.True(t, got.Contains(PasswordAlgorithmValue{Algorithm: PasswordAlgorithmMD5}))
	assert.False(t, got.Contains(PasswordAlgorithmValue{Algorithm: PasswordAlgorithm(0x0009)}))
}

func TestLongTermKeyAlgorithms(t *testing.T) {
	const (
		username = "user"
		realm    = "realm"
		password = "pass"
	)
	md5Key, err := LongTermKey(PasswordAlgorithmMD5, username, realm, password)
	assert.NoError(t, err)
	assert.Len(t, md5Key, 16)
	// Matches the historical NewLongTermIntegrity output.
	assert.Equal(t, []byte(NewLongTermIntegrity(username, realm, password)), md5Key)

	sha256Key, err := LongTermKey(PasswordAlgorithmSHA256, username, realm, password)
	assert.NoError(t, err)
	assert.Len(t, sha256Key, 32)
	assert.Equal(t, sha256Key, []byte(NewLongTermIntegritySHA256(username, realm, password)))

	_, err = LongTermKey(PasswordAlgorithm(0x0009), username, realm, password)
	assert.ErrorIs(t, err, ErrPasswordAlgorithmNotSupported)
}

func TestMessageIntegritySHA256RoundTrip(t *testing.T) {
	msg := New()
	msg.Type = BindingRequest
	msg.WriteHeader()
	assert.NoError(t, NewSoftware("software").AddTo(msg)) //nolint:errcheck,gosec
	integrity := NewShortTermIntegritySHA256("pwd")
	assert.NoError(t, integrity.AddTo(msg))
	assert.NoError(t, Fingerprint.AddTo(msg))

	decoded := New()
	assert.NoError(t, Decode(msg.Raw, decoded))
	assert.NoError(t, integrity.Check(decoded))

	// Tampering with the message must fail verification.
	decoded.Raw[24]++
	assertIntegrityMismatch(t, integrity.Check(decoded))
}

func TestMessageIntegritySHA256Truncation(t *testing.T) {
	integrity := NewShortTermIntegritySHA256("pwd")

	// Build a message carrying a 16-byte truncated value, re-computing the
	// HMAC over the same preceding content using the same length-adjustment
	// logic as AddTo.
	truncated := New()
	truncated.Type = BindingRequest
	truncated.WriteHeader()
	assert.NoError(t, addIntegrity(truncated, AttrMessageIntegritySHA256, integrity, 16, newHMACSHA256))

	// Strict Check rejects the truncated value; CheckTruncated accepts it.
	assert.ErrorIs(t, integrity.Check(truncated), ErrIntegritySize)
	assert.NoError(t, integrity.CheckTruncated(truncated))

	// Lengths below 16 bytes, non-multiples of four and over-long values fail.
	for _, size := range []int{12, 15, 20, 36} {
		bad := New()
		bad.Type = BindingRequest
		bad.WriteHeader()
		bad.Add(AttrMessageIntegritySHA256, make([]byte, size))
		assert.Error(t, integrity.CheckTruncated(bad), "size %d must be rejected", size)
	}
}

func TestMessageIntegritySHA256BeforeFingerprint(t *testing.T) {
	m := New()
	m.WriteHeader()
	assert.NoError(t, Fingerprint.AddTo(m))
	i := NewShortTermIntegritySHA256("password")
	assert.ErrorIs(t, i.AddTo(m), ErrFingerprintBeforeIntegrity)
}

func TestUserhashRoundTrip(t *testing.T) {
	hash := NewUserhash("user", "realm")
	assert.Len(t, hash, UserhashSize)

	m := New()
	m.WriteHeader()
	assert.NoError(t, hash.AddTo(m))

	decoded := New()
	assert.NoError(t, Decode(m.Raw, decoded))
	var got Userhash
	assert.NoError(t, got.GetFrom(decoded))
	assert.True(t, bytes.Equal(hash, got))

	// A wrong-sized USERHASH attribute is rejected.
	bad := New()
	bad.WriteHeader()
	bad.Add(AttrUserhash, []byte{1, 2, 3})
	var badHash Userhash
	assert.Error(t, badHash.GetFrom(bad))
}

func TestDuplicateSingletonAuthAttributes(t *testing.T) {
	m := New()
	m.Type = BindingRequest
	m.WriteHeader()
	m.Add(AttrUsername, []byte("first"))
	m.Add(AttrUsername, []byte("second"))
	m.Add(AttrRealm, []byte("realm"))
	m.Add(AttrRealm, []byte("realm2"))

	decoded := New()
	assert.NoError(t, Decode(m.Raw, decoded))

	count := 0
	for _, a := range decoded.Attributes {
		if a.Type == AttrUsername || a.Type == AttrRealm {
			count++
		}
	}
	assert.Equal(t, 2, count) // one of each, duplicates dropped

	var username Username
	assert.NoError(t, username.GetFrom(decoded))
	assert.Equal(t, "first", username.String())
	var realm Realm
	assert.NoError(t, realm.GetFrom(decoded))
	assert.Equal(t, "realm", realm.String())
}

func TestDuplicateIntegrityAttributes(t *testing.T) {
	// Duplicate MI256 attributes: only the first occurrence survives.
	m := New()
	m.Type = BindingRequest
	m.WriteHeader()
	integrity := NewShortTermIntegritySHA256("password")
	assert.NoError(t, integrity.AddTo(m))
	// A second, forged MI256 with a different key.
	forged := NewShortTermIntegritySHA256("attacker")
	assert.NoError(t, forged.AddTo(m))

	decoded := New()
	assert.NoError(t, Decode(m.Raw, decoded))
	count := 0
	for _, a := range decoded.Attributes {
		if a.Type == AttrMessageIntegritySHA256 {
			count++
		}
	}
	assert.Equal(t, 1, count)
	// The surviving first attribute verifies with the legitimate key.
	assert.NoError(t, integrity.Check(decoded))
	assertIntegrityMismatch(t, forged.Check(decoded))
}

func TestCheckLongTermIntegrityNoFallback(t *testing.T) {
	msg := New()
	msg.Type = BindingRequest
	msg.WriteHeader()
	legit := NewShortTermIntegritySHA256("password")
	assert.NoError(t, legit.AddTo(msg))

	decoded := New()
	assert.NoError(t, Decode(msg.Raw, decoded))

	// With MI256 present, a wrong key fails and never falls back to SHA1.
	algorithm, err := CheckLongTermIntegrity(decoded, []byte("wrong-key"))
	assert.Equal(t, IntegritySHA256, algorithm)
	assertIntegrityMismatch(t, err)

	// The right key succeeds.
	algorithm, err = CheckLongTermIntegrity(decoded, []byte("password"))
	assert.Equal(t, IntegritySHA256, algorithm)
	assert.NoError(t, err)

	// A message without any integrity attribute reports ErrNoIntegrity
	// instead of being treated as authenticated.
	plain := New()
	plain.Type = BindingRequest
	plain.WriteHeader()
	algorithm, err = CheckLongTermIntegrity(plain, []byte("password"))
	assert.Equal(t, IntegrityNone, algorithm)
	assert.ErrorIs(t, err, ErrNoIntegrity)
}

func TestCheckLongTermIntegrityLegacySHA1(t *testing.T) {
	msg := New()
	msg.Type = BindingRequest
	msg.WriteHeader()
	legit := NewShortTermIntegrity("password")
	assert.NoError(t, legit.AddTo(msg))

	decoded := New()
	assert.NoError(t, Decode(msg.Raw, decoded))
	algorithm, err := CheckLongTermIntegrity(decoded, []byte("password"))
	assert.Equal(t, IntegritySHA1, algorithm)
	assert.NoError(t, err)

	algorithm, err = CheckLongTermIntegrity(decoded, []byte("wrong"))
	assert.Equal(t, IntegritySHA1, algorithm)
	assertIntegrityMismatch(t, err)
}

func BenchmarkMessageIntegritySHA256_AddTo(b *testing.B) {
	m := new(Message)
	integrity := NewShortTermIntegritySHA256("password")
	m.WriteHeader()
	b.ReportAllocs()
	b.SetBytes(int64(len(m.Raw)))
	for i := 0; i < b.N; i++ {
		m.WriteHeader()
		assert.NoError(b, integrity.AddTo(m))
		m.Reset()
	}
}

func BenchmarkMessageIntegritySHA256_Check(b *testing.B) {
	m := new(Message)
	m.Raw = make([]byte, 0, 1024)
	NewSoftware("software").AddTo(m) //nolint:errcheck,gosec
	integrity := NewShortTermIntegritySHA256("password")
	b.ReportAllocs()
	m.WriteHeader()
	b.SetBytes(int64(len(m.Raw)))
	assert.NoError(b, integrity.AddTo(m))
	m.WriteLength()
	for i := 0; i < b.N; i++ {
		assert.NoError(b, integrity.Check(m))
	}
}
