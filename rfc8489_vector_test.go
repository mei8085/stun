// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRFC8489AppendixB reproduces the MESSAGE-INTEGRITY-SHA256 with
// USERHASH test vector of RFC 8489 Appendix B.1, using the corrected
// message from verified Errata 6268/6290: the printed vector had a wrong
// length field and was missing the required PASSWORD-ALGORITHM attribute.
//
// https://www.rfc-editor.org/errata/eid6268
// https://www.rfc-editor.org/errata/eid6290
func TestRFC8489AppendixB(t *testing.T) {
	// Parameters from Appendix B.1. The Japanese username is unaffected by
	// OpaqueString processing; "TheMatrIX" is the OpaqueString-prepared
	// password.
	username := "マトリックス"
	password := "TheMatrIX"
	realm := "example.org"
	nonce := "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA"

	// Expected USERHASH from the test vector.
	expectedUserhash, err := hex.DecodeString("4a3cf38fef6992bda952c6780417da0f24819415569e60b205c46e41407f1704")
	assert.NoError(t, err)
	assert.Equal(t, expectedUserhash, []byte(NewUserhash(username, realm)))

	// Build the request in the erratum-corrected attribute order:
	// USERHASH, NONCE, REALM, PASSWORD-ALGORITHM, MESSAGE-INTEGRITY-SHA256.
	msg := New()
	msg.Type = BindingRequest
	msg.TransactionID = [TransactionIDSize]byte{
		0x78, 0xad, 0x34, 0x33,
		0xc6, 0xad, 0x72, 0xc0,
		0x29, 0xda, 0x41, 0x2e,
	}
	msg.WriteHeader()

	assert.NoError(t, NewUserhash(username, realm).AddTo(msg))
	assert.NoError(t, NewNonce(nonce).AddTo(msg))
	assert.NoError(t, NewRealm(realm).AddTo(msg))
	assert.NoError(t, NewPasswordAlgorithm(PasswordAlgorithmSHA256).AddTo(msg))

	key, err := LongTermKey(PasswordAlgorithmSHA256, username, realm, password)
	assert.NoError(t, err)
	assert.Len(t, key, 32)
	assert.NoError(t, MessageIntegritySHA256(key).AddTo(msg))

	// Expected HMAC-SHA256 and length from the corrected erratum vector.
	expectedMI256, err := hex.DecodeString("b5c7bf005b6c52a21c51c5e892f81924136296cb927c43149309278cc6518e65")
	assert.NoError(t, err)
	gotMI256, err := msg.Get(AttrMessageIntegritySHA256)
	assert.NoError(t, err)
	assert.Equal(t, expectedMI256, gotMI256)
	assert.Equal(t, uint32(0x90), msg.Length)

	// Round-trip: decode and verify the integrity with the same key.
	decoded := New()
	assert.NoError(t, Decode(msg.Raw, decoded))
	assert.NoError(t, MessageIntegritySHA256(key).Check(decoded))

	// A wrong password must fail verification rather than fall back.
	badKey, err := LongTermKey(PasswordAlgorithmSHA256, username, realm, "wrong-password")
	assert.NoError(t, err)
	algorithm, checkErr := CheckLongTermIntegrity(decoded, badKey)
	assert.Equal(t, IntegritySHA256, algorithm)
	assertIntegrityMismatch(t, checkErr)
}
