// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This file encodes the authentication state matrix for STUN message
// parsing as executable tests. The parser first builds an attribute view
// (Message.Decode) and trust decisions are formed afterwards by
// MessageIntegrity.Check and Fingerprint.Check. The matrix covers:
//
//  1. Byte ranges: MESSAGE-INTEGRITY and FINGERPRINT each authenticate
//     exactly the byte range the protocol assigns to them.
//  2. Ordering: attributes after an integrity attribute (other than
//     MESSAGE-INTEGRITY-SHA256 / FINGERPRINT) are dropped and must never
//     be treated as authenticated data.
//  3. Truncation and duplication of attributes fail closed.
//  4. Object reuse: a failed decode or failed check on a reused Message
//     leaves no attributes or trust conclusions behind for the next
//     message decoded into the same object.
//  5. Valid-message cross-layer matrix: attribute semantics, check
//     results and serialization stay compatible across message classes,
//     auth combinations and decode paths.

// matrixKey is the short-term credential shared by the matrix tests.
var matrixKey = NewShortTermIntegrity("matrix-secret") //nolint:gochecknoglobals

// buildMatrixMessage builds a Binding message of typ carrying
// SOFTWARE("matrix-soft") plus the requested authentication attributes
// in protocol order (MESSAGE-INTEGRITY before FINGERPRINT).
func buildMatrixMessage(tb testing.TB, typ MessageType, withMI, withFP bool) *Message {
	tb.Helper()
	m := New()
	m.SetType(typ)
	m.WriteHeader()
	addAttr(tb, m, NewSoftware("matrix-soft"))
	if withMI {
		assert.NoError(tb, matrixKey.AddTo(m))
	}
	if withFP {
		assert.NoError(tb, Fingerprint.AddTo(m))
	}

	return m
}

// rawAttrValueOffset walks raw message attributes and returns the offset
// of the value of the occurrence-th attribute of type want.
func rawAttrValueOffset(tb testing.TB, raw []byte, want AttrType, occurrence int) int {
	tb.Helper()
	off := messageHeaderSize
	seen := 0
	for off+attributeHeaderSize <= len(raw) {
		attrType := AttrType(bin.Uint16(raw[off:]))
		attrLen := int(bin.Uint16(raw[off+2:]))
		if attrType == want {
			if seen == occurrence {
				return off + attributeHeaderSize
			}
			seen++
		}
		off += attributeHeaderSize + nearestPaddedValueLength(attrLen)
	}
	tb.Fatalf("attribute %s occurrence %d not found in raw message", want, occurrence)

	return 0
}

// decodeFresh decodes raw into a new Message, failing the test on error.
func decodeFresh(tb testing.TB, raw []byte) *Message {
	tb.Helper()
	m := New()
	if err := Decode(raw, m); err != nil {
		tb.Fatalf("Decode: %v", err)
	}

	return m
}

// TestAuthMatrixIntegrityByteRange verifies that MESSAGE-INTEGRITY
// authenticates exactly the header (with adjusted length) and the
// attributes preceding it: mutations inside that range fail the check,
// mutations outside it (in FINGERPRINT) must not.
func TestAuthMatrixIntegrityByteRange(t *testing.T) {
	base := buildMatrixMessage(t, BindingRequest, true, true)
	miOff := rawAttrValueOffset(t, base.Raw, AttrMessageIntegrity, 0)
	fpOff := rawAttrValueOffset(t, base.Raw, AttrFingerprint, 0)
	swOff := rawAttrValueOffset(t, base.Raw, AttrSoftware, 0)

	cases := []struct {
		name        string
		offset      int
		integrity   bool // expected MessageIntegrity.Check result
		fingerprint bool // expected Fingerprint.Check result
	}{
		{"no mutation", -1, true, true},
		{"transaction id", 8, false, false},
		{"attribute before MI", swOff, false, false},
		{"MI value itself", miOff, false, false},
		{"fingerprint value", fpOff, true, false}, // outside MI range
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := append([]byte(nil), base.Raw...)
			if c.offset >= 0 {
				raw[c.offset]++
			}
			m := decodeFresh(t, raw)

			err := matrixKey.Check(m)
			if c.integrity {
				assert.NoError(t, err, "integrity must cover only its own range")
			} else {
				assert.True(t, isIntegrityFailure(err), "expected integrity failure, got: %v", err)
			}

			err = Fingerprint.Check(m)
			if c.fingerprint {
				assert.NoError(t, err)
			} else {
				assert.True(t, isFingerprintFailure(err), "expected fingerprint failure, got: %v", err)
			}
		})
	}
}

// TestAuthMatrixFingerprintByteRange verifies that FINGERPRINT covers the
// whole message up to (excluding) the FINGERPRINT attribute itself, and
// that the check assumes FINGERPRINT is the last attribute.
func TestAuthMatrixFingerprintByteRange(t *testing.T) {
	base := buildMatrixMessage(t, BindingRequest, true, true)

	// Every byte before the FINGERPRINT attribute is inside the CRC range
	// (the length field is excluded: mutating it breaks decoding itself).
	fpAttrStart := rawAttrValueOffset(t, base.Raw, AttrFingerprint, 0) - attributeHeaderSize
	for _, off := range []int{0, 8, messageHeaderSize, fpAttrStart - 1} {
		raw := append([]byte(nil), base.Raw...)
		raw[off] ^= 0xff
		m := decodeFresh(t, raw)
		assert.True(t, isFingerprintFailure(Fingerprint.Check(m)), "offset %d", off)
	}

	// A correct fingerprint verifies, and the value bytes themselves are
	// outside the authenticated range (mutating them is detected by
	// comparison, not by CRC coverage).
	m := decodeFresh(t, base.Raw)
	assert.NoError(t, Fingerprint.Check(m))
}

// TestAuthMatrixOrdering covers the attribute ordering rules: attributes
// after an integrity attribute (except MI-SHA256/FINGERPRINT) are dropped
// at decode time and never become authenticated, readable attributes.
func TestAuthMatrixOrdering(t *testing.T) {
	t.Run("attribute after MI is dropped", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		addAttr(t, m, NewSoftware("before"))
		assert.NoError(t, matrixKey.AddTo(m))
		m.Add(AttrSoftware, []byte("after")) // smuggled after MI
		assert.NoError(t, Fingerprint.AddTo(m))

		d := decodeFresh(t, m.Raw)
		assert.NoError(t, matrixKey.Check(d))
		assert.NoError(t, Fingerprint.Check(d))
		v, err := d.Get(AttrSoftware)
		assert.NoError(t, err)
		assert.Equal(t, "before", string(v), "only the authenticated attribute may be visible")
		count := 0
		for _, a := range d.Attributes {
			if a.Type == AttrSoftware {
				count++
			}
		}
		assert.Equal(t, 1, count, "attribute after MI must be dropped")
	})

	t.Run("attribute after MI256 without MI is dropped", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		m.Add(AttrMessageIntegritySHA256, make([]byte, 32))
		m.Add(AttrSoftware, []byte("after"))
		assert.NoError(t, Fingerprint.AddTo(m))

		d := decodeFresh(t, m.Raw)
		assert.False(t, d.Contains(AttrSoftware))
		assert.NoError(t, Fingerprint.Check(d))
	})

	t.Run("MI256 after MI is kept", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		assert.NoError(t, matrixKey.AddTo(m))
		m.Add(AttrMessageIntegritySHA256, make([]byte, 32))
		assert.NoError(t, Fingerprint.AddTo(m))

		d := decodeFresh(t, m.Raw)
		assert.True(t, d.Contains(AttrMessageIntegrity))
		assert.True(t, d.Contains(AttrMessageIntegritySHA256))
		assert.NoError(t, matrixKey.Check(d))
		assert.NoError(t, Fingerprint.Check(d))
	})

	t.Run("fingerprint before integrity is rejected at build time", func(t *testing.T) {
		m := New()
		m.WriteHeader()
		assert.NoError(t, Fingerprint.AddTo(m))
		assert.ErrorIs(t, matrixKey.AddTo(m), ErrFingerprintBeforeIntegrity)
	})

	t.Run("fingerprint not last fails closed", func(t *testing.T) {
		// On the wire FINGERPRINT is not the last attribute: the check
		// computes the CRC over the wrong range and must fail.
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		assert.NoError(t, Fingerprint.AddTo(m))
		m.Add(AttrSoftware, []byte("tail"))

		d := decodeFresh(t, m.Raw)
		assert.True(t, isFingerprintFailure(Fingerprint.Check(d)))
	})
}

// TestAuthMatrixTruncation covers truncated messages and attributes:
// decoding must fail, and truncated authentication attributes must fail
// their checks instead of being accepted.
func TestAuthMatrixTruncation(t *testing.T) {
	base := buildMatrixMessage(t, BindingRequest, true, true)

	t.Run("header truncated", func(t *testing.T) {
		m := New()
		assert.ErrorIs(t, Decode(base.Raw[:messageHeaderSize-1], m), ErrUnexpectedHeaderEOF)
	})

	t.Run("body shorter than declared length", func(t *testing.T) {
		m := New()
		err := Decode(base.Raw[:len(base.Raw)-4], m)
		assert.Error(t, err)
		var dErr *DecodeErr
		assert.ErrorAs(t, err, &dErr)
	})

	t.Run("attribute header truncated", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		addAttr(t, m, NewSoftware("matrix-soft"))
		// Extend the declared length by 2 and append 2 dangling bytes:
		// a partial attribute header remains after the last attribute.
		m.Length += 2
		m.WriteLength()
		m.Raw = append(m.Raw, 0x00, 0x06)
		d := New()
		assert.Error(t, Decode(m.Raw, d))
	})

	t.Run("attribute value truncated", func(t *testing.T) {
		// Header declares 8 bytes: attribute header claims a 10-byte
		// value but only 4 bytes follow.
		raw := make([]byte, messageHeaderSize+8)
		bin.PutUint16(raw[0:2], BindingRequest.Value())
		bin.PutUint16(raw[2:4], 8)
		bin.PutUint32(raw[4:8], magicCookie)
		bin.PutUint16(raw[20:22], AttrUsername.Value())
		bin.PutUint16(raw[22:24], 10)
		m := New()
		assert.Error(t, Decode(raw, m))
	})

	t.Run("truncated MI value fails integrity check", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		m.Add(AttrMessageIntegrity, make([]byte, 10)) // 10 of 20 HMAC bytes
		d := decodeFresh(t, m.Raw)
		assert.True(t, isIntegrityFailure(matrixKey.Check(d)))
	})

	t.Run("empty MI value fails integrity check", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		m.Add(AttrMessageIntegrity, nil)
		d := decodeFresh(t, m.Raw)
		assert.True(t, isIntegrityFailure(matrixKey.Check(d)))
	})

	t.Run("truncated fingerprint fails size check", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		m.Add(AttrFingerprint, []byte{1, 2, 3})
		d := decodeFresh(t, m.Raw)
		assert.True(t, IsAttrSizeInvalid(Fingerprint.Check(d)))
	})
}

// TestAuthMatrixDuplication covers duplicated attributes: a second
// MESSAGE-INTEGRITY is dropped (the first, authenticated one wins) and a
// duplicated FINGERPRINT fails closed.
func TestAuthMatrixDuplication(t *testing.T) {
	t.Run("second MI is dropped", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		assert.NoError(t, matrixKey.AddTo(m))
		m.Add(AttrMessageIntegrity, make([]byte, 20)) // bogus duplicate
		assert.NoError(t, Fingerprint.AddTo(m))

		d := decodeFresh(t, m.Raw)
		count := 0
		for _, a := range d.Attributes {
			if a.Type == AttrMessageIntegrity {
				count++
			}
		}
		assert.Equal(t, 1, count)
		assert.NoError(t, matrixKey.Check(d), "first (valid) MI must be the one checked")
		assert.NoError(t, Fingerprint.Check(d))
	})

	t.Run("duplicated fingerprint fails closed", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		assert.NoError(t, Fingerprint.AddTo(m))
		assert.NoError(t, Fingerprint.AddTo(m)) // second, validly computed FP

		d := decodeFresh(t, m.Raw)
		assert.True(t, isFingerprintFailure(Fingerprint.Check(d)))
	})

	t.Run("duplicated regular attribute keeps first visible", func(t *testing.T) {
		m := New()
		m.SetType(BindingRequest)
		m.WriteHeader()
		m.Add(AttrSoftware, []byte("one"))
		m.Add(AttrSoftware, []byte("two"))
		assert.NoError(t, matrixKey.AddTo(m))

		d := decodeFresh(t, m.Raw)
		v, err := d.Get(AttrSoftware)
		assert.NoError(t, err)
		assert.Equal(t, "one", string(v))
		assert.NoError(t, matrixKey.Check(d))
	})
}

// TestAuthMatrixObjectReuse verifies that reusing one Message object
// across decodes never carries attributes or trust conclusions from a
// previous (possibly failed or malicious) message into the next one.
func TestAuthMatrixObjectReuse(t *testing.T) {
	msgA := New()
	msgA.SetType(BindingRequest)
	msgA.WriteHeader()
	addAttr(t, msgA, NewSoftware("alpha"))
	msgA.Add(AttrRealm, []byte("a-realm")) // unique to A
	assert.NoError(t, matrixKey.AddTo(msgA))
	assert.NoError(t, Fingerprint.AddTo(msgA))

	msgB := New()
	msgB.SetType(BindingSuccess)
	msgB.WriteHeader()
	addAttr(t, msgB, NewSoftware("beta"))
	assert.NoError(t, matrixKey.AddTo(msgB))
	assert.NoError(t, Fingerprint.AddTo(msgB))

	freshB := decodeFresh(t, msgB.Raw)

	// assertCleanB checks that m holds exactly message B: B's attributes,
	// B's trust results, and nothing left over from any earlier message.
	assertCleanB := func(t *testing.T, m *Message) {
		t.Helper()
		assert.NoError(t, matrixKey.Check(m))
		assert.NoError(t, Fingerprint.Check(m))
		assert.True(t, freshB.Equal(m), "reused object must decode identically to a fresh one")
		assert.False(t, m.Contains(AttrRealm), "attribute of previous message leaked")
		v, err := m.Get(AttrSoftware)
		assert.NoError(t, err)
		assert.Equal(t, "beta", string(v))
	}

	t.Run("valid then failed-auth then valid", func(t *testing.T) {
		m := New()
		assert.NoError(t, Decode(msgA.Raw, m))
		assert.NoError(t, matrixKey.Check(m))
		assert.True(t, m.Contains(AttrRealm))

		// Message with a corrupted HMAC: decodes, but fails the check.
		badAuth := append([]byte(nil), msgA.Raw...)
		badAuth[rawAttrValueOffset(t, badAuth, AttrMessageIntegrity, 0)] ^= 0xff
		assert.NoError(t, Decode(badAuth, m))
		assert.True(t, isIntegrityFailure(matrixKey.Check(m)))

		// The failed authentication must not poison the next message.
		assert.NoError(t, Decode(msgB.Raw, m))
		assertCleanB(t, m)
	})

	t.Run("valid then decode-error then valid", func(t *testing.T) {
		m := New()
		assert.NoError(t, Decode(msgA.Raw, m))

		// Truncated message: decode fails partway, leaving partial state.
		assert.Error(t, Decode(msgB.Raw[:len(msgB.Raw)-4], m))

		assert.NoError(t, Decode(msgB.Raw, m))
		assertCleanB(t, m)
	})

	t.Run("decode error mid-attributes leaves no residue", func(t *testing.T) {
		m := New()
		assert.NoError(t, Decode(msgA.Raw, m))

		// Declared length covers two dangling bytes past the last
		// attribute: decoding fails inside the attribute loop, after
		// some attributes were already decoded into the reused object.
		broken := append([]byte(nil), msgB.Raw...)
		broken = append(broken, 0x00, 0x06)
		bin.PutUint16(broken[2:4], uint16(len(broken)-messageHeaderSize)) //nolint:gosec // G115
		assert.Error(t, Decode(broken, m))

		assert.NoError(t, Decode(msgB.Raw, m))
		assert.Equal(t, len(freshB.Attributes), len(m.Attributes))
		assertCleanB(t, m)
	})

	t.Run("failed check leaves message state intact", func(t *testing.T) {
		raw := append([]byte(nil), msgA.Raw...)
		raw[rawAttrValueOffset(t, raw, AttrSoftware, 0)] ^= 0xff
		m := decodeFresh(t, raw)

		lengthBefore := m.Length
		rawBefore := append([]byte(nil), m.Raw...)
		assert.True(t, isIntegrityFailure(matrixKey.Check(m)))

		// A failed check must restore the header length it adjusted, so
		// the object stays reusable and serialization-compatible.
		assert.Equal(t, lengthBefore, m.Length)
		assert.Equal(t, rawBefore, m.Raw)
		serialized, err := m.MarshalBinary()
		assert.NoError(t, err)
		assert.Equal(t, rawBefore, serialized)

		// Check order does not matter: fingerprint result is identical
		// before and after the failed integrity check.
		assert.True(t, isFingerprintFailure(Fingerprint.Check(m)))
		assert.True(t, isIntegrityFailure(matrixKey.Check(m)))
	})

	t.Run("trust conclusions are recomputed per message", func(t *testing.T) {
		m := New()
		// A authenticates; B authenticates; a corrupted B must fail even
		// though the same object just held two valid messages.
		assert.NoError(t, Decode(msgA.Raw, m))
		assert.NoError(t, matrixKey.Check(m))
		assert.NoError(t, Decode(msgB.Raw, m))
		assert.NoError(t, matrixKey.Check(m))

		badB := append([]byte(nil), msgB.Raw...)
		badB[rawAttrValueOffset(t, badB, AttrSoftware, 0)] ^= 0xff
		assert.NoError(t, Decode(badB, m))
		assert.True(t, isIntegrityFailure(matrixKey.Check(m)))
		assert.True(t, isFingerprintFailure(Fingerprint.Check(m)))
	})
}

// TestAuthMatrixValidCrossLayer is the valid-message state matrix: every
// combination of message class and authentication layer must decode with
// stable attribute semantics, stable check results and compatible
// serialization across all decode paths.
func TestAuthMatrixValidCrossLayer(t *testing.T) {
	types := map[string]MessageType{
		"request":    NewType(MethodBinding, ClassRequest),
		"indication": NewType(MethodBinding, ClassIndication),
		"success":    NewType(MethodBinding, ClassSuccessResponse),
		"error":      NewType(MethodBinding, ClassErrorResponse),
	}
	auths := []struct {
		name   string
		mi, fp bool
	}{
		{"no auth", false, false},
		{"integrity only", true, false},
		{"fingerprint only", false, true},
		{"integrity+fingerprint", true, true},
	}

	for typeName, typ := range types {
		for _, auth := range auths {
			t.Run(typeName+"/"+auth.name, func(t *testing.T) {
				src := buildMatrixMessage(t, typ, auth.mi, auth.fp)
				raw := append([]byte(nil), src.Raw...)

				// Decode via every supported path.
				viaDecode := New()
				assert.NoError(t, Decode(raw, viaDecode))
				viaReadFrom := New()
				_, err := viaReadFrom.ReadFrom(bytes.NewReader(raw))
				assert.NoError(t, err)
				viaUnmarshal := New()
				assert.NoError(t, viaUnmarshal.UnmarshalBinary(raw))
				viaClone := New()
				assert.NoError(t, viaDecode.CloneTo(viaClone))

				for name, m := range map[string]*Message{
					"Decode":          viaDecode,
					"ReadFrom":        viaReadFrom,
					"UnmarshalBinary": viaUnmarshal,
					"CloneTo":         viaClone,
				} {
					// Attribute semantics are stable.
					assert.Equal(t, typ, m.Type, name)
					v, err := m.Get(AttrSoftware)
					assert.NoError(t, err, name)
					assert.Equal(t, "matrix-soft", string(v), name)

					// Trust results match the authentication layers present.
					err = matrixKey.Check(m)
					if auth.mi {
						assert.NoError(t, err, name)
					} else {
						assert.ErrorIs(t, err, ErrAttributeNotFound, name)
					}
					err = Fingerprint.Check(m)
					if auth.fp {
						assert.NoError(t, err, name)
					} else {
						assert.ErrorIs(t, err, ErrAttributeNotFound, name)
					}

					// Serialization is byte-compatible with the source.
					serialized, err := m.MarshalBinary()
					assert.NoError(t, err, name)
					assert.Equal(t, raw, serialized, name)

					// Re-encoding from the attribute view is byte-stable.
					re := New()
					re.Type = m.Type
					re.TransactionID = m.TransactionID
					re.Attributes = append(re.Attributes, m.Attributes...)
					re.Encode()
					assert.Equal(t, raw, re.Raw, name)
				}
			})
		}
	}
}
