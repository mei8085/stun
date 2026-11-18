// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

// This file covers the two attacker controlled length fields that define STUN
// attribute framing: the 16 bit value length inside every attribute TLV and the
// 16 bit message length in the header. A decoder that checks them only against
// the end of the datagram instead of the end of the declared message will treat
// a truncated or forged attribute as complete, so the tests below assert that
// framing and datagram length stay consistent and that nothing is ever read
// from outside the declared message.
//
// The reference framer (frameAttributes) is written from the wire format and
// deliberately does not reuse the package helpers it is checking.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by RFC 5389 for MESSAGE-INTEGRITY.
	"encoding/binary"
	"hash/crc32"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPassword is the shared password used by the authentication checks.
const testPassword = "password"

// wireAttribute is one attribute as framed by the reference framer.
type wireAttribute struct {
	typ AttrType
	// declaredLength is the value length from the TLV, excluding padding.
	declaredLength int
	value          []byte
	// valueStart and valueEnd delimit the padded value as offsets from the
	// first byte of the message attribute region.
	valueStart int
	valueEnd   int
}

// framingViolation reports why a datagram is not a sequence of complete TLVs
// that fits exactly in the message length declared by its header.
type framingViolation int

const (
	framingOK framingViolation = iota
	framingShortHeader
	framingInvalidCookie
	framingMessageBeyondDatagram
	framingPartialAttributeHeader
	framingValueBeyondMessage
)

func (v framingViolation) String() string {
	switch v {
	case framingOK:
		return "ok"
	case framingShortHeader:
		return "datagram is shorter than the message header"
	case framingInvalidCookie:
		return "invalid magic cookie"
	case framingMessageBeyondDatagram:
		return "declared message length exceeds the datagram"
	case framingPartialAttributeHeader:
		return "attribute header does not fit before the declared message end"
	case framingValueBeyondMessage:
		return "padded attribute value does not fit before the declared message end"
	default:
		return "unknown framing violation"
	}
}

// alignToFour rounds n up to the 32 bit attribute alignment of RFC 8489.
func alignToFour(n int) int {
	return (n + 3) &^ 3
}

// frameAttributes walks datagram using only the message length declared in the
// header. Bytes after that length are not attributes and are simply ignored; a
// TLV that ends after it is rejected instead of being allowed to read into the
// trailing bytes.
func frameAttributes(datagram []byte) ([]wireAttribute, int, framingViolation) {
	if len(datagram) < messageHeaderSize {
		return nil, 0, framingShortHeader
	}
	if binary.BigEndian.Uint32(datagram[4:8]) != magicCookie {
		return nil, 0, framingInvalidCookie
	}
	declared := int(binary.BigEndian.Uint16(datagram[2:4]))
	if messageHeaderSize+declared > len(datagram) {
		return nil, 0, framingMessageBeyondDatagram
	}
	region := datagram[messageHeaderSize : messageHeaderSize+declared]
	attributes := make([]wireAttribute, 0, declared/padding+1)
	for offset := 0; offset < declared; {
		if declared-offset < attributeHeaderSize {
			return nil, 0, framingPartialAttributeHeader
		}
		typ := compatAttrType(binary.BigEndian.Uint16(region[offset : offset+2]))
		length := int(binary.BigEndian.Uint16(region[offset+2 : offset+4]))
		valueStart := offset + attributeHeaderSize
		paddedEnd := valueStart + alignToFour(length)
		if paddedEnd > declared {
			return nil, 0, framingValueBeyondMessage
		}
		attributes = append(attributes, wireAttribute{
			typ:            typ,
			declaredLength: length,
			value:          region[valueStart : valueStart+length],
			valueStart:     valueStart,
			valueEnd:       paddedEnd,
		})
		offset = paddedEnd
	}

	return attributes, declared, framingOK
}

// retainAfterIntegrity mirrors RFC 8489 section 13.2.1: once MESSAGE-INTEGRITY
// has been seen only MESSAGE-INTEGRITY-SHA256 and FINGERPRINT may follow, and
// once MESSAGE-INTEGRITY-SHA256 has been seen only FINGERPRINT may follow when
// MESSAGE-INTEGRITY was absent.
func retainAfterIntegrity(attributes []wireAttribute) []wireAttribute {
	retained := make([]wireAttribute, 0, len(attributes))
	var seenIntegrity, seenIntegritySHA256 bool
	for _, attribute := range attributes {
		isIntegrity := attribute.typ == AttrMessageIntegrity
		isIntegritySHA256 := attribute.typ == AttrMessageIntegritySHA256
		isFingerprint := attribute.typ == AttrFingerprint
		dropped := (seenIntegrity && !isIntegritySHA256 && !isFingerprint) ||
			(!seenIntegrity && seenIntegritySHA256 && !isFingerprint)
		if dropped {
			continue
		}
		retained = append(retained, attribute)
		seenIntegrity = seenIntegrity || isIntegrity
		seenIntegritySHA256 = seenIntegritySHA256 || isIntegritySHA256
	}

	return retained
}

// encodeWireTLV builds a TLV with an explicit length field, which may disagree
// with len(value) to emulate a truncated or forged attribute.
func encodeWireTLV(typ AttrType, declaredLength int, value, pad []byte) []byte {
	tlv := make([]byte, attributeHeaderSize, attributeHeaderSize+len(value)+len(pad))
	binary.BigEndian.PutUint16(tlv[0:2], typ.Value())
	binary.BigEndian.PutUint16(tlv[2:4], uint16(declaredLength)) //nolint:gosec // G115, callers stay in range.
	tlv = append(tlv, value...)

	return append(tlv, pad...)
}

// makeDatagram builds a datagram with the given header length, attribute region
// and trailing bytes that are not covered by the declared message length.
func makeDatagram(declaredLength int, attributes, trailing []byte) []byte {
	datagram := make([]byte, messageHeaderSize, messageHeaderSize+len(attributes)+len(trailing))
	binary.BigEndian.PutUint16(datagram[0:2], BindingRequest.Value())
	binary.BigEndian.PutUint16(datagram[2:4], uint16(declaredLength)) //nolint:gosec // G115, callers stay in range.
	binary.BigEndian.PutUint32(datagram[4:8], magicCookie)
	datagram = append(datagram, attributes...)

	return append(datagram, trailing...)
}

// decodePath is one public way of turning a datagram into a Message.
type decodePath struct {
	name   string
	decode func(*Message) error
}

func decodePaths(datagram []byte) []decodePath {
	return []decodePath{
		{name: "Decode", decode: func(m *Message) error { return Decode(datagram, m) }},
		{name: "Write", decode: func(m *Message) error {
			_, err := m.Write(datagram)

			return err
		}},
		{name: "UnmarshalBinary", decode: func(m *Message) error { return m.UnmarshalBinary(datagram) }},
		{name: "ReadFrom", decode: func(m *Message) error {
			// ReadFrom reads into m.Raw[:cap(m.Raw)] once, so the capacity must
			// fit the datagram for the entry points to be comparable.
			m.Raw = make([]byte, 0, len(datagram))
			_, err := m.ReadFrom(bytes.NewReader(datagram))

			return err
		}},
		{name: "CloneTo", decode: func(m *Message) error {
			source := new(Message)
			source.Raw = append(source.Raw[:0], datagram...)

			return source.CloneTo(m)
		}},
	}
}

func assertDecodePathsAgree(tb testing.TB, datagram []byte, baseline *Message) {
	tb.Helper()
	for _, path := range decodePaths(datagram) {
		decoded := New()
		if !assert.NoError(tb, path.decode(decoded), "decode path %s", path.name) {
			continue
		}
		assert.Equal(tb, baseline.Length, decoded.Length, "decode path %s message length", path.name)
		assert.Equal(tb, baseline.Attributes, decoded.Attributes, "decode path %s attributes", path.name)
	}
}

func assertDecodePathsReject(tb testing.TB, datagram []byte) {
	tb.Helper()
	for _, path := range decodePaths(datagram) {
		decoded := New()
		assert.Error(tb, path.decode(decoded), "decode path %s must reject", path.name)
	}
}

// assertEncodeIsCanonical re-encodes the message and checks that the encoder
// derives both length fields from the attributes, that the result frames
// cleanly, and that padding is zeroed.
func assertEncodeIsCanonical(tb testing.TB, decoded *Message) {
	tb.Helper()
	decoded.Encode()
	assert.Equal(tb, messageHeaderSize+int(decoded.Length), len(decoded.Raw), "encoded header length")
	assert.Zero(tb, int(decoded.Length)%padding, "encoded message length alignment")

	attributes, _, violation := frameAttributes(decoded.Raw)
	require.Equal(tb, framingOK, violation, "encoded message must frame cleanly")
	require.Len(tb, attributes, len(decoded.Attributes), "encoded attribute count")
	for i, attribute := range attributes {
		encoded := decoded.Attributes[i]
		assert.Equal(tb, encoded.Type, attribute.typ, "encoded attribute %d type", i)
		assert.Equal(tb, int(encoded.Length), attribute.declaredLength, "encoded attribute %d length", i)
		assert.Equal(tb, encoded.Value, attribute.value, "encoded attribute %d value", i)
		paddingStart := messageHeaderSize + attribute.valueStart + attribute.declaredLength
		paddingEnd := messageHeaderSize + attribute.valueEnd
		for _, padByte := range decoded.Raw[paddingStart:paddingEnd] {
			assert.Zero(tb, padByte, "encoded attribute %d padding", i)
		}
	}
}

// assertFramingMatchesReference is the core property: whatever the reference
// framer says about a datagram is what the decoder must do, attribute by
// attribute and byte by byte.
func assertFramingMatchesReference(tb testing.TB, datagram []byte) {
	tb.Helper()
	attributes, declared, violation := frameAttributes(datagram)
	decoded := New()
	decodeErr := Decode(datagram, decoded)
	if violation != framingOK {
		require.Error(tb, decodeErr, "framing violation (%s) must be rejected", violation)
		assertDecodePathsReject(tb, datagram)

		return
	}

	require.NoError(tb, decodeErr)
	assert.Equal(tb, declared, int(decoded.Length), "decoded message length")
	assert.Len(tb, decoded.Raw, len(datagram), "decoded datagram length")
	retained := retainAfterIntegrity(attributes)
	require.Len(tb, decoded.Attributes, len(retained), "retained attribute count")
	for i, want := range retained {
		got := decoded.Attributes[i]
		assert.Equal(tb, want.typ, got.Type, "attribute %d type", i)
		assert.Equal(tb, want.declaredLength, int(got.Length), "attribute %d length", i)
		assert.Equal(tb, want.value, got.Value, "attribute %d value", i)
		assert.LessOrEqual(tb, want.valueEnd, declared, "attribute %d must end inside the message", i)
	}
	assertDecodePathsAgree(tb, datagram, decoded)
	assertEncodeIsCanonical(tb, decoded)
}

func TestFramingLengthConsistency(t *testing.T) {
	validAttribute := encodeWireTLV(AttrSoftware, 4, []byte("abcd"), nil)
	paddedAttribute := encodeWireTLV(AttrSoftware, 3, []byte("abc"), []byte{0xAA})

	testCases := []struct {
		name       string
		datagram   []byte
		violation  framingViolation
		attributes []AttrType
	}{
		{
			name:       "well formed message",
			datagram:   makeDatagram(8, validAttribute, nil),
			violation:  framingOK,
			attributes: []AttrType{AttrSoftware},
		},
		{
			name:       "dirty padding inside the message",
			datagram:   makeDatagram(8, paddedAttribute, nil),
			violation:  framingOK,
			attributes: []AttrType{AttrSoftware},
		},
		{
			name:       "empty attribute",
			datagram:   makeDatagram(4, encodeWireTLV(AttrData, 0, nil, nil), nil),
			violation:  framingOK,
			attributes: []AttrType{AttrData},
		},
		{
			name:       "empty message",
			datagram:   makeDatagram(0, nil, nil),
			violation:  framingOK,
			attributes: nil,
		},
		{
			name:       "declared length is shorter than the datagram",
			datagram:   makeDatagram(8, validAttribute, []byte{0xDE, 0xAD, 0xBE, 0xEF}),
			violation:  framingOK,
			attributes: []AttrType{AttrSoftware},
		},
		{
			name:      "attribute value crosses the declared message end",
			datagram:  makeDatagram(8, append(encodeWireTLV(AttrSoftware, 8, []byte("abcd"), nil), []byte("efgh")...), nil),
			violation: framingValueBeyondMessage,
		},
		{
			name: "attribute padding crosses the declared message end",
			// 5 value bytes and 3 padding bytes are present, but the declared
			// message ends after the fourth value byte.
			datagram:  makeDatagram(8, encodeWireTLV(AttrSoftware, 5, []byte("abcde"), []byte{0, 0, 0}), nil),
			violation: framingValueBeyondMessage,
		},
		{
			name:      "message length cuts an attribute header in half",
			datagram:  makeDatagram(2, encodeWireTLV(AttrSoftware, 0, nil, nil), nil),
			violation: framingPartialAttributeHeader,
		},
		{
			name: "message length cuts the attribute padding",
			// The value fits, but the two padding bytes needed to reach the next
			// 32 bit boundary are outside the declared message.
			datagram:  makeDatagram(6, encodeWireTLV(AttrSoftware, 2, []byte("ab"), []byte{0, 0}), nil),
			violation: framingValueBeyondMessage,
		},
		{
			name:      "attribute length exceeds the whole datagram",
			datagram:  makeDatagram(8, encodeWireTLV(AttrSoftware, 0xFFFF, []byte("abcd"), nil), nil),
			violation: framingValueBeyondMessage,
		},
		{
			name:      "declared length exceeds the datagram",
			datagram:  makeDatagram(12, validAttribute, nil),
			violation: framingMessageBeyondDatagram,
		},
		{
			name:      "truncated datagram",
			datagram:  makeDatagram(8, validAttribute, nil)[:24],
			violation: framingMessageBeyondDatagram,
		},
		{
			name:      "truncated header",
			datagram:  makeDatagram(8, validAttribute, nil)[:8],
			violation: framingShortHeader,
		},
		{
			name: "invalid magic cookie",
			datagram: func() []byte {
				datagram := makeDatagram(8, validAttribute, nil)
				datagram[4] = 0x00

				return datagram
			}(),
			violation: framingInvalidCookie,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			attributes, _, violation := frameAttributes(testCase.datagram)
			assert.Equal(t, testCase.violation, violation)
			assertFramingMatchesReference(t, testCase.datagram)

			if testCase.violation != framingOK {
				decoded := New()
				assert.Error(t, Decode(testCase.datagram, decoded))
				assert.Empty(t, decoded.Attributes, "rejected datagram must not expose attributes")

				return
			}
			got := []AttrType{}
			for _, attribute := range attributes {
				got = append(got, attribute.typ)
			}
			if testCase.attributes == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, testCase.attributes, got)
			}
		})
	}
}

func TestFramingTrailingBytesAreNotAttributes(t *testing.T) {
	software := encodeWireTLV(AttrSoftware, 3, []byte("abc"), make([]byte, alignToFour(3)-3))
	message := makeDatagram(len(software), software, nil)

	// Appending junk without extending the header length must not add,
	// extend, or truncate any attribute.
	for _, trailing := range [][]byte{
		{0x00},
		{0x80, 0x22, 0x00, 0x04},
		{0x80, 0x22, 0xFF, 0xFF},
		bytes.Repeat([]byte{0xA5}, 16),
	} {
		datagram := append(append([]byte{}, message...), trailing...)
		attributes, declared, violation := frameAttributes(datagram)
		require.Equal(t, framingOK, violation)
		require.Equal(t, len(software), declared)

		decoded := New()
		require.NoError(t, Decode(datagram, decoded))
		require.Len(t, decoded.Attributes, len(retainAfterIntegrity(attributes)))
		require.Len(t, decoded.Attributes, 1)
		assert.Equal(t, AttrSoftware, decoded.Attributes[0].Type)
		assert.Equal(t, []byte("abc"), decoded.Attributes[0].Value)
		assert.Equal(t, len(message), messageHeaderSize+int(decoded.Length))

		// Re-encoding drops the bytes that were never part of the message, so
		// the emitted length fields stay consistent with the emitted bytes.
		assertEncodeIsCanonical(t, decoded)
		assert.Equal(t, len(message), len(decoded.Raw))
	}
}

func TestFramingPaddingIsNotPartOfTheValue(t *testing.T) {
	paddingFills := [][]byte{{0x00}, {0xFF}, {0xAA}, {0x7F, 0x00, 0x13}}

	for valueLength := 0; valueLength <= 9; valueLength++ {
		value := make([]byte, valueLength)
		for i := range value {
			value[i] = byte(i + 1)
		}
		for _, fill := range paddingFills {
			pad := make([]byte, alignToFour(valueLength)-valueLength)
			for i := range pad {
				pad[i] = fill[i%len(fill)]
			}
			datagram := makeDatagram(attributeHeaderSize+len(value)+len(pad), encodeWireTLV(AttrSoftware, valueLength, value, pad), nil)

			attributes, _, violation := frameAttributes(datagram)
			require.Equal(t, framingOK, violation)
			require.Len(t, attributes, 1)
			assert.Equal(t, valueLength, len(attributes[0].value))
			assert.Equal(t, valueLength, attributes[0].valueEnd-attributes[0].valueStart-(alignToFour(valueLength)-valueLength))

			decoded := New()
			require.NoError(t, Decode(datagram, decoded))
			require.Len(t, decoded.Attributes, 1)
			assert.Equal(t, AttrSoftware, decoded.Attributes[0].Type)
			assert.Equal(t, value, decoded.Attributes[0].Value, "padding must not leak into the value")
			assert.Equal(t, uint16(valueLength), decoded.Attributes[0].Length)

			assertEncodeIsCanonical(t, decoded)
			assert.Equal(t, value, decoded.Attributes[0].Value)
		}
	}
}

func TestFramingDecodePathsAgree(t *testing.T) {
	software := encodeWireTLV(AttrSoftware, 5, []byte("abcde"), []byte{0xAA, 0xAA, 0xAA})
	integrity := encodeWireTLV(AttrMessageIntegrity, messageIntegritySize, make([]byte, messageIntegritySize), nil)
	unknown := encodeWireTLV(AttrType(0x9001), 2, []byte{1, 2}, []byte{0xFF, 0xFF})
	datagrams := [][]byte{
		makeDatagram(0, nil, nil),
		makeDatagram(len(software), software, nil),
		makeDatagram(len(software)+len(integrity)+len(unknown), bytes.Join([][]byte{software, integrity, unknown}, nil), nil),
		makeDatagram(len(software)+len(integrity), append(append([]byte{}, software...), integrity...), []byte{1, 2, 3, 4}),
	}

	for i, datagram := range datagrams {
		baseline := New()
		if !assert.NoError(t, Decode(datagram, baseline), "datagram %d", i) {
			continue
		}
		assertDecodePathsAgree(t, datagram, baseline)
	}
}

// TestAttributeWireLayoutAndSemantics pins the byte layout of well formed
// attributes and confirms that the integrity and fingerprint values are
// computed over exactly the bytes required by RFC 5389, so that compatible
// implementations keep interoperating.
func TestAttributeWireLayoutAndSemantics(t *testing.T) {
	transactionID := [TransactionIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	message, err := Build(
		BindingRequest,
		NewTransactionIDSetter(transactionID),
		NewSoftware("pion/stun"), // 9 bytes, so three padding bytes are required.
		NewUsername("user"),
		NewShortTermIntegrity(testPassword),
		Fingerprint,
	)
	require.NoError(t, err)

	const (
		softwareTLVEnd    = messageHeaderSize + attributeHeaderSize + 12 // 9 value bytes + 3 padding bytes
		usernameTLVEnd    = softwareTLVEnd + attributeHeaderSize + 4
		integrityTLVStart = usernameTLVEnd
		integrityTLVEnd   = integrityTLVStart + attributeHeaderSize + messageIntegritySize
		fingerprintStart  = integrityTLVEnd
		fingerprintEnd    = fingerprintStart + attributeHeaderSize + fingerprintSize
	)
	require.Len(t, message.Raw, fingerprintEnd)
	assert.Equal(t, uint32(fingerprintEnd-messageHeaderSize), message.Length)
	assert.Equal(t, transactionID[:], message.Raw[8:messageHeaderSize])

	attributes, declared, violation := frameAttributes(message.Raw)
	require.Equal(t, framingOK, violation)
	assert.Equal(t, int(message.Length), declared)
	require.Len(t, attributes, 4)
	assert.Equal(t, []strip{
		{AttrSoftware, 9, 12},
		{AttrUsername, 4, 4},
		{AttrMessageIntegrity, messageIntegritySize, messageIntegritySize},
		{AttrFingerprint, fingerprintSize, fingerprintSize},
	}, stripOf(attributes))

	// MESSAGE-INTEGRITY: HMAC-SHA1 over the message up to the attribute, with
	// the header length extended to cover the integrity TLV.
	integrityInput := append([]byte{}, message.Raw[:integrityTLVStart]...)
	binary.BigEndian.PutUint16(integrityInput[2:4], uint16(integrityTLVEnd-messageHeaderSize)) //nolint:gosec // G115, small constant.
	mac := hmac.New(sha1.New, []byte(testPassword))
	mac.Write(integrityInput)
	assert.Equal(t, mac.Sum(nil), message.Raw[integrityTLVStart+attributeHeaderSize:integrityTLVEnd])

	// FINGERPRINT: CRC-32 of the message up to the attribute, XORed with
	// 0x5354554e, with the header length extended to cover the TLV.
	fingerprintInput := append([]byte{}, message.Raw[:fingerprintStart]...)
	binary.BigEndian.PutUint16(fingerprintInput[2:4], uint16(fingerprintEnd-messageHeaderSize)) //nolint:gosec // G115, small constant.
	assert.Equal(t, crc32.ChecksumIEEE(fingerprintInput)^0x5354554e,
		binary.BigEndian.Uint32(message.Raw[fingerprintStart+attributeHeaderSize:fingerprintEnd]))

	// The wire form decodes to the same values and verifies as authentic.
	decoded := New()
	require.NoError(t, Decode(message.Raw, decoded))
	assertDecodePathsAgree(t, message.Raw, decoded)
	var (
		software Software
		username Username
	)
	require.NoError(t, decoded.Parse(&software, &username))
	assert.Equal(t, "pion/stun", software.String())
	assert.Equal(t, "user", username.String())
	assert.NoError(t, NewShortTermIntegrity(testPassword).Check(decoded))
	assert.NoError(t, Fingerprint.Check(decoded))

	// Re-encoding reproduces the same bytes.
	decoded.Encode()
	assert.Equal(t, message.Raw, decoded.Raw)
}

// strip is a canonical, comparable view of an attribute's wire layout.
type strip struct {
	typ        AttrType
	valueLen   int
	paddedSize int
}

func stripOf(attributes []wireAttribute) []strip {
	strips := make([]strip, 0, len(attributes))
	for _, attribute := range attributes {
		strips = append(strips, strip{
			typ:        attribute.typ,
			valueLen:   attribute.declaredLength,
			paddedSize: attribute.valueEnd - attribute.valueStart,
		})
	}

	return strips
}

func TestUnknownAttributesDoNotChangeAuthenticationState(t *testing.T) {
	optionalUnknown := RawAttribute{Type: 0x9001, Value: []byte{0xDE, 0xAD}}
	requiredUnknown := RawAttribute{Type: 0x0005, Value: []byte{0xBE, 0xEF, 0x01}}

	buildAuthentic := func(t *testing.T, before, afterIntegrity []Setter) *Message {
		t.Helper()
		// Attributes in afterIntegrity are placed between MESSAGE-INTEGRITY
		// and FINGERPRINT, which RFC 8489 allows to be authenticated by the
		// fingerprint only.
		setters := append([]Setter{}, before...)
		setters = append(setters, NewSoftware("pion"), NewShortTermIntegrity(testPassword))
		setters = append(setters, afterIntegrity...)
		setters = append(setters, Fingerprint)
		message := new(Message)
		require.NoError(t, message.Build(setters...))

		return message
	}
	checkVerifies := func(t *testing.T, message *Message) {
		t.Helper()
		assert.NoError(t, NewShortTermIntegrity(testPassword).Check(message))
		assert.NoError(t, Fingerprint.Check(message))
	}

	t.Run("unknown attributes before integrity verify", func(t *testing.T) {
		message := buildAuthentic(t, []Setter{NewSoftware("first"), optionalUnknown, requiredUnknown}, nil)
		decoded := New()
		require.NoError(t, Decode(message.Raw, decoded))
		checkVerifies(t, decoded)

		for _, attribute := range []RawAttribute{optionalUnknown, requiredUnknown} {
			value, err := decoded.Get(attribute.Type)
			require.NoError(t, err)
			assert.Equal(t, attribute.Value, value, "unknown attribute %s", attribute.Type)
		}
	})

	t.Run("unknown attributes after integrity are dropped and do not break the checks", func(t *testing.T) {
		withUnknown := buildAuthentic(t, nil, []Setter{optionalUnknown})
		withoutUnknown := buildAuthentic(t, nil, nil)
		decoded := New()
		require.NoError(t, Decode(withUnknown.Raw, decoded))
		checkVerifies(t, decoded)
		_, found := decoded.Attributes.Get(optionalUnknown.Type)
		assert.False(t, found, "attribute after MESSAGE-INTEGRITY must be dropped")

		// The authentication verdict is identical to the message that never
		// carried the unknown attribute.
		baseline := New()
		require.NoError(t, Decode(withoutUnknown.Raw, baseline))
		checkVerifies(t, baseline)
	})

	t.Run("unknown attributes are authenticated when they precede integrity", func(t *testing.T) {
		authentic := buildAuthentic(t, []Setter{optionalUnknown}, nil)
		tampered := append([]byte{}, authentic.Raw...)
		index := bytes.Index(tampered, optionalUnknown.Value)
		require.GreaterOrEqual(t, index, messageHeaderSize)
		tampered[index] ^= 0x01

		decoded := New()
		require.NoError(t, Decode(tampered, decoded))
		// The debug build returns *IntegrityErr and *CRCMismatch instead of the
		// sentinel errors, so only the failure is asserted here.
		assert.Error(t, NewShortTermIntegrity(testPassword).Check(decoded), "tampered unknown attribute must fail integrity")
		assert.Error(t, Fingerprint.Check(decoded), "tampered unknown attribute must fail fingerprint")
	})
}

func TestForgedAttributesNeverPassAuthentication(t *testing.T) {
	key := NewShortTermIntegrity(testPassword)
	authentic := new(Message)
	require.NoError(t, authentic.Build(BindingRequest, NewSoftware("pion/stun"), userhashForTest(), key, Fingerprint))
	pristine := append([]byte{}, authentic.Raw...)

	unknown := encodeWireTLV(AttrType(0x9001), 4, []byte{0xDE, 0xAD, 0xBE, 0xEF}, nil)
	unknownBeforeIntegrity := append(append([]byte{}, pristine[:messageHeaderSize]...), unknown...)
	unknownBeforeIntegrity = append(unknownBeforeIntegrity, pristine[messageHeaderSize:]...)

	testCases := []struct {
		name       string
		datagram   []byte
		wantDecode bool
		wantPasses bool
	}{
		{
			name:       "untouched message",
			datagram:   pristine,
			wantDecode: true,
			wantPasses: true,
		},
		{
			name:       "attribute inserted before integrity",
			datagram:   withMessageLength(unknownBeforeIntegrity),
			wantDecode: true,
			wantPasses: false,
		},
		{
			name:       "attribute appended after fingerprint",
			datagram:   withMessageLength(append(append([]byte{}, pristine...), unknown...)),
			wantDecode: true,
			wantPasses: false,
		},
		{
			name:       "attribute appended beyond the declared length",
			datagram:   append(append([]byte{}, pristine...), unknown...),
			wantDecode: true,
			wantPasses: false,
		},
		{
			name:       "message truncated into the attributes",
			datagram:   withMessageLength(pristine[:len(pristine)-6]),
			wantDecode: false,
			wantPasses: false,
		},
		{
			name:       "declared length shortened without removing bytes",
			datagram:   withShortenedMessageLength(pristine, len(pristine)-messageHeaderSize-8),
			wantDecode: true,
			wantPasses: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			decoded := New()
			err := Decode(testCase.datagram, decoded)
			if !testCase.wantDecode {
				require.Error(t, err)
				assertDecodePathsReject(t, testCase.datagram)

				return
			}
			require.NoError(t, err)
			assertFramingMatchesReference(t, testCase.datagram)

			passes := key.Check(decoded) == nil && Fingerprint.Check(decoded) == nil
			assert.Equal(t, testCase.wantPasses, passes, "both authentication checks must agree")
			if passes {
				assert.Equal(t, pristine, testCase.datagram, "a passing datagram must be the authentic bytes")
			}
		})
	}
}

// withMessageLength rewrites the header length to cover exactly the present
// bytes, as a forger would when appending an attribute.
func withMessageLength(datagram []byte) []byte {
	rewritten := append([]byte{}, datagram...)
	binary.BigEndian.PutUint16(rewritten[2:4], uint16(len(rewritten)-messageHeaderSize)) //nolint:gosec // G115, test sizes.

	return rewritten
}

// withShortenedMessageLength sets a smaller header length while keeping buffer
// length as-is, so trailing attribute bytes would be reachable only by reading
// past the declared end.
func withShortenedMessageLength(datagram []byte, declaredLength int) []byte {
	rewritten := append([]byte{}, datagram...)
	binary.BigEndian.PutUint16(rewritten[2:4], uint16(declaredLength)) //nolint:gosec // G115, test sizes.

	return rewritten
}

// userhashForTest returns a USERHASH attribute used to give the authentic
// message a second attribute before MESSAGE-INTEGRITY.
func userhashForTest() RawAttribute {
	return RawAttribute{Type: AttrUserhash, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
}

// generatedDatagram deterministically builds a datagram from valid TLVs with a
// controlled amount of corruption: wrong header length, truncated values,
// forged attribute lengths, and trailing bytes.
func generatedDatagram(rng *rand.Rand) []byte {
	types := []AttrType{
		AttrSoftware, AttrUsername, AttrData, AttrMessageIntegrity,
		AttrMessageIntegritySHA256, AttrFingerprint, AttrType(0x9001), AttrType(0x0005),
	}

	attributes := make([]byte, 0, 64)
	for count := rng.Intn(5); count > 0; count-- {
		value := make([]byte, rng.Intn(9))
		_, _ = rng.Read(value) // math/rand never fails.
		padLength := alignToFour(len(value)) - len(value)
		padding := make([]byte, padLength)
		_, _ = rng.Read(padding) // math/rand never fails.
		declaredLength := len(value)
		if rng.Intn(4) == 0 {
			// Forged length field that does not match the value present.
			declaredLength = rng.Intn(alignToFour(len(value)) + 5)
		}
		attributes = append(attributes, encodeWireTLV(types[rng.Intn(len(types))], declaredLength, value, padding)...)
	}

	declaredLength := len(attributes)
	switch rng.Intn(8) {
	case 0:
		declaredLength += 1 + rng.Intn(4)
	case 1:
		declaredLength = rng.Intn(declaredLength + 1)
	case 2:
		declaredLength = rng.Intn(declaredLength + 5)
	}

	trailing := make([]byte, rng.Intn(9))
	_, _ = rng.Read(trailing) // math/rand never fails.

	datagram := makeDatagram(declaredLength, attributes, trailing)
	if rng.Intn(6) == 0 {
		// Cut the datagram somewhere, including inside the header.
		datagram = datagram[:rng.Intn(len(datagram)+1)]
	}

	return datagram
}

func TestFramingRandomizedAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20261117)) //nolint:gosec // Deterministic test input.
	for range 2000 {
		assertFramingMatchesReference(t, generatedDatagram(rng))
	}
}

func FuzzTLVFraming(f *testing.F) {
	software := encodeWireTLV(AttrSoftware, 3, []byte("abc"), []byte{0xAA})
	integrity := encodeWireTLV(AttrMessageIntegrity, messageIntegritySize, make([]byte, messageIntegritySize), nil)

	f.Add(software, int8(0), []byte{})
	f.Add(append(append([]byte{}, software...), integrity...), int8(0), []byte{})
	f.Add(software, int8(-1), []byte{0xFF})
	f.Add(software, int8(1), []byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add(encodeWireTLV(AttrSoftware, 5, []byte("abcde"), nil), int8(-8), []byte{})
	f.Add([]byte{0x80, 0x22, 0xFF, 0xFF}, int8(4), []byte{})
	f.Add([]byte{}, int8(0), []byte{})
	f.Add([]byte(nil), int8(-20), []byte{1, 2, 3})

	f.Fuzz(func(t *testing.T, payload []byte, declaredDelta int8, trailing []byte) {
		if len(payload) > 1024 || len(trailing) > 64 {
			return
		}
		declaredLength := len(payload) + int(declaredDelta)
		if declaredLength < 0 || declaredLength > 0xFFFF {
			return
		}
		assertFramingMatchesReference(t, makeDatagram(declaredLength, payload, trailing))
	})
}

// forgeAttribute turns the fuzz plan into a mutated authentic datagram. Every
// decision is taken from plan bytes, so failures reproduce without extra state.
func forgeAttribute(plan, value, authentic []byte) []byte {
	byteAt := func(index int) byte {
		if index < len(plan) {
			return plan[index]
		}

		return 0
	}

	forgedTypes := []AttrType{
		AttrSoftware, AttrType(0x0005), AttrType(0x9001),
		AttrMessageIntegrity, AttrMessageIntegritySHA256, AttrFingerprint,
	}
	forgedType := forgedTypes[int(byteAt(0))%len(forgedTypes)]
	value = value[:min(len(value), 16)]
	padLength := alignToFour(len(value)) - len(value)
	padding := bytes.Repeat([]byte{byteAt(1)}, padLength)
	forgedTLV := encodeWireTLV(forgedType, len(value), value, padding)

	regionLength := len(authentic) - messageHeaderSize
	offset := messageHeaderSize + int(byteAt(2))%max(regionLength, 1)

	var mutated []byte
	switch byteAt(3) % 4 {
	case 0: // Insert the forged TLV at an arbitrary attribute boundary or not.
		mutated = append(append(append([]byte{}, authentic[:offset]...), forgedTLV...), authentic[offset:]...)
	case 1: // Append behind FINGERPRINT.
		mutated = append(append([]byte{}, authentic...), forgedTLV...)
	case 2: // Truncate the datagram.
		mutated = append([]byte{}, authentic[:offset]...)
	default: // Flip one bit inside the attribute region.
		mutated = append([]byte{}, authentic...)
		mutated[offset] ^= 1 << (byteAt(4) % 8)
	}

	if byteAt(5)&1 == 1 {
		mutated = withMessageLength(mutated)
	}

	return mutated
}

// authenticDatagram builds a fixed, correctly authenticated message. The fuzz
// target mutates this instead of mutating fuzzer supplied "authentic" bytes,
// because those may already be corrupted and a mutation can then undo the
// corruption instead of introducing one.
func authenticDatagram(tb testing.TB, recipe byte) []byte {
	tb.Helper()
	setters := []Setter{
		NewTransactionIDSetter([TransactionIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}),
		NewSoftware("pion/stun"),
		RawAttribute{Type: AttrUserhash, Value: []byte{1, 2, 3, 4}},
		NewShortTermIntegrity(testPassword),
		Fingerprint,
	}
	if recipe&1 == 1 {
		setters = append([]Setter{NewSoftware("first"), RawAttribute{Type: 0x9001, Value: []byte{0xAA}}}, setters...)
	}
	message := new(Message)
	require.NoError(tb, message.Build(setters...))

	return append([]byte{}, message.Raw...)
}

func FuzzForgedAttributeFraming(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 1, 4, 0, 0, 0},
		{2, 3, 0, 1, 1, 1},
		{4, 5, 7, 2, 6, 0},
		{1, 0, 9, 3, 7, 1},
		{5, 2, 33, 0, 7, 1},
	} {
		f.Add(seed, []byte{1, 2, 3})
	}

	f.Fuzz(func(t *testing.T, plan, value []byte) {
		if len(plan) < 6 {
			return
		}
		authentic := authenticDatagram(t, plan[6%len(plan)])
		mutated := forgeAttribute(plan, value, authentic)
		if len(mutated) < messageHeaderSize {
			return
		}

		decoded := New()
		if err := Decode(mutated, decoded); err != nil {
			return
		}
		integrityOK := NewShortTermIntegrity(testPassword).Check(decoded) == nil
		fingerprintOK := Fingerprint.Check(decoded) == nil
		if !integrityOK || !fingerprintOK {
			return
		}
		require.Equal(t, authentic, mutated, "a forged datagram must not pass both authentication checks")
	})
}
