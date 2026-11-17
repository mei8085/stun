// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This file exercises MAPPED-ADDRESS and XOR-MAPPED-ADDRESS across the three
// boundaries an address value crosses:
//
//  1. Attribute decoding: the address family selects the encoded length
//     (4 + 4 for IPv4, 4 + 16 for IPv6) and is interpreted only inside the
//     declared attribute value, never borrowing bytes from the next
//     attribute or from padding.
//  2. Authentication coverage: when a message carries MESSAGE-INTEGRITY or
//     FINGERPRINT, the address bytes belong to an authenticated range.
//     Decoding or re-encoding an address must not flip a trust conclusion
//     for the same datagram.
//  3. Re-serialization: decoding then encoding a message must preserve the
//     attribute view and must not turn unauthenticated bytes into an
//     authenticated message.
//
// The cases cover IPv4/IPv6 switching, short and overlong ("odd") values,
// truncated padding, unknown address families and duplicated attributes.

// addrBoundaryTID is a fixed transaction ID so XOR-mapped values can be
// computed by hand in the expectations.
func addrBoundaryTID() [TransactionIDSize]byte {
	return [TransactionIDSize]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76}
}

// newAddrBoundaryMessage returns a Binding success message with a written
// header, ready to accept attributes.
func newAddrBoundaryMessage() *Message {
	m := New()
	m.Type = BindingSuccess
	m.TransactionID = addrBoundaryTID()
	m.WriteHeader()

	return m
}

// decodeAddrBoundary decodes raw into a fresh Message.
func decodeAddrBoundary(tb testing.TB, raw []byte) (*Message, error) {
	tb.Helper()
	m := New()
	err := Decode(raw, m)

	return m, err
}

// addrBoundaryValue builds a MAPPED-ADDRESS style value: family, port, IP.
func addrBoundaryValue(family uint16, port int, ip []byte) []byte {
	value := make([]byte, 4+len(ip))
	bin.PutUint16(value[0:2], family)
	bin.PutUint16(value[2:4], uint16(port)) //nolint:gosec // G115
	copy(value[4:], ip)

	return value
}

// xorAddrBoundaryValue builds an XOR-MAPPED-ADDRESS style value using the
// same masking the package uses on the wire.
func xorAddrBoundaryValue(tid [TransactionIDSize]byte, family uint16, port int, ip []byte) []byte {
	value := addrBoundaryValue(family, 0, ip)
	//nolint:gosec // G115
	bin.PutUint16(value[2:4], uint16(port^(magicCookie>>16)))
	xorValue := make([]byte, 4+TransactionIDSize)
	bin.PutUint32(xorValue[0:4], magicCookie)
	copy(xorValue[4:], tid[:])
	for i := range ip {
		value[4+i] ^= xorValue[i]
	}

	return value
}

// addrFamilyIPLen is the number of address bytes the wire format carries for
// a family; the value itself is always 4 bytes of family/port plus this.
func addrFamilyIPLen(family uint16) int {
	if family == familyIPv6 {
		return net.IPv6len
	}

	return net.IPv4len
}

// expectPartialAddress checks that ip holds exactly the bytes derivable from
// the available value bytes and zero elsewhere. It proves the decoder never
// interpreted padding or a neighboring attribute as address bytes.
func expectPartialAddress(tb testing.TB, family uint16, ip net.IP, value []byte, xor bool) {
	tb.Helper()
	wantLen := addrFamilyIPLen(family)
	assert.Len(tb, ip, wantLen, "address length must be selected by the family")

	available := min(len(value)-4, wantLen)
	xorValue := make([]byte, 4+TransactionIDSize)
	bin.PutUint32(xorValue[0:4], magicCookie)
	tid := addrBoundaryTID()
	copy(xorValue[4:], tid[:])
	for i := range wantLen {
		var want byte
		if i < available {
			want = value[4+i]
			if xor {
				want ^= xorValue[i]
			}
		}
		assert.Equalf(tb, want, ip[i], "byte %d of address must come only from the attribute value", i)
	}
}

// TestAddrFamilyDecodeMatrix pins the exact address produced by each family
// and attribute type, both from a value built on the wire and from a value
// produced by the encoder.
func TestAddrFamilyDecodeMatrix(t *testing.T) {
	ipv4 := net.IPv4(203, 0, 113, 9).To4()
	ipv6 := net.ParseIP("2001:db8:1234:5678:9abc:def0:1122:3344")
	ipv4in16 := net.ParseIP("203.0.113.9")
	assert.Len(t, ipv4in16, net.IPv6len, "net.ParseIP returns 16-byte IPv4-in-IPv6 form")

	cases := []struct {
		name   string
		family uint16
		ip     []byte
	}{
		{"ipv4", familyIPv4, ipv4},
		{"ipv6", familyIPv6, ipv6},
	}

	for _, testCase := range cases {
		t.Run("MAPPED-ADDRESS/"+testCase.name, func(t *testing.T) {
			m := newAddrBoundaryMessage()
			m.Add(AttrMappedAddress, addrBoundaryValue(testCase.family, 54821, testCase.ip))
			raw := append([]byte(nil), m.Raw...)

			decoded, err := decodeAddrBoundary(t, raw)
			assert.NoError(t, err)

			got := new(MappedAddress)
			assert.NoError(t, got.GetFrom(decoded))
			assert.Equal(t, 54821, got.Port)
			assert.Truef(t, got.IP.Equal(testCase.ip), "got %v, want %v", got.IP, testCase.ip)
			assert.Len(t, got.IP, addrFamilyIPLen(testCase.family))
		})

		t.Run("XOR-MAPPED-ADDRESS/"+testCase.name, func(t *testing.T) {
			m := newAddrBoundaryMessage()
			m.Add(AttrXORMappedAddress, xorAddrBoundaryValue(m.TransactionID, testCase.family, 54821, testCase.ip))
			raw := append([]byte(nil), m.Raw...)

			decoded, err := decodeAddrBoundary(t, raw)
			assert.NoError(t, err)

			got := new(XORMappedAddress)
			assert.NoError(t, got.GetFrom(decoded))
			assert.Equal(t, 54821, got.Port)
			assert.Truef(t, got.IP.Equal(testCase.ip), "got %v, want %v", got.IP, testCase.ip)
			assert.Len(t, got.IP, addrFamilyIPLen(testCase.family))
		})
	}

	t.Run("encoder picks family and length", func(t *testing.T) {
		// A 16-byte IPv4-in-IPv6 net.IP must be encoded as IPv4 (family 1,
		// 8-byte value), never as an IPv6 address with a duplicated IPv4 tail.
		for name, ip := range map[string]net.IP{"ipv4-in-16": ipv4in16, "ipv4-4": ipv4} {
			m := newAddrBoundaryMessage()
			assert.NoError(t, (&MappedAddress{IP: ip, Port: 7}).AddTo(m))
			value, err := m.Get(AttrMappedAddress)
			assert.NoError(t, err, name)
			assert.Equal(t, familyIPv4, bin.Uint16(value[0:2]), name)
			assert.Len(t, value, 8, name)

			m = newAddrBoundaryMessage()
			assert.NoError(t, (&XORMappedAddress{IP: ip, Port: 7}).AddTo(m))
			value, err = m.Get(AttrXORMappedAddress)
			assert.NoError(t, err, name)
			assert.Equal(t, familyIPv4, bin.Uint16(value[0:2]), name)
			assert.Len(t, value, 8, name)
		}

		m := newAddrBoundaryMessage()
		assert.NoError(t, (&MappedAddress{IP: ipv6, Port: 7}).AddTo(m))
		value, err := m.Get(AttrMappedAddress)
		assert.NoError(t, err)
		assert.Equal(t, familyIPv6, bin.Uint16(value[0:2]))
		assert.Len(t, value, 20)

		m = newAddrBoundaryMessage()
		assert.NoError(t, (&XORMappedAddress{IP: ipv6, Port: 7}).AddTo(m))
		value, err = m.Get(AttrXORMappedAddress)
		assert.NoError(t, err)
		assert.Equal(t, familyIPv6, bin.Uint16(value[0:2]))
		assert.Len(t, value, 20)

		assert.ErrorIs(t, (&MappedAddress{IP: []byte{1, 2, 3, 4, 5}, Port: 7}).AddTo(newAddrBoundaryMessage()), ErrBadIPLength)
		assert.ErrorIs(t, (&XORMappedAddress{IP: []byte{1, 2, 3}, Port: 7}).AddTo(newAddrBoundaryMessage()), ErrBadIPLength)
	})
}

// checkAddrValueLength decodes one attribute value of the given length and
// asserts that the resulting address is built only from the attribute's own
// bytes.
func checkAddrValueLength(t *testing.T, attr AttrType, family uint16, length int) {
	t.Helper()
	const neighborValue = "neighbor"
	isXOR := attr == AttrXORMappedAddress

	value := make([]byte, length)
	if length >= 2 {
		bin.PutUint16(value[0:2], family)
	}
	if length >= 4 {
		bin.PutUint16(value[2:4], 60000)
	}
	for i := 4; i < length; i++ {
		// 0xa5 is used for every address byte; the padding is zero so any
		// non-zero contribution proves cross-reading.
		value[i] = 0xa5
	}

	m := newAddrBoundaryMessage()
	m.Add(attr, value)
	m.Add(AttrSoftware, []byte(neighborValue))
	raw := append([]byte(nil), m.Raw...)

	decoded, err := decodeAddrBoundary(t, raw)
	assert.NoErrorf(t, err, "%s len=%d: the message itself must stay decodable", attr, length)

	// The neighboring attribute is never consumed by address decoding,
	// regardless of the address value length.
	var software Software
	assert.NoErrorf(t, software.GetFrom(decoded), "%s len=%d: neighbor must survive", attr, length)
	assert.Equalf(t, neighborValue, software.String(), "%s len=%d: neighbor value changed", attr, length)

	var (
		getErr  error
		gotIP   net.IP
		gotPort int
	)
	if isXOR {
		got := new(XORMappedAddress)
		getErr, gotIP, gotPort = got.GetFrom(decoded), got.IP, got.Port
	} else {
		got := new(MappedAddress)
		getErr, gotIP, gotPort = got.GetFrom(decoded), got.IP, got.Port
	}

	if length <= 4 {
		// Family and port cannot be parsed at all.
		assert.Equalf(t, io.ErrUnexpectedEOF, getErr, "%s len=%d: expected EOF", attr, length)
		assert.Nilf(t, gotIP, "%s len=%d: no address may be produced", attr, length)

		return
	}

	if isXOR && length-4 > addrFamilyIPLen(family) {
		// XOR decoding rejects values wider than the family and does so
		// without touching the following attribute or reporting a
		// half-decoded address.
		assert.Truef(t, IsAttrSizeOverflow(getErr),
			"%s len=%d: overlong value must report overflow, got %v", attr, length, getErr)
		assert.Zerof(t, gotPort, "%s len=%d: port must not be decoded", attr, length)
		assert.Truef(t, isZeros(gotIP), "%s len=%d: rejected address must not be half written", attr, length)

		return
	}

	// MAPPED-ADDRESS (and XOR within the family size) accepts the value and
	// reads at most one family's worth of address bytes; any surplus stays
	// unread and cannot reach a neighbor.
	assert.NoErrorf(t, getErr, "%s len=%d", attr, length)
	expectPartialAddress(t, family, gotIP, value, isXOR)
	wantPort := 60000
	if isXOR {
		wantPort ^= magicCookie >> 16
	}
	assert.Equalf(t, wantPort, gotPort, "%s len=%d: bad port", attr, length)
}

// TestAddrValueLengthBoundaries walks every value length around the two
// family sizes. Every failure must be an attribute-local error, the
// following attribute must stay intact and the address bytes must never be
// borrowed from outside the attribute value.
func TestAddrValueLengthBoundaries(t *testing.T) {
	for _, attr := range []AttrType{AttrMappedAddress, AttrXORMappedAddress} {
		for _, family := range []uint16{familyIPv4, familyIPv6} {
			for length := range 4 + net.IPv6len + 3 {
				checkAddrValueLength(t, attr, family, length)
			}
		}
	}
}

// TestAddrPaddingTruncation covers odd declared lengths: padding is never
// address data, and a datagram that ends before the required padding fails
// at the attribute boundary without producing a partial address.
func TestAddrPaddingTruncation(t *testing.T) {
	for _, family := range []uint16{familyIPv4, familyIPv6} {
		t.Run("padding is not address data", func(t *testing.T) {
			ipLen := addrFamilyIPLen(family)
			// Declared length one byte short of a full address: the final
			// (missing) address byte must stay zero even though three
			// padding bytes with a distinctive pattern follow.
			declared := 4 + ipLen - 1
			value := addrBoundaryValue(family, 4242, bytes.Repeat([]byte{0x5a}, ipLen-1))
			m := newAddrBoundaryMessage()
			m.Add(AttrMappedAddress, value)
			m.Add(AttrSoftware, []byte("after"))
			// Overwrite the zero padding with a pattern: it must not leak
			// into the decoded address.
			padStart := messageHeaderSize + attributeHeaderSize + declared
			for i := padStart; i < padStart+nearestPaddedValueLength(declared)-declared; i++ {
				m.Raw[i] = 0xa5
			}
			m.WriteHeader()

			decoded, err := decodeAddrBoundary(t, m.Raw)
			assert.NoError(t, err)
			got := new(MappedAddress)
			assert.NoError(t, got.GetFrom(decoded))
			assert.Len(t, got.IP, ipLen)
			for i := 0; i < ipLen-1; i++ {
				assert.Equalf(t, byte(0x5a), got.IP[i], "address byte %d", i)
			}
			assert.Zerof(t, got.IP[ipLen-1], "padding byte leaked into the address")
			assert.Equal(t, 4242, got.Port)
		})
	}

	t.Run("truncated padding fails at the attribute boundary", func(t *testing.T) {
		// Header declares an odd-length MAPPED-ADDRESS value whose 3 padding
		// bytes were cut off by the datagram end.
		raw := make([]byte, messageHeaderSize+attributeHeaderSize+5)
		bin.PutUint16(raw[0:2], BindingSuccess.Value())
		bin.PutUint16(raw[2:4], uint16(len(raw)-messageHeaderSize)) //nolint:gosec // G115
		bin.PutUint32(raw[4:8], magicCookie)
		tid := addrBoundaryTID()
		copy(raw[8:messageHeaderSize], tid[:])
		bin.PutUint16(raw[messageHeaderSize:], uint16(AttrMappedAddress))
		bin.PutUint16(raw[messageHeaderSize+2:], 5)
		copy(raw[messageHeaderSize+4:], []byte{0x00, 0x01, 0x10, 0x92, 0xc0})

		decoded, err := decodeAddrBoundary(t, raw)
		var decodeErr *DecodeErr
		assert.ErrorAs(t, err, &decodeErr)
		assert.True(t, decodeErr.IsPlaceChildren("value"), "failure must be reported at the attribute value boundary")
		assert.False(t, decoded.Contains(AttrMappedAddress), "no partial address may be exposed")
	})

	t.Run("truncated value does not leak into a following attribute", func(t *testing.T) {
		// Same attribute, but the message is cut in the middle of the value
		// while a full neighbor would follow in the original datagram.
		m := newAddrBoundaryMessage()
		m.Add(AttrMappedAddress, addrBoundaryValue(familyIPv4, 1, net.IPv4(198, 51, 100, 1).To4()))
		full := append([]byte(nil), m.Raw...)
		cut := append([]byte(nil), full[:messageHeaderSize+attributeHeaderSize+6]...)
		bin.PutUint16(cut[2:4], uint16(len(cut)-messageHeaderSize)) //nolint:gosec // G115

		decoded, err := decodeAddrBoundary(t, cut)
		assert.Error(t, err)
		assert.False(t, decoded.Contains(AttrMappedAddress))
	})
}

// TestAddrUnknownFamily checks that an address family outside {IPv4, IPv6}
// is rejected explicitly, with an attribute-local error, and without
// modifying the caller's address or the message's authentication state.
func TestAddrUnknownFamily(t *testing.T) {
	key := NewShortTermIntegrity("addr-unknown-family")
	for _, family := range []uint16{0, 0x0003, 0x00ff, 0x8000, 0xffff} {
		t.Run("MAPPED-ADDRESS", func(t *testing.T) {
			m := newAddrBoundaryMessage()
			m.Add(AttrMappedAddress, addrBoundaryValue(family, 42, []byte{192, 0, 2, 1}))
			assert.NoError(t, key.AddTo(m))
			assert.NoError(t, Fingerprint.AddTo(m))

			decoded, err := decodeAddrBoundary(t, m.Raw)
			assert.NoError(t, err)

			got := MappedAddress{IP: net.IPv4(10, 0, 0, 1).To4(), Port: 7}
			err = got.GetFrom(decoded)
			var decodeErr *DecodeErr
			assert.ErrorAsf(t, err, &decodeErr, "family %#x must be rejected", family)
			assert.Truef(t, decodeErr.IsPlaceChildren("family"), "family %#x: error must identify the family", family)
			assert.True(t, got.IP.Equal(net.IPv4(10, 0, 0, 1)), "receiver must not be mutated on rejection")
			assert.Equal(t, 7, got.Port)

			// A malformed address value is not authenticated data corruption:
			// the surrounding message still verifies as sent.
			assert.NoError(t, key.Check(decoded))
			assert.NoError(t, Fingerprint.Check(decoded))
		})

		t.Run("XOR-MAPPED-ADDRESS", func(t *testing.T) {
			m := newAddrBoundaryMessage()
			m.Add(AttrXORMappedAddress, xorAddrBoundaryValue(m.TransactionID, family, 42, []byte{192, 0, 2, 1}))
			assert.NoError(t, key.AddTo(m))
			assert.NoError(t, Fingerprint.AddTo(m))

			decoded, err := decodeAddrBoundary(t, m.Raw)
			assert.NoError(t, err)

			got := XORMappedAddress{IP: net.IPv4(10, 0, 0, 1).To4(), Port: 7}
			err = got.GetFrom(decoded)
			var decodeErr *DecodeErr
			assert.ErrorAsf(t, err, &decodeErr, "family %#x must be rejected", family)
			assert.Truef(t, decodeErr.IsPlaceChildren("family"), "family %#x: error must identify the family", family)
			assert.True(t, got.IP.Equal(net.IPv4(10, 0, 0, 1)), "receiver must not be mutated on rejection")
			assert.Equal(t, 7, got.Port)

			assert.NoError(t, key.Check(decoded))
			assert.NoError(t, Fingerprint.Check(decoded))
		})
	}
}

// TestAddrDuplicateAttributes covers repeated address attributes: the first
// occurrence is the one a getter sees, duplicates survive re-serialization
// byte-for-byte, and a first occurrence that cannot be interpreted (unknown
// family) fails the getter without changing the authentication conclusions or
// silently falling through to the second occurrence.
func TestAddrDuplicateAttributes(t *testing.T) {
	key := NewShortTermIntegrity("addr-duplicates")

	t.Run("first occurrence wins", func(t *testing.T) {
		m := newAddrBoundaryMessage()
		m.Add(AttrMappedAddress, addrBoundaryValue(familyIPv4, 1111, []byte{192, 0, 2, 1}))
		m.Add(AttrMappedAddress, addrBoundaryValue(familyIPv6, 2222, net.ParseIP("2001:db8::1")))
		m.Add(AttrXORMappedAddress, xorAddrBoundaryValue(m.TransactionID, familyIPv4, 3333, []byte{198, 51, 100, 2}))
		m.Add(AttrXORMappedAddress, xorAddrBoundaryValue(m.TransactionID, familyIPv6, 4444, net.ParseIP("2001:db8::2")))
		assert.NoError(t, key.AddTo(m))
		assert.NoError(t, Fingerprint.AddTo(m))
		raw := append([]byte(nil), m.Raw...)

		decoded, err := decodeAddrBoundary(t, raw)
		assert.NoError(t, err)
		assert.Equal(t, 6, len(decoded.Attributes), "duplicates must not be collapsed")

		mapped := new(MappedAddress)
		assert.NoError(t, mapped.GetFrom(decoded))
		assert.True(t, mapped.IP.Equal(net.IP{192, 0, 2, 1}))
		assert.Equal(t, 1111, mapped.Port)

		xor := new(XORMappedAddress)
		assert.NoError(t, xor.GetFrom(decoded))
		assert.True(t, xor.IP.Equal(net.IP{198, 51, 100, 2}))
		assert.Equal(t, 3333, xor.Port)

		// Authentication covers the raw bytes, duplicates included.
		assert.NoError(t, key.Check(decoded))
		assert.NoError(t, Fingerprint.Check(decoded))

		decoded.Encode()
		assert.True(t, bytes.Equal(raw, decoded.Raw), "re-encoding must reproduce duplicates verbatim")
		assert.NoError(t, key.Check(decoded))
		assert.NoError(t, Fingerprint.Check(decoded))
	})

	t.Run("unknown-family first occurrence does not fall through (MAPPED-ADDRESS)", func(t *testing.T) {
		m := newAddrBoundaryMessage()
		m.Add(AttrMappedAddress, addrBoundaryValue(0x0042, 5555, []byte{192, 0, 2, 9}))
		m.Add(AttrMappedAddress, addrBoundaryValue(familyIPv4, 5556, []byte{203, 0, 113, 3}))
		assert.NoError(t, key.AddTo(m))
		assert.NoError(t, Fingerprint.AddTo(m))
		raw := append([]byte(nil), m.Raw...)

		decoded, err := decodeAddrBoundary(t, raw)
		assert.NoError(t, err)

		mapped := new(MappedAddress)
		getErr := mapped.GetFrom(decoded)
		var decodeErr *DecodeErr
		assert.ErrorAs(t, getErr, &decodeErr, "the first duplicate has an unknown family; a getter must not silently use the second")
		assert.True(t, decodeErr.IsPlaceChildren("family"))
		assert.NotEqual(t, 5556, mapped.Port, "the second duplicate must not be used")

		// The unknown-family value was authenticated as-is: it must not
		// poison the trust conclusions, and re-encoding must not launder it.
		assert.NoError(t, key.Check(decoded))
		assert.NoError(t, Fingerprint.Check(decoded))
		decoded.Encode()
		assert.True(t, bytes.Equal(raw, decoded.Raw))
		assert.NoError(t, key.Check(decoded))
		assert.NoError(t, Fingerprint.Check(decoded))
	})

	t.Run("unknown-family first occurrence does not fall through", func(t *testing.T) {
		m := newAddrBoundaryMessage()
		m.Add(AttrXORMappedAddress, xorAddrBoundaryValue(m.TransactionID, 0x0042, 6666, []byte{192, 0, 2, 9}))
		m.Add(AttrXORMappedAddress, xorAddrBoundaryValue(m.TransactionID, familyIPv4, 7777, []byte{192, 0, 2, 10}))

		decoded, err := decodeAddrBoundary(t, m.Raw)
		assert.NoError(t, err)

		got := new(XORMappedAddress)
		err = got.GetFrom(decoded)
		var decodeErr *DecodeErr
		assert.ErrorAs(t, err, &decodeErr)
		assert.True(t, decodeErr.IsPlaceChildren("family"))
		assert.NotEqual(t, 7777, got.Port, "the second duplicate must not be used")
	})
}

// checkAuthLayers asserts the trust conclusions implied by the authentication
// layers declared in the message.
func checkAuthLayers(t *testing.T, key MessageIntegrity, msg *Message, integrity, fingerprint bool) {
	t.Helper()
	if integrity {
		assert.NoError(t, key.Check(msg))
	} else {
		assert.ErrorIs(t, key.Check(msg), ErrAttributeNotFound)
	}
	if fingerprint {
		assert.NoError(t, Fingerprint.Check(msg))
	} else {
		assert.ErrorIs(t, Fingerprint.Check(msg), ErrAttributeNotFound)
	}
}

// addrAuthLayer describes which authentication attributes a message carries.
type addrAuthLayer struct {
	name   string
	mi, fp bool
}

// runAddrReserializeCase drives one address/auth combination through the
// decode, check, re-encode and tamper sequence.
func runAddrReserializeCase(
	t *testing.T,
	key MessageIntegrity,
	build func(*Message) error,
	check func(testing.TB, *Message),
	layer addrAuthLayer,
) {
	t.Helper()
	m := newAddrBoundaryMessage()
	assert.NoError(t, build(m))
	if layer.mi {
		assert.NoError(t, key.AddTo(m))
	}
	if layer.fp {
		assert.NoError(t, Fingerprint.AddTo(m))
	}
	raw := append([]byte(nil), m.Raw...)

	decoded, err := decodeAddrBoundary(t, raw)
	assert.NoError(t, err)
	check(t, decoded)
	checkAuthLayers(t, key, decoded, layer.mi, layer.fp)

	decoded.Encode()
	assert.True(t, bytes.Equal(raw, decoded.Raw), "decode/encode must be byte-stable")
	check(t, decoded)
	checkAuthLayers(t, key, decoded, layer.mi, layer.fp)

	serialized, err := decoded.MarshalBinary()
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(raw, serialized))

	// Tampering with the address value must break authentication both
	// before and after re-serialization: encoding is not a way to obtain a
	// different trust conclusion.
	if !layer.mi && !layer.fp {
		return
	}
	tampered := append([]byte(nil), raw...)
	tampered[messageHeaderSize+attributeHeaderSize] ^= 0x01
	msg, err := decodeAddrBoundary(t, tampered)
	assert.NoError(t, err)
	msg.Encode()
	if layer.mi {
		assert.Error(t, key.Check(msg))
	}
	if layer.fp {
		assert.Error(t, Fingerprint.Check(msg))
	}
}

// TestAddrDecodeReserializeAuth is the cross-layer combination: for every
// address attribute and family, and for every authentication layer, the
// decoded address, the trust conclusions and the bytes survive a decode /
// encode cycle, and re-encoding cannot turn a tampered message into a valid
// one.
func TestAddrDecodeReserializeAuth(t *testing.T) {
	key := NewShortTermIntegrity("addr-reserialize")
	ipv4 := []byte{203, 0, 113, 9}
	ipv6 := net.ParseIP("2001:db8:1234:5678:9abc:def0:1122:3344")

	addresses := []struct {
		name  string
		build func(m *Message) error
		check func(tb testing.TB, m *Message)
	}{
		{
			"mapped-ipv4",
			func(m *Message) error {
				return (&MappedAddress{IP: ipv4, Port: 1111}).AddTo(m)
			},
			func(tb testing.TB, m *Message) {
				tb.Helper()
				got := new(MappedAddress)
				assert.NoError(tb, got.GetFrom(m))
				assert.True(tb, got.IP.Equal(ipv4))
				assert.Equal(tb, 1111, got.Port)
			},
		},
		{
			"mapped-ipv6",
			func(m *Message) error {
				return (&MappedAddress{IP: ipv6, Port: 2222}).AddTo(m)
			},
			func(tb testing.TB, m *Message) {
				tb.Helper()
				got := new(MappedAddress)
				assert.NoError(tb, got.GetFrom(m))
				assert.True(tb, got.IP.Equal(ipv6))
				assert.Equal(tb, 2222, got.Port)
			},
		},
		{
			"xor-ipv4",
			func(m *Message) error {
				return (&XORMappedAddress{IP: ipv4, Port: 3333}).AddTo(m)
			},
			func(tb testing.TB, m *Message) {
				tb.Helper()
				got := new(XORMappedAddress)
				assert.NoError(tb, got.GetFrom(m))
				assert.True(tb, got.IP.Equal(ipv4))
				assert.Equal(tb, 3333, got.Port)
			},
		},
		{
			"xor-ipv6",
			func(m *Message) error {
				return (&XORMappedAddress{IP: ipv6, Port: 4444}).AddTo(m)
			},
			func(tb testing.TB, m *Message) {
				tb.Helper()
				got := new(XORMappedAddress)
				assert.NoError(tb, got.GetFrom(m))
				assert.True(tb, got.IP.Equal(ipv6))
				assert.Equal(tb, 4444, got.Port)
			},
		},
	}

	layers := []addrAuthLayer{
		{"plain", false, false},
		{"integrity", true, false},
		{"fingerprint", false, true},
		{"integrity+fingerprint", true, true},
	}

	for _, address := range addresses {
		for _, layer := range layers {
			t.Run(address.name+"/"+layer.name, func(t *testing.T) {
				runAddrReserializeCase(t, key, address.build, address.check, layer)
			})
		}
	}
}

// TestAddrMalformedWithAuth checks that malformed address values (overlong,
// unknown family, short) never change the authentication verdict and that
// re-serializing such a message keeps the same verdict.
func TestAddrMalformedWithAuth(t *testing.T) {
	key := NewShortTermIntegrity("addr-malformed-auth")

	cases := []struct {
		name  string
		value []byte
		attr  AttrType
	}{
		{
			name:  "mapped overlong ipv4",
			attr:  AttrMappedAddress,
			value: []byte{0x00, 0x01, 0x10, 0x92, 192, 0, 2, 1, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:  "xor overlong ipv4",
			attr:  AttrXORMappedAddress,
			value: []byte{0x00, 0x01, 0x10, 0x92, 192, 0, 2, 1, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:  "mapped overlong ipv6",
			attr:  AttrMappedAddress,
			value: append([]byte{0x00, 0x02, 0x10, 0x92}, bytes.Repeat([]byte{0x11}, net.IPv6len+4)...),
		},
		{
			name:  "xor overlong ipv6",
			attr:  AttrXORMappedAddress,
			value: append([]byte{0x00, 0x02, 0x10, 0x92}, bytes.Repeat([]byte{0x11}, net.IPv6len+4)...),
		},
		{
			name:  "mapped unknown family",
			attr:  AttrMappedAddress,
			value: []byte{0x00, 0x07, 0x10, 0x92, 192, 0, 2, 1},
		},
		{
			name:  "xor unknown family",
			attr:  AttrXORMappedAddress,
			value: []byte{0x00, 0x07, 0x10, 0x92, 192, 0, 2, 1},
		},
		{
			name:  "mapped short ipv6",
			attr:  AttrMappedAddress,
			value: []byte{0x00, 0x02, 0x10, 0x92, 0x20, 0x01, 0x0d, 0xb8},
		},
		{
			name:  "xor short ipv6",
			attr:  AttrXORMappedAddress,
			value: []byte{0x00, 0x02, 0x10, 0x92, 0x20, 0x01, 0x0d, 0xb8},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			m := newAddrBoundaryMessage()
			m.Add(testCase.attr, testCase.value)
			m.Add(AttrSoftware, []byte("neighbor"))
			assert.NoError(t, key.AddTo(m))
			assert.NoError(t, Fingerprint.AddTo(m))
			raw := append([]byte(nil), m.Raw...)

			decoded, err := decodeAddrBoundary(t, raw)
			assert.NoError(t, err)
			assert.NoError(t, key.Check(decoded), "malformed address must not break integrity")
			assert.NoError(t, Fingerprint.Check(decoded))

			var software Software
			assert.NoError(t, software.GetFrom(decoded))
			assert.Equal(t, "neighbor", software.String())

			decoded.Encode()
			assert.True(t, bytes.Equal(raw, decoded.Raw), "re-encoding must be byte-stable for malformed addresses too")
			assert.NoError(t, key.Check(decoded))
			assert.NoError(t, Fingerprint.Check(decoded))

			// A mutation anywhere in the address value is still caught: the
			// malformed value is not excused from authentication.
			tampered := append([]byte(nil), raw...)
			tampered[messageHeaderSize+attributeHeaderSize] ^= 0x80
			msg, err := decodeAddrBoundary(t, tampered)
			assert.NoError(t, err)
			assert.Error(t, key.Check(msg))
			assert.Error(t, Fingerprint.Check(msg))
		})
	}
}

// TestAddrReserializeDoesNotLaunderTrust pins the requirement that the same
// message must not reach a different trust conclusion after re-encoding.
// A legal address attribute value is 8 or 20 bytes, i.e. already a multiple
// of the 4-byte alignment, so its TLV has no padding: decoding and encoding
// must be byte-exact and the check results must not move in either direction.
func TestAddrReserializeDoesNotLaunderTrust(t *testing.T) {
	key := NewShortTermIntegrity("addr-launder")

	values := map[string]func(*Message) error{
		"mapped-ipv4": func(m *Message) error {
			return (&MappedAddress{IP: net.IPv4(192, 0, 2, 77).To4(), Port: 4242}).AddTo(m)
		},
		"mapped-ipv6": func(m *Message) error {
			return (&MappedAddress{IP: net.ParseIP("2001:db8::77"), Port: 4243}).AddTo(m)
		},
		"xor-ipv4": func(m *Message) error {
			return (&XORMappedAddress{IP: net.IPv4(192, 0, 2, 78).To4(), Port: 4244}).AddTo(m)
		},
		"xor-ipv6": func(m *Message) error {
			return (&XORMappedAddress{IP: net.ParseIP("2001:db8::78"), Port: 4245}).AddTo(m)
		},
	}

	for name, build := range values {
		t.Run(name, func(t *testing.T) {
			m := newAddrBoundaryMessage()
			assert.NoError(t, build(m))
			assert.NoError(t, key.AddTo(m))
			assert.NoError(t, Fingerprint.AddTo(m))
			raw := append([]byte(nil), m.Raw...)

			decoded, err := decodeAddrBoundary(t, raw)
			assert.NoError(t, err)
			assert.NoError(t, key.Check(decoded))
			assert.NoError(t, Fingerprint.Check(decoded))

			decoded.Encode()
			assert.True(t, bytes.Equal(raw, decoded.Raw), "a legal address value must re-serialize byte-for-byte")
			assert.NoError(t, key.Check(decoded), "re-encoding must not invalidate an authentic message")
			assert.NoError(t, Fingerprint.Check(decoded))

			// The inverse direction: corrupting one authenticated byte must
			// stay visible after a decode/encode round trip.
			tampered := append([]byte(nil), raw...)
			tampered[messageHeaderSize+attributeHeaderSize+4] ^= 0xff
			msg, err := decodeAddrBoundary(t, tampered)
			assert.NoError(t, err)
			assert.Error(t, key.Check(msg))
			assert.Error(t, Fingerprint.Check(msg))
			msg.Encode()
			assert.Error(t, key.Check(msg), "re-encoding must not launder a tampered message")
			assert.Error(t, Fingerprint.Check(msg))
		})
	}
}

// TestAddrOddLengthPaddingReserialize characterizes what happens to an
// address TLV with a non-4-byte-aligned value length, whose padding bytes
// are authenticated (padding is inside the MESSAGE-INTEGRITY /
// FINGERPRINT range) but are not part of any attribute value.
//
// The encoder always writes zero padding. Decoding therefore cannot preserve
// arbitrary padding through Encode, which means a decode/encode cycle can
// move the trust conclusion for a message whose wire padding is non-zero.
// These assertions record the current behavior precisely so any change is
// visible; they are not an endorsement of it.
func TestAddrOddLengthPaddingReserialize(t *testing.T) {
	key := NewShortTermIntegrity("addr-odd-padding")

	// seal signs the currently assembled message and returns its bytes.
	seal := func(t *testing.T, m *Message) []byte {
		t.Helper()
		assert.NoError(t, key.AddTo(m))
		assert.NoError(t, Fingerprint.AddTo(m))

		return append([]byte(nil), m.Raw...)
	}

	t.Run("non-zero wire padding is normalized to zero", func(t *testing.T) {
		const valueLen = 9 // IPv4 header plus one surplus byte, 3 padding bytes
		m := newAddrBoundaryMessage()
		m.Add(AttrMappedAddress, []byte{0x00, 0x01, 0x10, 0x92, 192, 0, 2, 1, 0x99})
		padStart := messageHeaderSize + attributeHeaderSize + valueLen
		padLen := nearestPaddedValueLength(valueLen) - valueLen
		for i := padStart; i < padStart+padLen; i++ {
			m.Raw[i] = 0xa5
		}
		wired := seal(t, m)

		decoded, err := decodeAddrBoundary(t, wired)
		assert.NoError(t, err)
		assert.NoError(t, key.Check(decoded), "the sealed datagram including its padding is authentic")
		assert.NoError(t, Fingerprint.Check(decoded))

		decoded.Encode()
		assert.False(t, bytes.Equal(wired, decoded.Raw), "the encoder rewrites padding to zero")
		for i := padStart; i < padStart+padLen; i++ {
			assert.Zerof(t, decoded.Raw[i], "re-encoded padding byte %d must be zero", i)
		}
		// The rewritten bytes are inside both authenticated ranges, so the
		// checks no longer match the datagram that was sealed.
		assert.Error(t, key.Check(decoded))
		assert.Error(t, Fingerprint.Check(decoded))
	})

	t.Run("zero-padded datagram re-serializes byte-for-byte", func(t *testing.T) {
		m := newAddrBoundaryMessage()
		m.Add(AttrMappedAddress, []byte{0x00, 0x01, 0x10, 0x92, 192, 0, 2, 1, 0x99})
		wired := seal(t, m)

		decoded, err := decodeAddrBoundary(t, wired)
		assert.NoError(t, err)
		decoded.Encode()
		assert.True(t, bytes.Equal(wired, decoded.Raw))
		assert.NoError(t, key.Check(decoded))
		assert.NoError(t, Fingerprint.Check(decoded))
	})

	t.Run("legal values never carry padding", func(t *testing.T) {
		for _, family := range []uint16{familyIPv4, familyIPv6} {
			for _, attr := range []AttrType{AttrMappedAddress, AttrXORMappedAddress} {
				valueLen := 4 + addrFamilyIPLen(family)
				assert.Zerof(t, valueLen%padding,
					"%s family %d: a legal address value must need no padding", attr, family)
			}
		}
	})
}

// TestAddrFamilySwitchOnReusedReceiver checks the IPv4/IPv6 switch on a
// reused address value: decoding must re-select the length from the family
// of the current value, must not keep the previous family's bytes, and a
// rejected value must not leave the receiver looking like a successful
// decode of a different family.
func TestAddrFamilySwitchOnReusedReceiver(t *testing.T) {
	ipv4 := []byte{203, 0, 113, 41}
	ipv6 := net.ParseIP("2001:db8::dead:beef")

	build := func(tb testing.TB, attr AttrType, family uint16, port int, ip []byte) *Message {
		tb.Helper()
		m := newAddrBoundaryMessage()
		if attr == AttrXORMappedAddress {
			m.Add(attr, xorAddrBoundaryValue(m.TransactionID, family, port, ip))
		} else {
			m.Add(attr, addrBoundaryValue(family, port, ip))
		}
		decoded, err := decodeAddrBoundary(tb, m.Raw)
		assert.NoError(tb, err)

		return decoded
	}

	// checkSwitch runs the IPv4 -> IPv6 -> IPv4 sequence and verifies that
	// the receiver re-selects its length from the family of each value.
	checkSwitch := func(t *testing.T, attr AttrType, get func(*Message) (net.IP, int, error), firstPort int) {
		t.Helper()
		steps := []struct {
			family uint16
			ip     []byte
			port   int
		}{
			{familyIPv4, ipv4, firstPort},
			{familyIPv6, ipv6, firstPort + 1},
			{familyIPv4, ipv4, firstPort + 2},
		}
		for i, step := range steps {
			gotIP, gotPort, err := get(build(t, attr, step.family, step.port, step.ip))
			assert.NoError(t, err)
			assert.Equalf(t, addrFamilyIPLen(step.family), len(gotIP), "step %d: address length", i)
			assert.Truef(t, gotIP.Equal(step.ip),
				"step %d: family %d must replace the whole address, not a prefix", i, step.family)
			assert.Equalf(t, step.port, gotPort, "step %d: port", i)
		}
	}

	t.Run("MAPPED-ADDRESS", func(t *testing.T) {
		checkSwitch(t, AttrMappedAddress, func(m *Message) (net.IP, int, error) {
			got := new(MappedAddress)
			err := got.GetFrom(m)

			return got.IP, got.Port, err
		}, 1001)
	})

	t.Run("XOR-MAPPED-ADDRESS", func(t *testing.T) {
		checkSwitch(t, AttrXORMappedAddress, func(m *Message) (net.IP, int, error) {
			got := new(XORMappedAddress)
			err := got.GetFrom(m)

			return got.IP, got.Port, err
		}, 2001)
	})

	t.Run("rejected value leaves the receiver untouched", func(t *testing.T) {
		bad := newAddrBoundaryMessage()
		bad.Add(AttrMappedAddress, addrBoundaryValue(0x0009, 9999, ipv4))
		badMapped, err := decodeAddrBoundary(t, bad.Raw)
		assert.NoError(t, err)

		mapped := MappedAddress{IP: ipv6, Port: 4242}
		assert.Error(t, mapped.GetFrom(badMapped), "unknown family must be rejected")
		assert.True(t, mapped.IP.Equal(ipv6), "address must survive a rejected decode")
		assert.Equal(t, 4242, mapped.Port, "port must survive a rejected decode")

		badXOR := newAddrBoundaryMessage()
		badXOR.Add(AttrXORMappedAddress, xorAddrBoundaryValue(badXOR.TransactionID, 0x0009, 9999, ipv4))
		badXORDecoded, err := decodeAddrBoundary(t, badXOR.Raw)
		assert.NoError(t, err)

		xor := XORMappedAddress{IP: ipv6, Port: 4243}
		assert.Error(t, xor.GetFrom(badXORDecoded), "unknown family must be rejected")
		assert.True(t, xor.IP.Equal(ipv6), "address must survive a rejected decode")
		assert.Equal(t, 4243, xor.Port, "port must survive a rejected decode")
	})
}

// TestAddrGetFromAfterDecodeError documents that address decoding never
// reads past the declared message boundary: a datagram whose last address
// attribute claims more bytes than remain fails message decoding, so no
// address value is exposed at all.
func TestAddrGetFromAfterDecodeError(t *testing.T) {
	for _, attr := range []AttrType{AttrMappedAddress, AttrXORMappedAddress} {
		for _, family := range []uint16{familyIPv4, familyIPv6} {
			// Attribute header declares the full family size, but the
			// datagram stops inside the value.
			declared := 4 + addrFamilyIPLen(family)
			raw := make([]byte, messageHeaderSize+attributeHeaderSize+declared-1)
			bin.PutUint16(raw[0:2], BindingSuccess.Value())
			bin.PutUint16(raw[2:4], uint16(len(raw)-messageHeaderSize)) //nolint:gosec // G115
			bin.PutUint32(raw[4:8], magicCookie)
			tid := addrBoundaryTID()
			copy(raw[8:messageHeaderSize], tid[:])
			bin.PutUint16(raw[messageHeaderSize:], uint16(attr))
			bin.PutUint16(raw[messageHeaderSize+2:], uint16(declared)) //nolint:gosec // G115
			bin.PutUint16(raw[messageHeaderSize+4:], family)

			decoded, err := decodeAddrBoundary(t, raw)
			assert.Error(t, err)
			var decodeErr *DecodeErr
			assert.ErrorAs(t, err, &decodeErr)
			assert.True(t, decodeErr.IsPlaceChildren("value"))

			var getErr error
			if attr == AttrXORMappedAddress {
				got := new(XORMappedAddress)
				getErr = got.GetFrom(decoded)
			} else {
				got := new(MappedAddress)
				getErr = got.GetFrom(decoded)
			}
			assert.ErrorIs(t, getErr, ErrAttributeNotFound, "truncated attribute must not surface a value")
			assert.False(t, errors.Is(getErr, io.ErrUnexpectedEOF))
		}
	}
}

// TestAddrSharedDecoderAttributes checks that the attributes reusing the
// MappedAddress codec (ALTERNATE-SERVER, OTHER-ADDRESS, RESPONSE-ORIGIN) obey
// the same family and length rules, so a boundary bug cannot hide in one
// attribute type while another passes.
func TestAddrSharedDecoderAttributes(t *testing.T) {
	key := NewShortTermIntegrity("addr-shared")
	ipv6 := net.ParseIP("2001:db8::abc")

	attrs := []struct {
		name    string
		attr    AttrType
		adder   func(*Message) error
		getFrom func(*Message) error
	}{
		{
			"ALTERNATE-SERVER",
			AttrAlternateServer,
			func(m *Message) error { return (&AlternateServer{IP: ipv6, Port: 3478}).AddTo(m) },
			func(m *Message) error { return (&AlternateServer{}).GetFrom(m) },
		},
		{
			"OTHER-ADDRESS",
			AttrOtherAddress,
			func(m *Message) error { return (&OtherAddress{IP: ipv6, Port: 3479}).AddTo(m) },
			func(m *Message) error { return (&OtherAddress{}).GetFrom(m) },
		},
		{
			"RESPONSE-ORIGIN",
			AttrResponseOrigin,
			func(m *Message) error { return (&ResponseOrigin{IP: ipv6, Port: 3480}).AddTo(m) },
			func(m *Message) error { return (&ResponseOrigin{}).GetFrom(m) },
		},
	}

	for _, testCase := range attrs {
		t.Run(testCase.name, func(t *testing.T) {
			// Valid IPv6 round trip.
			m := newAddrBoundaryMessage()
			assert.NoError(t, testCase.adder(m))
			assert.NoError(t, key.AddTo(m))
			assert.NoError(t, Fingerprint.AddTo(m))
			raw := append([]byte(nil), m.Raw...)

			decoded, err := decodeAddrBoundary(t, raw)
			assert.NoError(t, err)
			assert.NoError(t, key.Check(decoded))
			assert.NoError(t, Fingerprint.Check(decoded))

			value, err := decoded.Get(testCase.attr)
			assert.NoError(t, err)
			assert.Equal(t, familyIPv6, bin.Uint16(value[0:2]))
			assert.Len(t, value, 4+net.IPv6len)

			decoded.Encode()
			assert.True(t, bytes.Equal(raw, decoded.Raw))

			// Unknown family is rejected by the shared decoder.
			bad := newAddrBoundaryMessage()
			bad.Add(testCase.attr, addrBoundaryValue(0x0005, 3481, []byte{192, 0, 2, 1}))
			badDecoded, err := decodeAddrBoundary(t, bad.Raw)
			assert.NoError(t, err)
			assert.Error(t, testCase.getFrom(badDecoded))

			// An overlong value does not consume the neighbor.
			overlong := newAddrBoundaryMessage()
			overlong.Add(testCase.attr, append(addrBoundaryValue(familyIPv4, 3482, []byte{192, 0, 2, 2}),
				[]byte{0xde, 0xad, 0xbe, 0xef}...))
			overlong.Add(AttrSoftware, []byte("neighbor"))
			overDecoded, err := decodeAddrBoundary(t, overlong.Raw)
			assert.NoError(t, err)
			var software Software
			assert.NoError(t, software.GetFrom(overDecoded))
			assert.Equal(t, "neighbor", software.String())
		})
	}
}

// TestAddrLegacyXorAttributeAlias covers the RFC 3489-era 0x8020 type that
// compatAttrType rewrites to XOR-MAPPED-ADDRESS: the rewritten attribute must
// decode under exactly the same family and authentication rules as 0x0020.
func TestAddrLegacyXorAttributeAlias(t *testing.T) {
	key := NewShortTermIntegrity("addr-alias")
	const legacyType = 0x8020

	for _, family := range []uint16{familyIPv4, familyIPv6} {
		ip := []byte{192, 0, 2, 31}
		if family == familyIPv6 {
			ip = net.ParseIP("2001:db8::31")
		}

		m := newAddrBoundaryMessage()
		m.Add(legacyType, xorAddrBoundaryValue(m.TransactionID, family, 1234, ip))
		assert.NoError(t, key.AddTo(m))
		assert.NoError(t, Fingerprint.AddTo(m))
		raw := append([]byte(nil), m.Raw...)

		decoded, err := decodeAddrBoundary(t, raw)
		assert.NoError(t, err)
		assert.True(t, decoded.Contains(AttrXORMappedAddress), "legacy type must be visible as XOR-MAPPED-ADDRESS")

		got := new(XORMappedAddress)
		assert.NoError(t, got.GetFrom(decoded))
		assert.Truef(t, got.IP.Equal(ip), "family %d: got %v", family, got.IP)
		assert.Equal(t, 1234, got.Port)
		assert.NoError(t, key.Check(decoded))
		assert.NoError(t, Fingerprint.Check(decoded))

		// An unknown family behind the legacy type is rejected the same way.
		bad := newAddrBoundaryMessage()
		bad.Add(legacyType, xorAddrBoundaryValue(bad.TransactionID, 0x0077, 1234, ip))
		badDecoded, err := decodeAddrBoundary(t, bad.Raw)
		assert.NoError(t, err)
		badAddr := new(XORMappedAddress)
		err = badAddr.GetFrom(badDecoded)
		var decodeErr *DecodeErr
		assert.ErrorAs(t, err, &decodeErr)
		assert.True(t, decodeErr.IsPlaceChildren("family"))
	}
}
