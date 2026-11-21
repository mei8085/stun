// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"errors"
)

// STUN Password Algorithms, as defined by RFC 8489 Section 18.5.
const (
	// PasswordAlgorithmReserved is the reserved 0x0000 algorithm number.
	PasswordAlgorithmReserved PasswordAlgorithm = 0x0000
	// PasswordAlgorithmMD5 derives a 16-byte key as
	// MD5(username ":" realm ":" password). It MUST only be used for
	// compatibility with legacy systems.
	PasswordAlgorithmMD5 PasswordAlgorithm = 0x0001
	// PasswordAlgorithmSHA256 derives a 32-byte key as
	// SHA-256(username ":" realm ":" password).
	PasswordAlgorithmSHA256 PasswordAlgorithm = 0x0002
)

// PasswordAlgorithm is a STUN Password Algorithm number from the IANA
// "STUN Password Algorithms" registry (RFC 8489 Section 18.5).
type PasswordAlgorithm uint16

// String returns the name of the algorithm, or its hex representation when
// the algorithm number is unknown.
func (a PasswordAlgorithm) String() string {
	switch a {
	case PasswordAlgorithmReserved:
		return "Reserved"
	case PasswordAlgorithmMD5:
		return "MD5"
	case PasswordAlgorithmSHA256:
		return "SHA-256"
	default:
		return "0x" + hex4(uint16(a))
	}
}

// keySize returns the long-term key length produced by the algorithm, or -1
// when the algorithm number is unknown.
func (a PasswordAlgorithm) keySize() int {
	switch a {
	case PasswordAlgorithmMD5:
		return md5.Size
	case PasswordAlgorithmSHA256:
		return sha256.Size
	default:
		return -1
	}
}

// PasswordAlgorithmValue is one entry of a PASSWORD-ALGORITHM(S) attribute:
// an algorithm number together with its (possibly empty) parameters.
//
// RFC 8489 Sections 14.11 and 14.12.
type PasswordAlgorithmValue struct {
	Algorithm  PasswordAlgorithm
	Parameters []byte
}

// ErrPasswordAlgorithmSize means that the PASSWORD-ALGORITHM or
// PASSWORD-ALGORITHMS attribute value is malformed.
var ErrPasswordAlgorithmSize = errors.New("bad PASSWORD-ALGORITHM size")

// header of one algorithm entry: 16-bit algorithm number and 16-bit
// parameters length.
const passwordAlgorithmHeaderSize = 4

// AddToAs encodes the single algorithm entry into attribute attrType.
func (v PasswordAlgorithmValue) AddToAs(m *Message, attrType AttrType) error {
	value := make([]byte, 0, passwordAlgorithmHeaderSize+nearestPaddedValueLength(len(v.Parameters)))
	value = bin.AppendUint16(value, uint16(v.Algorithm))
	value = bin.AppendUint16(value, uint16(len(v.Parameters)))
	value = append(value, v.Parameters...)
	for len(value)%padding != 0 {
		value = append(value, 0)
	}
	m.Add(attrType, value)

	return nil
}

// GetFromAs decodes a single algorithm entry from attribute attrType,
// ignoring padding.
func (v *PasswordAlgorithmValue) GetFromAs(m *Message, attrType AttrType) error {
	raw, err := m.Get(attrType)
	if err != nil {
		return err
	}
	if len(raw) < passwordAlgorithmHeaderSize {
		return ErrPasswordAlgorithmSize
	}
	paramLen := int(bin.Uint16(raw[2:4]))
	if passwordAlgorithmHeaderSize+nearestPaddedValueLength(paramLen) != len(raw) {
		return ErrPasswordAlgorithmSize
	}
	v.Algorithm = PasswordAlgorithm(bin.Uint16(raw[0:2]))
	v.Parameters = append(v.Parameters[:0], raw[passwordAlgorithmHeaderSize:passwordAlgorithmHeaderSize+paramLen]...)

	return nil
}

// PasswordAlgorithmAttr represents the PASSWORD-ALGORITHM attribute
// (0x001D), present only in requests. It contains the algorithm the server
// must use to derive the key from the long-term password.
//
// RFC 8489 Section 14.12.
type PasswordAlgorithmAttr = PasswordAlgorithmValue

// AddTo adds the PASSWORD-ALGORITHM attribute to m.
func (v PasswordAlgorithmAttr) AddTo(m *Message) error {
	return PasswordAlgorithmValue(v).AddToAs(m, AttrPasswordAlgorithm)
}

// GetFrom decodes the PASSWORD-ALGORITHM attribute from m.
func (v *PasswordAlgorithmAttr) GetFrom(m *Message) error {
	return (*PasswordAlgorithmValue)(v).GetFromAs(m, AttrPasswordAlgorithm)
}

// NewPasswordAlgorithm returns a PASSWORD-ALGORITHM attribute for algorithm
// with empty parameters, as used by the MD5 and SHA-256 algorithms.
func NewPasswordAlgorithm(algorithm PasswordAlgorithm) PasswordAlgorithmAttr {
	return PasswordAlgorithmAttr{Algorithm: algorithm}
}

// PasswordAlgorithms represents the PASSWORD-ALGORITHMS attribute (0x8002),
// the list of algorithms a server can use to derive the long-term password,
// in preferential order.
//
// RFC 8489 Section 14.11.
type PasswordAlgorithms []PasswordAlgorithmValue

// AddTo adds the PASSWORD-ALGORITHMS attribute to m.
func (a PasswordAlgorithms) AddTo(m *Message) error {
	value := make([]byte, 0, len(a)*passwordAlgorithmHeaderSize)
	for _, entry := range a {
		value = bin.AppendUint16(value, uint16(entry.Algorithm))
		value = bin.AppendUint16(value, uint16(len(entry.Parameters)))
		value = append(value, entry.Parameters...)
		for len(value)%padding != 0 {
			value = append(value, 0)
		}
	}
	m.Add(AttrPasswordAlgorithms, value)

	return nil
}

// GetFrom decodes the PASSWORD-ALGORITHMS attribute from m.
func (a *PasswordAlgorithms) GetFrom(m *Message) error {
	raw, err := m.Get(AttrPasswordAlgorithms)
	if err != nil {
		return err
	}
	*a = (*a)[:0]
	for offset := 0; offset < len(raw); {
		if len(raw)-offset < passwordAlgorithmHeaderSize {
			return ErrPasswordAlgorithmSize
		}
		algorithm := PasswordAlgorithm(bin.Uint16(raw[offset : offset+2]))
		paramLen := int(bin.Uint16(raw[offset+2 : offset+4]))
		end := offset + passwordAlgorithmHeaderSize + paramLen
		if end > len(raw) || offset+passwordAlgorithmHeaderSize+nearestPaddedValueLength(paramLen) > len(raw) {
			return ErrPasswordAlgorithmSize
		}
		params := make([]byte, paramLen)
		copy(params, raw[offset+passwordAlgorithmHeaderSize:end])
		*a = append(*a, PasswordAlgorithmValue{Algorithm: algorithm, Parameters: params})
		offset += passwordAlgorithmHeaderSize + nearestPaddedValueLength(paramLen)
	}

	return nil
}

// Contains reports whether algorithm is listed in a with identical
// parameters.
func (a PasswordAlgorithms) Contains(algorithm PasswordAlgorithmValue) bool {
	for _, entry := range a {
		if entry.Algorithm != algorithm.Algorithm {
			continue
		}
		if string(entry.Parameters) == string(algorithm.Parameters) {
			return true
		}
	}

	return false
}

// hex4 returns the 4-digit lowercase hex representation of v.
func hex4(v uint16) string {
	const digits = "0123456789abcdef"

	return string([]byte{
		digits[(v>>12)&0xf],
		digits[(v>>8)&0xf],
		digits[(v>>4)&0xf],
		digits[v&0xf],
	})
}
