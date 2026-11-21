// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/pion/stun/v5/internal/hmac"
)

// separator for credentials.
const credentialsSep = ":"

// NewLongTermIntegrity returns new MessageIntegrity with key for long-term
// credentials. Password, username, and realm must be SASL-prepared.
//
// The key is the 16-byte MD5 hash defined by RFC 8489 Section 9.2.2:
//
//	key = MD5(username ":" realm ":" password)
func NewLongTermIntegrity(username, realm, password string) MessageIntegrity {
	return MessageIntegrity(longTermKeyMD5(username, realm, password))
}

// NewLongTermIntegritySHA256 returns new MessageIntegritySHA256 with key for
// long-term credentials derived with the SHA-256 password algorithm
// (RFC 8489 Section 18.5.1.2):
//
//	key = SHA-256(username ":" realm ":" password)
//
// Password, username, and realm must be SASL/OpaqueString-prepared.
func NewLongTermIntegritySHA256(username, realm, password string) MessageIntegritySHA256 {
	return MessageIntegritySHA256(longTermKeySHA256(username, realm, password))
}

// NewShortTermIntegrity returns new MessageIntegrity with key for short-term
// credentials. Password must be SASL-prepared.
func NewShortTermIntegrity(password string) MessageIntegrity {
	return MessageIntegrity(password)
}

// NewShortTermIntegritySHA256 returns new MessageIntegritySHA256 with key for
// short-term credentials. Password must be SASL/OpaqueString-prepared.
//
// RFC 8489 Section 9.1.1: key = OpaqueString(password).
func NewShortTermIntegritySHA256(password string) MessageIntegritySHA256 {
	return MessageIntegritySHA256(password)
}

func longTermKeyMD5(username, realm, password string) []byte {
	k := strings.Join([]string{username, realm, password}, credentialsSep)
	h := md5.New() //nolint:gosec
	fmt.Fprint(h, k)

	return h.Sum(nil)
}

func longTermKeySHA256(username, realm, password string) []byte {
	k := strings.Join([]string{username, realm, password}, credentialsSep)
	h := sha256.New()
	fmt.Fprint(h, k)

	return h.Sum(nil)
}

// LongTermKey derives the long-term HMAC key for algorithm from the
// OpaqueString-prepared username, realm, and password.
//
// MD5 (the only algorithm usable by the legacy MESSAGE-INTEGRITY flow)
// produces a 16-byte key and SHA-256 produces a 32-byte key, as defined by
// RFC 8489 Section 18.5.1. ErrPasswordAlgorithmNotSupported is returned for
// unknown algorithm numbers.
func LongTermKey(algorithm PasswordAlgorithm, username, realm, password string) ([]byte, error) {
	switch algorithm {
	case PasswordAlgorithmMD5:
		return longTermKeyMD5(username, realm, password), nil
	case PasswordAlgorithmSHA256:
		return longTermKeySHA256(username, realm, password), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrPasswordAlgorithmNotSupported, algorithm)
	}
}

// MessageIntegrity represents MESSAGE-INTEGRITY attribute.
//
// AddTo and Check methods are using zero-allocation version of hmac, see
// newHMAC function and internal/hmac/pool.go.
//
// RFC 5389 Section 15.4, RFC 8489 Section 14.5.
type MessageIntegrity []byte

// MessageIntegritySHA256 represents MESSAGE-INTEGRITY-SHA256 attribute.
//
// The attribute carries the full 32-byte HMAC-SHA256; truncated values
// (16..32 bytes in multiples of four) are accepted on Check only when the
// STUN Usage explicitly permits them.
//
// RFC 8489 Section 14.6.
type MessageIntegritySHA256 []byte

func newHMACSHA1(key, message, buf []byte) []byte {
	mac := hmac.AcquireSHA1(key)
	writeOrPanic(mac, message)
	defer hmac.PutSHA1(mac)

	return mac.Sum(buf)
}

func newHMACSHA256(key, message, buf []byte) []byte {
	mac := hmac.AcquireSHA256(key)
	writeOrPanic(mac, message)
	defer hmac.PutSHA256(mac)

	return mac.Sum(buf)
}

func (i MessageIntegrity) String() string {
	return fmt.Sprintf("KEY: 0x%x", []byte(i))
}

func (i MessageIntegritySHA256) String() string {
	return fmt.Sprintf("KEY: 0x%x", []byte(i))
}

const (
	messageIntegritySize    = 20 // HMAC-SHA1 output.
	messageIntegrity256Size = sha256.Size
	messageIntegrity256Min  = 16
	hmacSizeMultiple        = 4
)

// ErrFingerprintBeforeIntegrity means that FINGERPRINT attribute is already in
// message, so MESSAGE-INTEGRITY attribute cannot be added.
var ErrFingerprintBeforeIntegrity = errors.New("FINGERPRINT before MESSAGE-INTEGRITY attribute")

// noFingerprintBeforeIntegrity verifies that no FINGERPRINT attribute is
// already present, as integrity attributes have to precede FINGERPRINT.
func noFingerprintBeforeIntegrity(msg *Message) error {
	for _, a := range msg.Attributes {
		if a.Type == AttrFingerprint {
			return ErrFingerprintBeforeIntegrity
		}
	}

	return nil
}

// addIntegrity adds an HMAC integrity attribute of the given size and hash
// to msg, adjusting the message Length field for the duration of the HMAC
// computation as required by RFC 8489 Sections 14.5 and 14.6.
func addIntegrity(msg *Message, attrType AttrType, key []byte, size int, hmacFn func(key, message, buf []byte) []byte) error {
	if err := noFingerprintBeforeIntegrity(msg); err != nil {
		return err
	}
	// The text used as input to HMAC is the STUN message,
	// including the header, up to and including the attribute preceding the
	// integrity attribute.
	length := msg.Length
	// Adjusting m.Length to contain the integrity TLV.
	msg.Length += uint32(size + attributeHeaderSize)  //nolint:gosec // G115
	msg.WriteLength()                                 // writing length to m.Raw
	v := hmacFn(key, msg.Raw, msg.Raw[len(msg.Raw):]) // calculating HMAC for adjusted m.Raw
	msg.Length = length                               // changing m.Length back

	// Copy hmac value to temporary variable to protect it from resetting
	// while processing m.Add call.
	vBuf := make([]byte, size)
	copy(vBuf, v)

	msg.Add(attrType, vBuf)

	return nil
}

// AddTo adds MESSAGE-INTEGRITY attribute to message.
//
// CPU costly, see BenchmarkMessageIntegrity_AddTo.
func (i MessageIntegrity) AddTo(msg *Message) error {
	return addIntegrity(msg, AttrMessageIntegrity, i, messageIntegritySize, newHMACSHA1)
}

// AddTo adds MESSAGE-INTEGRITY-SHA256 attribute to message.
//
// CPU costly, see BenchmarkMessageIntegritySHA256_AddTo.
func (i MessageIntegritySHA256) AddTo(msg *Message) error {
	return addIntegrity(msg, AttrMessageIntegritySHA256, i, messageIntegrity256Size, newHMACSHA256)
}

// ErrIntegrityMismatch means that computed HMAC differs from expected.
var ErrIntegrityMismatch = errors.New("integrity check failed")

// ErrIntegritySize means that a MESSAGE-INTEGRITY(-SHA256) attribute value
// has an invalid length.
var ErrIntegritySize = errors.New("integrity attribute size is invalid")

// checkIntegrity verifies the integrity attribute attrType of msg against
// the HMAC computed with hmacFn, accepting values of exactly expectedSize
// bytes (or, for SHA-256, any RFC 8489-permitted truncated length when
// allowTruncation is true).
func checkIntegrity(
	msg *Message,
	attrType AttrType,
	key []byte,
	expectedSize int,
	allowTruncation bool,
	hmacFn func(key, message, buf []byte) []byte,
) error {
	val, err := msg.Get(attrType)
	if err != nil {
		return err
	}
	if len(val) != expectedSize {
		if !allowTruncation || len(val) < messageIntegrity256Min || len(val) > expectedSize || len(val)%hmacSizeMultiple != 0 {
			return ErrIntegritySize
		}
	}

	// Adjusting length in header to match m.Raw that was
	// used when computing HMAC.
	var (
		length      = msg.Length
		sizeReduced int
	)
	for _, a := range msg.Attributes {
		sizeReduced += attributeHeaderSize
		sizeReduced += nearestPaddedValueLength(int(a.Length))
		if a.Type == attrType {
			break
		}
	}
	msg.Length = uint32(sizeReduced) //nolint:gosec // G115
	msg.WriteLength()
	// startOfHMAC should be first byte of integrity attribute.
	startOfHMAC := messageHeaderSize + int(msg.Length) - (attributeHeaderSize + len(val))
	b := msg.Raw[:startOfHMAC] // data before integrity attribute
	expected := hmacFn(key, b, msg.Raw[len(msg.Raw):])
	msg.Length = length
	msg.WriteLength() // writing length back

	// Only compare the bytes actually present, so that permitted truncated
	// HMAC values validate against the initial portion of the full HMAC.
	return checkHMAC(val, expected[:len(val)])
}

// Check checks MESSAGE-INTEGRITY attribute.
//
// CPU costly, see BenchmarkMessageIntegrity_Check.
func (i MessageIntegrity) Check(msg *Message) error {
	return checkIntegrity(msg, AttrMessageIntegrity, i, messageIntegritySize, false, newHMACSHA1)
}

// Check checks MESSAGE-INTEGRITY-SHA256 attribute. The full 32-byte HMAC is
// required unless the STUN Usage explicitly permits truncation, in which
// case CheckTruncated must be used.
//
// CPU costly.
func (i MessageIntegritySHA256) Check(msg *Message) error {
	return checkIntegrity(msg, AttrMessageIntegritySHA256, i, messageIntegrity256Size, false, newHMACSHA256)
}

// CheckTruncated checks MESSAGE-INTEGRITY-SHA256 accepting the truncated
// values permitted by RFC 8489 Section 14.6: at least 16 bytes and a
// multiple of 4 bytes, never longer than 32 bytes.
func (i MessageIntegritySHA256) CheckTruncated(msg *Message) error {
	return checkIntegrity(msg, AttrMessageIntegritySHA256, i, messageIntegrity256Size, true, newHMACSHA256)
}
