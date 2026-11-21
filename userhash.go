// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import "crypto/sha256"

// UserhashSize is the fixed length, in bytes, of the USERHASH attribute
// value.
//
// RFC 8489 Section 14.4.
const UserhashSize = sha256.Size

// Userhash represents the USERHASH attribute (0x001E). It replaces the
// USERNAME attribute when username anonymity is used and contains the
// SHA-256 hash of the OpaqueString-prepared username and realm:
//
//	userhash = SHA-256(OpaqueString(username) ":" OpaqueString(realm))
//
// RFC 8489 Section 14.4.
type Userhash []byte

// NewUserhash computes the USERHASH value for username in realm. Username
// and realm must already be processed with the OpaqueString profile.
func NewUserhash(username, realm string) Userhash {
	h := sha256.New()
	writeOrPanic(h, []byte(username))
	writeOrPanic(h, []byte(credentialsSep))
	writeOrPanic(h, []byte(realm))

	return Userhash(h.Sum(nil))
}

// AddTo adds the USERHASH attribute to m.
func (u Userhash) AddTo(m *Message) error {
	if err := CheckSize(AttrUserhash, len(u), UserhashSize); err != nil {
		return err
	}
	m.Add(AttrUserhash, u)

	return nil
}

// GetFrom decodes the USERHASH attribute from m.
func (u *Userhash) GetFrom(m *Message) error {
	v, err := m.Get(AttrUserhash)
	if err != nil {
		return err
	}
	if err = CheckSize(AttrUserhash, len(v), UserhashSize); err != nil {
		return err
	}
	*u = append((*u)[:0], v...)

	return nil
}
