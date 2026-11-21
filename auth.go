// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import "errors"

// Errors returned by the long-term credential authentication helpers.
var (
	// ErrPasswordAlgorithmNotSupported means that a PASSWORD-ALGORITHM
	// attribute names an algorithm this implementation does not know.
	ErrPasswordAlgorithmNotSupported = errors.New("password algorithm is not supported")
	// ErrNoIntegrity means that a message contains neither
	// MESSAGE-INTEGRITY nor MESSAGE-INTEGRITY-SHA256.
	ErrNoIntegrity = errors.New("message has no MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute")
	// ErrMissingAuthAttribute means that a message carries an integrity
	// attribute but is missing one of USERNAME/USERHASH, REALM or NONCE.
	ErrMissingAuthAttribute = errors.New("missing USERNAME/USERHASH, REALM or NONCE attribute")
	// ErrPasswordAlgorithmsMismatch means that the PASSWORD-ALGORITHMS
	// attribute echoed in a request does not match the one the server
	// advertised, or that PASSWORD-ALGORITHM does not name one of the
	// advertised algorithms.
	ErrPasswordAlgorithmsMismatch = errors.New("PASSWORD-ALGORITHM(S) mismatch")
	// ErrNoPasswordAlgorithm means that a nonce advertises the password
	// algorithms security feature but the message contains neither
	// PASSWORD-ALGORITHM nor PASSWORD-ALGORITHMS.
	ErrNoPasswordAlgorithm = errors.New("PASSWORD-ALGORITHM(S) required by nonce cookie but absent")
)

// IntegrityAlgorithm identifies which message-integrity attribute protected
// a message.
type IntegrityAlgorithm int

// Message-integrity algorithms.
const (
	// IntegrityNone means that no message-integrity attribute was present.
	IntegrityNone IntegrityAlgorithm = iota
	// IntegritySHA1 means the HMAC-SHA1 MESSAGE-INTEGRITY attribute.
	IntegritySHA1
	// IntegritySHA256 means the HMAC-SHA256 MESSAGE-INTEGRITY-SHA256
	// attribute.
	IntegritySHA256
)

// CheckLongTermIntegrity verifies the long-term credential message
// integrity of msg, implementing the verification order from RFC 8489
// Sections 9.1.3 and 9.2.4.
//
// If MESSAGE-INTEGRITY-SHA256 is present it is checked and, on failure, the
// function returns immediately: the legacy HMAC-SHA1 MESSAGE-INTEGRITY is
// never used as a fallback, so an attacker cannot bid the exchange down to
// the weaker algorithm to get a forged message accepted. The legacy
// attribute is only consulted when MESSAGE-INTEGRITY-SHA256 is absent.
//
// The key must be derived for the negotiated password algorithm, see
// LongTermKey. The returned IntegrityAlgorithm reports which attribute was
// verified. ErrNoIntegrity is returned when neither attribute is present and
// ErrIntegrityMismatch when the HMAC does not match.
func CheckLongTermIntegrity(msg *Message, key []byte) (IntegrityAlgorithm, error) {
	switch {
	case msg.Contains(AttrMessageIntegritySHA256):
		integrity := MessageIntegritySHA256(key)
		if err := integrity.Check(msg); err != nil {
			return IntegritySHA256, err
		}

		return IntegritySHA256, nil
	case msg.Contains(AttrMessageIntegrity):
		integrity := MessageIntegrity(key)
		if err := integrity.Check(msg); err != nil {
			return IntegritySHA1, err
		}

		return IntegritySHA1, nil
	default:
		return IntegrityNone, ErrNoIntegrity
	}
}

// KeyFromMessage derives the long-term key needed to verify msg using the
// OpaqueString-prepared username, realm and password, honoring the
// PASSWORD-ALGORITHM negotiation and nonce-cookie bid-down protection from
// RFC 8489 Section 9.2.4.
//
// When the nonce cookie advertises the "Password algorithms" feature:
//
//   - a message with neither PASSWORD-ALGORITHM nor PASSWORD-ALGORITHMS is
//     processed as though PASSWORD-ALGORITHM were MD5 (legacy interop),
//   - otherwise both attributes must be present, PASSWORD-ALGORITHM must
//     name an entry of PASSWORD-ALGORITHMS, and when advertised is non-nil
//     the echoed PASSWORD-ALGORITHMS must be identical to it; any violation
//     returns ErrPasswordAlgorithmsMismatch / ErrNoPasswordAlgorithm rather
//     than silently falling back to a weaker algorithm.
//
// advertised may be nil when the caller did not advertise PASSWORD-ALGORITHMS.
func KeyFromMessage(msg *Message, username, realm, password string, advertised PasswordAlgorithms) (
	[]byte, PasswordAlgorithm, error,
) {
	var (
		nonce      Nonce
		algAttr    PasswordAlgorithmAttr
		algorithms PasswordAlgorithms
	)
	_ = nonce.GetFrom(msg)
	hasAlgAttr := algAttr.GetFrom(msg) == nil
	hasAlgorithms := algorithms.GetFrom(msg) == nil

	features, cookieErr := ParseNonceCookie(nonce)
	if cookieErr == nil && features.Has(SecurityFeaturePasswordAlgorithms) {
		if !hasAlgAttr && !hasAlgorithms {
			// RFC 8489 9.2.4: a request containing neither algorithm
			// attribute is processed as though PASSWORD-ALGORITHM were
			// MD5. When the server advertised an algorithm list, a request
			// reaching this branch had the attributes stripped on path, so
			// reject it instead of silently downgrading.
			if advertised != nil {
				return nil, PasswordAlgorithmReserved, ErrNoPasswordAlgorithm
			}
			key, err := LongTermKey(PasswordAlgorithmMD5, username, realm, password)

			return key, PasswordAlgorithmMD5, err
		}
		if !hasAlgAttr || !hasAlgorithms {
			return nil, PasswordAlgorithmReserved, ErrNoPasswordAlgorithm
		}
		if advertised != nil && !equalPasswordAlgorithms(algorithms, advertised) {
			return nil, PasswordAlgorithmReserved, ErrPasswordAlgorithmsMismatch
		}
		if !algorithms.Contains(algAttr) {
			return nil, PasswordAlgorithmReserved, ErrPasswordAlgorithmsMismatch
		}
	}

	algorithm := PasswordAlgorithmMD5
	if hasAlgAttr {
		algorithm = algAttr.Algorithm
	}
	key, err := LongTermKey(algorithm, username, realm, password)
	if err != nil {
		return nil, algorithm, err
	}

	return key, algorithm, nil
}

func equalPasswordAlgorithms(a, b PasswordAlgorithms) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Algorithm != b[i].Algorithm || string(a[i].Parameters) != string(b[i].Parameters) {
			return false
		}
	}

	return true
}

// LongTermAuthResult is the outcome of authenticating a request with long-term
// credentials.
type LongTermAuthResult struct {
	// Algorithm reports which message-integrity attribute authenticated the
	// message, or IntegrityNone when the message was unauthenticated.
	Algorithm IntegrityAlgorithm
	// PasswordAlgorithm reports the password algorithm used to derive the
	// key.
	PasswordAlgorithm PasswordAlgorithm
	// Username is the USERNAME attribute value. Empty when USERHASH was
	// used.
	Username Username
	// Userhash is the USERHASH attribute value, when present.
	Userhash Userhash
	// Realm and Nonce echoed by the client.
	Realm Realm
	Nonce Nonce
}

// LongTermAuthLookup resolves the OpaqueString-prepared username (or the
// raw USERHASH bytes when useUserhash is true) and realm of an
// authenticated request to its password. Returning ok=false means that the
// credentials are unknown; the caller then rejects the request with 401.
type LongTermAuthLookup func(username Username, realm Realm, userhash Userhash) (password string, ok bool)

// LongTermUsernameResolver maps a USERHASH value back to the
// OpaqueString-prepared username it was computed from, so that the long-term
// key can be derived for a message that only carries USERHASH. It is only
// required when USERHASH anonymity is in use.
type LongTermUsernameResolver func(userhash Userhash, realm Realm) (username string, ok bool)

// AuthenticateLongTermRequest performs the server-side long-term credential
// checks of RFC 8489 Section 9.2.4. It never falls back to a weaker
// algorithm in order to accept a message: every failure is reported as a
// distinct error so the caller can select the matching STUN error code
// (400, 401, 420, ...).
//
// advertised is the PASSWORD-ALGORITHMS value the server sent in its
// challenge, or nil when password algorithm negotiation is not used.
//
// Password-algorithm negotiation and nonce-cookie bid-down protection are
// evaluated before the HMAC, so a tampered request is rejected with a
// 400-class negotiation error instead of being silently accepted through a
// weaker fallback. The returned result's Algorithm field tells the caller
// which integrity attribute must protect the response:
// MESSAGE-INTEGRITY-SHA256 for an SHA-256-derived key, MESSAGE-INTEGRITY
// for a legacy MD5-derived key.
func AuthenticateLongTermRequest(msg *Message, advertised PasswordAlgorithms, lookup LongTermAuthLookup) (
	LongTermAuthResult, error,
) {
	return AuthenticateLongTermRequestWithResolver(msg, advertised, lookup, nil)
}

// AuthenticateLongTermRequestWithResolver is AuthenticateLongTermRequest
// with an explicit resolver used to recover the raw username behind a
// USERHASH attribute. resolver may be nil when USERHASH is never used.
func AuthenticateLongTermRequestWithResolver(
	msg *Message,
	advertised PasswordAlgorithms,
	lookup LongTermAuthLookup,
	resolver LongTermUsernameResolver,
) (LongTermAuthResult, error) {
	if !msg.Contains(AttrMessageIntegrity) && !msg.Contains(AttrMessageIntegritySHA256) {
		return LongTermAuthResult{}, ErrNoIntegrity
	}

	var (
		realm    Realm
		nonce    Nonce
		username Username
		userhash Userhash
	)
	realmErr := realm.GetFrom(msg)
	nonceErr := nonce.GetFrom(msg)
	usernameErr := username.GetFrom(msg)
	userhashErr := userhash.GetFrom(msg)
	if realmErr != nil || nonceErr != nil || (usernameErr != nil && userhashErr != nil) {
		return LongTermAuthResult{}, ErrMissingAuthAttribute
	}

	rawUsername := username.String()
	if usernameErr != nil {
		if resolver == nil {
			return LongTermAuthResult{Realm: realm, Nonce: nonce, Userhash: userhash}, ErrMissingAuthAttribute
		}
		resolved, ok := resolver(userhash, realm)
		if !ok {
			return LongTermAuthResult{Realm: realm, Nonce: nonce, Userhash: userhash}, ErrIntegrityMismatch
		}
		rawUsername = resolved
	}

	password, ok := lookup(username, realm, userhash)
	if !ok {
		return LongTermAuthResult{Realm: realm, Nonce: nonce, Username: username, Userhash: userhash},
			ErrIntegrityMismatch
	}

	key, passwordAlgorithm, err := KeyFromMessage(msg, rawUsername, realm.String(), password, advertised)
	if err != nil {
		return LongTermAuthResult{Realm: realm, Nonce: nonce, Username: username, Userhash: userhash}, err
	}

	algorithm, err := CheckLongTermIntegrity(msg, key)
	if err != nil {
		return LongTermAuthResult{Realm: realm, Nonce: nonce, Username: username, Userhash: userhash}, err
	}

	return LongTermAuthResult{
		Algorithm:         algorithm,
		PasswordAlgorithm: passwordAlgorithm,
		Username:          username,
		Userhash:          userhash,
		Realm:             realm,
		Nonce:             nonce,
	}, nil
}

// LongTermChallenge carries the parameters of a 401 Unauthenticated
// challenge.
type LongTermChallenge struct {
	Realm       Realm
	Nonce       Nonce
	Algorithms  PasswordAlgorithms
	UseUserhash bool
}

// AddTo adds the REALM, NONCE and (when non-empty) PASSWORD-ALGORITHMS
// attributes of the challenge to an error response, and ensures the nonce
// cookie advertises the security features matching those attributes.
//
// RFC 8489 Section 9.2.4: the "Password algorithms" bit is set exactly when
// PASSWORD-ALGORITHMS is included, and the "Username anonymity" bit is set
// when UseUserhash requests USERHASH on the retry.
func (c LongTermChallenge) AddTo(msg *Message) error {
	features := SecurityFeatures{}
	if len(c.Algorithms) > 0 {
		features.Set(SecurityFeaturePasswordAlgorithms)
	}
	if c.UseUserhash {
		features.Set(SecurityFeatureUsernameAnonymity)
	}
	nonce := c.Nonce
	if features != (SecurityFeatures{}) {
		if _, err := ParseNonceCookie(nonce); err != nil {
			nonce = NewNonceWithFeatures(features, string(nonce))
		}
	}
	if err := nonce.AddTo(msg); err != nil {
		return err
	}
	if err := c.Realm.AddTo(msg); err != nil {
		return err
	}
	if len(c.Algorithms) > 0 {
		if err := c.Algorithms.AddTo(msg); err != nil {
			return err
		}
	}

	return nil
}

// LongTermCredentials carries the client-side long-term credential material.
type LongTermCredentials struct {
	Username string
	Password string
	Realm    string
	Nonce    Nonce
	// UseUserhash selects USERHASH instead of USERNAME, as required when
	// the challenge nonce cookie advertises the "Username anonymity"
	// feature.
	UseUserhash bool
	// Algorithms is the PASSWORD-ALGORITHMS value received in the
	// challenge and echoed verbatim in the authenticated request.
	Algorithms PasswordAlgorithms
	// Integrity selects the integrity attribute added to the request.
	// When zero, MESSAGE-INTEGRITY-SHA256 is used whenever a non-MD5
	// password algorithm is negotiated, MESSAGE-INTEGRITY otherwise.
	Integrity IntegrityAlgorithm
}

// ErrNoSupportedPasswordAlgorithm means that none of the algorithms
// advertised by the server is supported by this client.
var ErrNoSupportedPasswordAlgorithm = errors.New("none of the advertised password algorithms is supported")

// selectPasswordAlgorithm implements the client algorithm choice of RFC 8489
// Section 9.2.5: the first algorithm of the advertised list that the client
// supports.
func selectPasswordAlgorithm(advertised PasswordAlgorithms) (PasswordAlgorithmValue, error) {
	for _, candidate := range advertised {
		if candidate.Algorithm.keySize() > 0 {
			return candidate, nil
		}
	}

	return PasswordAlgorithmValue{}, ErrNoSupportedPasswordAlgorithm
}

// AddTo adds the authentication attributes of an authenticated request to
// msg: USERNAME or USERHASH, REALM, NONCE, PASSWORD-ALGORITHM(S) and the
// selected message-integrity attribute, deriving the key from the
// negotiated password algorithm.
//
// Bid-down protection is enforced: when the challenge nonce carries the
// "Password algorithms" security bit, a missing or unsupported
// PASSWORD-ALGORITHMS value produces an error instead of a silent fall back
// to MD5.
func (c LongTermCredentials) AddTo(msg *Message) error {
	algorithm := PasswordAlgorithmMD5
	if len(c.Algorithms) > 0 {
		chosen, err := selectPasswordAlgorithm(c.Algorithms)
		if err != nil {
			return err
		}
		algorithm = chosen.Algorithm
		// Echo PASSWORD-ALGORITHMS verbatim and add the chosen
		// PASSWORD-ALGORITHM.
		if err = c.Algorithms.AddTo(msg); err != nil {
			return err
		}
		if err = chosen.AddToAs(msg, AttrPasswordAlgorithm); err != nil {
			return err
		}
	} else if features, err := ParseNonceCookie(c.Nonce); err == nil &&
		features.Has(SecurityFeaturePasswordAlgorithms) {
		// RFC 8489 9.2.5: do not retry; the negotiation was tampered with.
		return ErrNoPasswordAlgorithm
	}

	key, err := LongTermKey(algorithm, c.Username, c.Realm, c.Password)
	if err != nil {
		return err
	}

	if c.UseUserhash {
		if err = NewUserhash(c.Username, c.Realm).AddTo(msg); err != nil {
			return err
		}
	} else {
		if err = NewUsername(c.Username).AddTo(msg); err != nil {
			return err
		}
	}
	if err = NewRealm(c.Realm).AddTo(msg); err != nil {
		return err
	}
	if err = c.Nonce.AddTo(msg); err != nil {
		return err
	}

	integrity := c.Integrity
	if integrity == IntegrityNone {
		if algorithm == PasswordAlgorithmMD5 && len(c.Algorithms) == 0 {
			integrity = IntegritySHA1
		} else {
			integrity = IntegritySHA256
		}
	}
	switch integrity {
	case IntegritySHA256:
		return MessageIntegritySHA256(key).AddTo(msg)
	default:
		return MessageIntegrity(key).AddTo(msg)
	}
}

// ParseLongTermChallenge inspects a 401 Unauthenticated or 438 Stale Nonce
// error response and returns the client-side credentials needed to retry,
// applying the RFC 8489 Section 9.2.5 checks:
//
//   - when the nonce cookie sets the "Password algorithms" bit, the
//     PASSWORD-ALGORITHMS attribute must be present and contain at least one
//     supported algorithm, otherwise the request must not be retried;
//   - the "Username anonymity" bit selects USERHASH.
//
// The returned LongTermCredentials still needs Username and Password filled
// in by the caller.
func ParseLongTermChallenge(msg *Message) (LongTermCredentials, error) {
	var (
		realm Realm
		nonce Nonce
	)
	if err := realm.GetFrom(msg); err != nil {
		return LongTermCredentials{}, err
	}
	if err := nonce.GetFrom(msg); err != nil {
		return LongTermCredentials{}, err
	}
	creds := LongTermCredentials{Realm: realm.String(), Nonce: nonce}

	features, cookieErr := ParseNonceCookie(nonce)
	if cookieErr == nil {
		creds.UseUserhash = features.Has(SecurityFeatureUsernameAnonymity)
		if features.Has(SecurityFeaturePasswordAlgorithms) {
			if err := creds.Algorithms.GetFrom(msg); err != nil {
				return LongTermCredentials{}, ErrNoPasswordAlgorithm
			}
			if _, err := selectPasswordAlgorithm(creds.Algorithms); err != nil {
				return LongTermCredentials{}, err
			}
		}
	}
	if creds.Algorithms == nil {
		if err := creds.Algorithms.GetFrom(msg); err == nil {
			if _, err := selectPasswordAlgorithm(creds.Algorithms); err != nil {
				creds.Algorithms = nil
			}
		}
	}

	return creds, nil
}
