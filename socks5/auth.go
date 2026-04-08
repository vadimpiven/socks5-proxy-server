// SPDX-License-Identifier: Apache-2.0 OR MIT

// auth.go provides the [Authenticator] and [CredentialStore] interfaces and
// their built-in implementations.
//
// Most servers only need [Config.Users]. Use [UserPassAuthenticator] directly
// when you need a custom [CredentialStore] (LDAP, database, etc.).
// Implement [Authenticator] for a completely different auth scheme.
package socks5

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
)

// User holds credentials and per-user policy for username/password
// authentication (RFC 1929).
//
// In [Config.Users] the map key is a human-readable identifier (never sent
// over the wire). Login is the actual SOCKS5 credential and defaults to the
// map key when empty.
type User struct {
	// Login is the SOCKS5 username (UNAME) sent by the client.
	// Defaults to the map key in [Config.Users] when empty.
	Login string `toml:"login"`
	// Password is the SOCKS5 password (PASSWD). Required; must not be empty.
	Password string `toml:"password"`
	// AllowPrivate permits this user to CONNECT to private, loopback,
	// and link-local IP destinations.
	AllowPrivate bool `toml:"allow_private"`
}

// Authenticator handles a single SOCKS5 authentication method.
//
// The server calls Authenticate only after it has written the method-selection
// byte to the client, so implementations perform only the method-specific
// sub-negotiation (not the method selection itself).
//
// Authenticate returns the authenticated identity (e.g. username) on success,
// or an empty string for anonymous methods such as NoAuth. The identity is
// used for logging; the server closes the connection on any non-nil error.
//
// For username/password authentication, use [Config.Users] instead of
// implementing this interface.
type Authenticator interface {
	// Code returns the SOCKS5 method byte this authenticator handles.
	Code() byte
	// Authenticate performs the method sub-negotiation on conn and returns
	// the authenticated identity (username, token, etc.) on success, or an
	// error that causes the server to close the connection.
	Authenticate(conn net.Conn) (identity string, err error)
}

// NoAuthAuthenticator implements SOCKS5 method 0x00 (no authentication).
// The sub-negotiation is empty; Authenticate returns immediately.
// This is the default when [Config.Users] is nil and [Config.Authenticator]
// is nil.
type NoAuthAuthenticator struct{}

func (NoAuthAuthenticator) Code() byte { return methodNoAuth }

func (NoAuthAuthenticator) Authenticate(_ net.Conn) (string, error) {
	return "", nil // anonymous: no identity
}

// UserPassAuthenticator implements RFC 1929 username/password authentication
// (SOCKS5 method 0x02).
//
// Most servers should use [Config.Users] instead. Use this type directly only
// when you need a custom [CredentialStore] (LDAP, database, etc.) and pass it
// as [Config.Authenticator].
type UserPassAuthenticator struct {
	// Credentials validates username/password pairs. Must not be nil;
	// [NewServer] returns an error if it is.
	Credentials CredentialStore
}

func (a UserPassAuthenticator) Code() byte { return methodUserPass }

// Authenticate performs the RFC 1929 sub-negotiation and returns the
// authenticated username on success.
//
// Wire format — request:  VER(1) | ULEN(1) | UNAME(1-255) | PLEN(1) | PASSWD(1-255)
// Wire format — response: VER(1) | STATUS(1)
func (a UserPassAuthenticator) Authenticate(conn net.Conn) (string, error) {
	return doUserPassAuth(conn, a.Credentials)
}

// CredentialStore validates username/password pairs.
// Implementations must use constant-time comparison to prevent timing attacks.
type CredentialStore interface {
	Valid(username, password string) bool
}

// staticCredentials is a single-pair [CredentialStore]. Both comparisons are
// constant-time (SHA-256 normalised) to resist timing side-channels.
type staticCredentials struct {
	username, password string
}

func (s staticCredentials) Valid(username, password string) bool {
	// Assign both results before combining: if the && were applied directly
	// to the two calls, the short-circuit would skip the password comparison
	// when the username is wrong, leaking via timing whether the username exists.
	userOK := constantTimeEqual([]byte(username), []byte(s.username))
	passOK := constantTimeEqual([]byte(password), []byte(s.password))
	return userOK && passOK
}

// mapCredentials is a multi-user [CredentialStore] backed by a username →
// password map. Map lookup is not constant-time (timing reveals whether a
// username exists), but password comparison is. Suitable when the username
// list is not sensitive.
type mapCredentials map[string]string

func (m mapCredentials) Valid(username, password string) bool {
	stored, ok := m[username]
	if !ok {
		constantTimeEqual([]byte(password), nil) // dummy comparison; avoids timing oracle
		return false
	}
	return constantTimeEqual([]byte(password), []byte(stored))
}

// doUserPassAuth is the stateless RFC 1929 wire implementation.
// Returns the authenticated username on success.
func doUserPassAuth(rw io.ReadWriter, store CredentialStore) (string, error) {
	var header [2]byte
	if _, err := io.ReadFull(rw, header[:]); err != nil {
		return "", fmt.Errorf("read auth header: %w", err)
	}
	if header[0] != authSubVersion {
		return "", fmt.Errorf("unsupported auth sub-version: %#x (want %#x)", header[0], authSubVersion)
	}
	if header[1] == 0 {
		_, _ = rw.Write([]byte{authSubVersion, authFailure})
		return "", errors.New("ULEN is 0: username must be 1-255 bytes (RFC 1929 §2)")
	}

	username := make([]byte, header[1])
	if _, err := io.ReadFull(rw, username); err != nil {
		return "", fmt.Errorf("read username: %w", err)
	}

	var plen [1]byte
	if _, err := io.ReadFull(rw, plen[:]); err != nil {
		return "", fmt.Errorf("read password length: %w", err)
	}
	if plen[0] == 0 {
		_, _ = rw.Write([]byte{authSubVersion, authFailure})
		return "", errors.New("PLEN is 0: password must be 1-255 bytes (RFC 1929 §2)")
	}

	password := make([]byte, plen[0])
	if _, err := io.ReadFull(rw, password); err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	status := authSuccess
	if !store.Valid(string(username), string(password)) {
		status = authFailure
	}
	if _, err := rw.Write([]byte{authSubVersion, status}); err != nil {
		return "", fmt.Errorf("write auth response: %w", err)
	}
	if status != authSuccess {
		return "", errors.New("authentication failed")
	}
	return string(username), nil
}

// constantTimeEqual compares two byte slices in constant time regardless of
// length. subtle.ConstantTimeCompare returns 0 immediately when lengths differ,
// leaking length via timing; hashing both to 32-byte SHA-256 digests first
// eliminates that.
func constantTimeEqual(a, b []byte) bool {
	ha := sha256.Sum256(a)
	hb := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
