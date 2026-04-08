// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

// pipeWithDeadline creates a net.Pipe with a test-scoped deadline so tests
// fail fast instead of hanging on deadlocks.
func pipeWithDeadline(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	dl := time.Now().Add(5 * time.Second)
	c.SetDeadline(dl)
	s.SetDeadline(dl)
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

// TestUserPassAuth verifies that [UserPassAuth] returns a working RFC 1929
// authenticator that accepts the configured credential pair.
func TestUserPassAuth(t *testing.T) {
	client, server := pipeWithDeadline(t)
	auth := UserPassAuth("alice", "secret")

	if auth.Code() != methodUserPass {
		t.Fatalf("Code() = %#x, want %#x (methodUserPass)", auth.Code(), methodUserPass)
	}

	errc := make(chan error, 1)
	go func() {
		_, err := auth.Authenticate(server)
		errc <- err
	}()

	// RFC 1929 sub-negotiation: VER | ULEN | UNAME | PLEN | PASSWD
	pkt := []byte{authSubVersion, 5, 'a', 'l', 'i', 'c', 'e', 6, 's', 'e', 'c', 'r', 'e', 't'}
	client.Write(pkt)

	resp := make([]byte, 2)
	io.ReadFull(client, resp)
	if resp[0] != authSubVersion {
		t.Fatalf("auth response VER = %#x, want 0x01 (RFC 1929 §2)", resp[0])
	}
	if resp[1] != authSuccess {
		t.Fatalf("STATUS = %#x, want 0x00 (success)", resp[1])
	}
	if err := <-errc; err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

// TestUserPassAuthMulti verifies that [UserPassAuthMulti] accepts any
// credential pair from the provided map.
func TestUserPassAuthMulti(t *testing.T) {
	creds := map[string]string{"alice": "secret", "bob": "pass"}

	for user, pass := range creds {
		t.Run(user, func(t *testing.T) {
			client, server := pipeWithDeadline(t)
			auth := UserPassAuthMulti(creds)

			errc := make(chan error, 1)
			go func() {
				_, err := auth.Authenticate(server)
				errc <- err
			}()

			pkt := append([]byte{authSubVersion, byte(len(user))}, []byte(user)...)
			pkt = append(pkt, byte(len(pass)))
			pkt = append(pkt, []byte(pass)...)
			client.Write(pkt)

			resp := make([]byte, 2)
			io.ReadFull(client, resp)
			if resp[0] != authSubVersion {
				t.Fatalf("auth response VER = %#x, want 0x01 (RFC 1929 §2)", resp[0])
			}
			if resp[1] != authSuccess {
				t.Fatalf("STATUS = %#x, want 0x00 (success) for user %q", resp[1], user)
			}
			if err := <-errc; err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
		})
	}
}

// TestUserPassAuth_BadSubVersion verifies that the server rejects a
// sub-negotiation whose VER field is not 0x01 (RFC 1929 §2).
func TestUserPassAuth_BadSubVersion(t *testing.T) {
	client, server := pipeWithDeadline(t)
	a := UserPassAuth("u", "p")

	errc := make(chan error, 1)
	go func() {
		_, err := a.Authenticate(server)
		errc <- err
	}()

	// Server returns after reading 2 bytes without consuming the rest; write
	// in a goroutine to avoid deadlocking on net.Pipe's unbuffered transport.
	go client.Write([]byte{0x02, 0x01, 'u', 0x01, 'p'}) // VER=0x02 instead of 0x01

	if err := <-errc; err == nil {
		t.Fatal("expected error for bad sub-negotiation version")
	}
}

// TestUserPassAuth_ZeroLengthUsername verifies that ULEN=0 is rejected with
// STATUS=0x01 (RFC 1929 §2: ULEN is "1 to 255").
func TestUserPassAuth_ZeroLengthUsername(t *testing.T) {
	client, server := pipeWithDeadline(t)
	a := UserPassAuth("u", "p")

	errc := make(chan error, 1)
	go func() {
		_, err := a.Authenticate(server)
		errc <- err
	}()

	// Server reads 2 bytes (header) then writes failure without consuming the
	// remaining bytes; write in a goroutine to avoid deadlocking on net.Pipe.
	go client.Write([]byte{authSubVersion, 0x00, 0x01, 'p'})

	resp := make([]byte, 2)
	io.ReadFull(client, resp)
	if resp[0] != authSubVersion {
		t.Fatalf("auth response VER = %#x, want 0x01 (RFC 1929 §2)", resp[0])
	}
	if resp[1] != authFailure {
		t.Fatalf("STATUS = %#x, want 0x01 (failure) for ULEN=0", resp[1])
	}
	if err := <-errc; err == nil {
		t.Fatal("expected error for ULEN=0")
	}
}

// TestUserPassAuth_ZeroLengthPassword verifies that PLEN=0 is rejected with
// STATUS=0x01 (RFC 1929 §2: PLEN is "1 to 255").
func TestUserPassAuth_ZeroLengthPassword(t *testing.T) {
	client, server := pipeWithDeadline(t)
	a := UserPassAuth("u", "p")

	errc := make(chan error, 1)
	go func() {
		_, err := a.Authenticate(server)
		errc <- err
	}()

	client.Write([]byte{authSubVersion, 0x01, 'u', 0x00})

	resp := make([]byte, 2)
	io.ReadFull(client, resp)
	if resp[0] != authSubVersion {
		t.Fatalf("auth response VER = %#x, want 0x01 (RFC 1929 §2)", resp[0])
	}
	if resp[1] != authFailure {
		t.Fatalf("STATUS = %#x, want 0x01 (failure) for PLEN=0", resp[1])
	}
	if err := <-errc; err == nil {
		t.Fatal("expected error for PLEN=0")
	}
}

func TestStaticCredentials(t *testing.T) {
	s := StaticCredentials{Username: "alice", Password: "secret"}
	if !s.Valid("alice", "secret") {
		t.Error("expected valid for correct credentials")
	}
	if s.Valid("alice", "wrong") {
		t.Error("expected invalid for wrong password")
	}
	if s.Valid("bob", "secret") {
		t.Error("expected invalid for wrong username")
	}
}

func TestMapCredentials(t *testing.T) {
	m := MapCredentials{"alice": "secret", "bob": "pass"}
	if !m.Valid("alice", "secret") {
		t.Error("expected valid")
	}
	if m.Valid("alice", "wrong") {
		t.Error("expected invalid for wrong password")
	}
	if m.Valid("unknown", "anything") {
		t.Error("expected invalid for missing user")
	}
}
