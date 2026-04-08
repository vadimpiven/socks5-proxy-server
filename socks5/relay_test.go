// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestRelay_HalfClose verifies that when one side of a relayed connection
// sends a TCP FIN (half-close), relay propagates it via CloseWrite rather than
// tearing down the whole connection. This allows the remote to finish sending
// before both sides close completely.
//
// The test uses real TCP connections (not net.Pipe) so that CloseWrite is
// available on both sides, which is representative of production behaviour.
func TestRelay_HalfClose(t *testing.T) {
	dial := func(t *testing.T) (client, server net.Conn) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		acceptc := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); acceptc <- c }()
		client, err = net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server = <-acceptc
		t.Cleanup(func() { client.Close(); server.Close() })
		return
	}

	clientSide, proxySide := dial(t)
	remoteProxySide, remoteSide := dial(t)

	errc := make(chan error, 1)
	go func() { errc <- relay(proxySide, remoteProxySide, 5*time.Second) }()

	// Client sends data then half-closes its write side.
	clientSide.Write([]byte("ping"))
	clientSide.(*net.TCPConn).CloseWrite()

	// Remote must receive "ping" followed by EOF.
	got, err := io.ReadAll(remoteSide)
	if err != nil {
		t.Fatalf("remote ReadAll: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("remote got %q, want %q", got, "ping")
	}

	// Remote replies and half-closes.
	remoteSide.Write([]byte("pong"))
	remoteSide.(*net.TCPConn).CloseWrite()

	// Client must receive "pong" followed by EOF.
	resp, err := io.ReadAll(clientSide)
	if err != nil {
		t.Fatalf("client ReadAll: %v", err)
	}
	if string(resp) != "pong" {
		t.Fatalf("client got %q, want %q", resp, "pong")
	}

	<-errc
}
