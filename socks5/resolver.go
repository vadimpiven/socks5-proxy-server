// SPDX-License-Identifier: Apache-2.0 OR MIT

// resolver.go defines [Resolver] for domain-name resolution and [DialFunc]
// for outbound TCP connections.
//
// [DefaultResolver] is used when [Config.Resolver] is nil; it resolves names
// via the system DNS. Implement [Resolver] to route resolution through a
// custom server, add caching, or rewrite names.
//
// [DialFunc] is the type of [Config.Dial]. The method value of
// [net.Dialer.DialContext] satisfies this type directly, making it easy to
// add bind addresses, metrics, TLS, or proxy chaining.
package socks5

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Resolver resolves a host name to an IP address.
// It is used by the UDP relay to resolve per-datagram domain destinations.
// TCP CONNECT lets [DialFunc] handle DNS internally.
type Resolver interface {
	// Resolve looks up host and returns one address.
	// The context may carry a deadline or cancellation signal.
	Resolve(ctx context.Context, host string) (netip.Addr, error)
}

// DefaultResolver uses the system DNS resolver via [net.Resolver.LookupNetIP]
// (Go 1.21+), which returns [netip.Addr] values directly.
// It returns the first result in the order the resolver provides; the
// address family depends on the system DNS configuration.
type DefaultResolver struct{}

func (DefaultResolver) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	// "ip" returns both A and AAAA records; the first result is used.
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no addresses for %q", host)
	}
	return addrs[0].Unmap(), nil
}

// DialFunc establishes an outgoing TCP connection.
// The network argument is always "tcp"; addr is in "host:port" form.
// The context carries the configured dial deadline.
//
// The method value of [net.Dialer.DialContext] satisfies this type, so
// callers can write:
//
//	cfg.Dial = (&net.Dialer{LocalAddr: bindAddr}).DialContext
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
