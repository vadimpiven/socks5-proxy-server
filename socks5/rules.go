// SPDX-License-Identifier: Apache-2.0 OR MIT

// rules.go defines [AddrSpec], [Command], [Request], [RuleSet], and the
// built-in implementations [PermitAll] and [PermitCommand].
//
// Most servers don't need a custom [RuleSet]; the default ([PermitAll]) permits
// every request. Use [PermitCommand] to restrict commands. Implement [RuleSet]
// for IP-based, user-based, or destination-based access control.
package socks5

import (
	"context"
	"net"
	"net/netip"
	"strconv"
)

// AddrSpec is a SOCKS5 network destination: a literal IP address or a domain
// name, plus a port. Exactly one of IP and Domain is set.
//
// IP destinations always use plain IPv4 or IPv6 — IPv4-mapped IPv6
// (::ffff:a.b.c.d) is normalised to plain IPv4 by the parser.
type AddrSpec struct {
	// IP is set for literal-IP destinations. Zero (not IsValid) when Domain is set.
	IP netip.Addr
	// Domain is set for DOMAINNAME destinations. Empty when IP is set.
	Domain string
	// Port is the destination TCP or UDP port.
	Port uint16
}

// String returns a "host:port" string suitable for net.Dial.
func (a AddrSpec) String() string {
	if a.Domain != "" {
		return net.JoinHostPort(a.Domain, strconv.Itoa(int(a.Port)))
	}
	return netip.AddrPortFrom(a.IP, a.Port).String()
}

// AddrPort returns the netip.AddrPort for IP destinations, or the zero value
// for domain destinations (IP not yet resolved).
func (a AddrSpec) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(a.IP, a.Port)
}

// Command is a SOCKS5 request command (RFC 1928 §4).
type Command byte

const (
	CommandConnect      Command = 0x01
	CommandBind         Command = 0x02 // not implemented; rejected with reply 0x07
	CommandUDPAssociate Command = 0x03
)

// Request holds the information about an incoming SOCKS5 request presented to
// a [RuleSet] before any outbound connection is established.
type Request struct {
	// Command is the SOCKS5 command ([CommandConnect] or [CommandUDPAssociate]).
	Command Command
	// ClientAddr is the client's TCP source address (IP already Unmap'd).
	ClientAddr netip.AddrPort
	// Dest is the parsed destination. Domain destinations are not yet resolved
	// at the time Allow is called.
	Dest AddrSpec
	// Auth carries identity from the completed auth phase. Type-assert to
	// [NoAuthInfo] or [UserPassInfo] to inspect method-specific fields.
	Auth AuthInfo
}

// RuleSet gates incoming SOCKS5 requests before any outbound connection is
// attempted. Returning false sends reply 0x02 (not allowed) and closes the
// connection cleanly.
//
// Allow receives a copy of Request; modifications have no effect.
// The context is derived from context.Background().
type RuleSet interface {
	Allow(ctx context.Context, req Request) bool
}

// PermitAll is a [RuleSet] that allows every request unconditionally.
// It is the default when [Config.Rules] is nil.
type PermitAll struct{}

func (PermitAll) Allow(_ context.Context, _ Request) bool { return true }

// PermitCommand is a [RuleSet] that selectively enables SOCKS5 commands.
// Commands not explicitly enabled are rejected with reply 0x02 (not allowed).
//
//	Rules: socks5.PermitCommand{EnableConnect: true} // TCP only; UDP rejected
type PermitCommand struct {
	// EnableConnect permits CONNECT (TCP tunnel) requests.
	EnableConnect bool
	// EnableUDPAssociate permits UDP ASSOCIATE requests.
	EnableUDPAssociate bool
}

func (p PermitCommand) Allow(_ context.Context, req Request) bool {
	switch req.Command {
	case CommandConnect:
		return p.EnableConnect
	case CommandUDPAssociate:
		return p.EnableUDPAssociate
	default:
		return false
	}
}
