# socks5-srv

A lightweight, embeddable SOCKS5 proxy server written in Go, implementing
[RFC 1928](rfcs/rfc1928.txt) and [RFC 1929](rfcs/rfc1929.txt).

## Features

| Feature             | Detail                                                   |
| ------------------- | -------------------------------------------------------- |
| Commands            | `CONNECT` (TCP tunnel), `UDP ASSOCIATE` (datagram relay) |
| Auth methods        | No-auth (0x00), username/password (0x02)                 |
| Address families    | IPv4, IPv6, domain names                                 |
| Per-user policy     | Private-destination access controlled per user           |
| Concurrency limit   | Configurable max simultaneous connections (default 1024) |
| Graceful shutdown   | Drains active sessions before exiting                    |
| Hot reload          | SIGHUP reloads config without dropping active sessions   |

> **Not implemented:** BIND (0x02) — rejected with reply 0x07.  
> **Not implemented:** GSSAPI (method 0x01) — absent from virtually all deployed SOCKS5 stacks.  
> **Not implemented:** UDP fragmentation — silently dropped per RFC 1928 §7.

## Requirements

- Go 1.26+

## Build

```sh
go build -o socks5-srv .
```

## Usage

```text
socks5-srv [flags]

  -config   string   path to TOML configuration file (default "socks5-srv.toml")
  -verbose           enable verbose log output
  -version           print version and exit
```

On first run, if the config file does not exist, the server creates it with
documented defaults and continues running. The default config enables password
authentication with an empty user list, which denies all connections until the
operator adds at least one user.

Send SIGHUP to reload the configuration without dropping active sessions:

```sh
kill -HUP $(pidof socks5-srv)
```

### Config file format (TOML)

```toml
# Listen address (host:port).
addr = ":1080"

# Network interface for outbound connections (e.g. "eth0", "en0").
# bind = "eth0"

# Presence of [users] enables username/password authentication.
# An empty section denies all connections. Remove it for no-auth mode.
# The key is a human-readable ID; "login" defaults to the key if omitted.
[users]
alice = { login = "alice", password = "s3cr3t", private = true }
bob   = { login = "bob",   password = "hunter2" }
```

| Field      | Scope    | Description                                           |
| ---------- | -------- | ----------------------------------------------------- |
| `addr`     | global   | Listen address (default `":1080"`)                    |
| `bind`     | global   | Network interface for outbound connections            |
| `[users]`  | section  | Presence enables password auth; absence means no-auth |
| `login`    | per-user | SOCKS5 username (defaults to the key if omitted)      |
| `password` | per-user | SOCKS5 password (required)                            |
| `private`  | per-user | Allow connections to private/loopback destinations    |

### Basic usage

```sh
./socks5-srv
```

### Verbose logging

```sh
./socks5-srv -verbose
```

### Custom config path

```sh
./socks5-srv -config /etc/socks5-srv.toml
```

## Embedding

```go
import "github.com/vadimpiven/socks5-srv/socks5"

srv, err := socks5.NewServer(socks5.Config{
    Authenticators: []socks5.Authenticator{
        socks5.UserPassAuth("alice", "s3cr3t"),
    },
})
if err != nil {
    log.Fatal(err)
}

ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

if err := srv.ListenAndServe(ctx, ":1080"); err != nil {
    log.Fatal(err)
}
```

### Multiple users

```go
socks5.UserPassAuthMulti(map[string]string{
    "alice": "s3cr3t",
    "bob":   "hunter2",
})
```

### Custom outbound dialer (proxy chaining, metrics, TLS)

```go
socks5.Config{
    Dial: (&net.Dialer{LocalAddr: bindAddr}).DialContext,
}
```

### Private-destination policy

By default, CONNECT to private, loopback, and link-local addresses is blocked
(SSRF protection). Set `AllowPrivateDestinations` to permit specific users
(or all users) to reach internal infrastructure:

```go
socks5.Config{
    AllowPrivateDestinations: func(identity string) bool { return true },
}
```

## Testing

```sh
go test ./...
go test -race ./...
```

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE.txt) or [MIT](LICENSE-MIT.txt).
