// SPDX-License-Identifier: Apache-2.0 OR MIT

// Command socks5-srv starts a lightweight SOCKS5 proxy server.
//
// It supports TCP CONNECT and UDP ASSOCIATE through IPv4 and IPv6 networks,
// with optional username/password authentication per RFC 1928 and RFC 1929.
//
// On first run the server creates a default configuration file
// (socks5-srv.toml) with documented settings. The default config enables
// password authentication with an empty user list, which denies all
// connections until the operator adds at least one user.
//
// Send SIGHUP to reload the configuration without dropping active sessions.
//
// Usage:
//
//	socks5-srv [flags]
//	  -config   socks5-srv.toml   path to TOML configuration file
//	  -verbose                    enable verbose log output
//	  -version                    print version and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/vadimpiven/socks5-srv/socks5"
)

var version = "dev"

// config is the top-level TOML configuration.
type config struct {
	Addr  string               `toml:"addr"`
	Bind  string               `toml:"bind"`
	Users map[string]userEntry `toml:"users"`
}

// userEntry represents one user in the [users] table.
// The map key serves as the human-readable ID.
type userEntry struct {
	Login    string `toml:"login"`
	Password string `toml:"password"`
	Private  bool   `toml:"private"`
}

const defaultConfig = `# socks5-srv configuration
# https://github.com/vadimpiven/socks5-srv
#
# Send SIGHUP to reload without dropping active sessions.

# Listen address (host:port).
addr = ":1080"

# Network interface for outbound connections (e.g. "eth0", "en0").
# The server resolves the interface to an IP matching each destination's
# address family (IPv4 or IPv6) per connection, similar to curl --interface.
# bind = "eth0"

# User list. Presence of this section enables username/password authentication.
# An empty section denies all connections — add at least one user to accept traffic.
# Remove or comment out the entire [users] section for no-auth mode.
#
# The key is a human-readable ID. If "login" is omitted it defaults to the key.
[users]
# alice = { login = "alice", password = "s3cr3t", private = true }
# bob   = { login = "bob",   password = "hunter2" }
`

func main() {
	configPath := flag.String("config", "socks5-srv.toml", "path to configuration file")
	verbose := flag.Bool("verbose", false, "enable verbose log output")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("socks5-srv " + version)
		return
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		if err := os.WriteFile(*configPath, []byte(defaultConfig), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot create config: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "created default config: %s (edit and restart)\n", *configPath)
	}

	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	for {
		srv, err := buildServer(cfg, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		ln, err := net.Listen("tcp", cfg.Addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		srvCtx, srvCancel := context.WithCancel(ctx)
		srvDone := make(chan error, 1)
		go func() {
			srvDone <- srv.Serve(srvCtx, ln)
		}()

		logger.Warn("listening", "addr", cfg.Addr)

		reloaded := false
		for !reloaded {
			select {
			case <-ctx.Done():
				srvCancel()
				<-srvDone
				return
			case err := <-srvDone:
				if err != nil {
					logger.Error("fatal", "err", err)
				}
				os.Exit(1)
			case <-sighup:
				newCfg, err := loadConfig(*configPath)
				if err != nil {
					logger.Error("reload failed", "err", err)
					break // re-enter select, keep running old config
				}
				cfg = newCfg
				reloaded = true
			}
		}

		// Stop accepting new connections; drain active sessions in background.
		ln.Close()
		go func(cancel context.CancelFunc, done <-chan error) {
			<-done
			cancel()
		}(srvCancel, srvDone)

		logger.Warn("configuration reloaded")
	}
}

// loadConfig reads and validates the TOML configuration file.
func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var cfg config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return config{}, err
	}
	if cfg.Addr == "" {
		cfg.Addr = ":1080"
	}
	if cfg.Bind != "" {
		if _, err := net.InterfaceByName(cfg.Bind); err != nil {
			return config{}, fmt.Errorf("bind interface %q: %w", cfg.Bind, err)
		}
	}
	if cfg.Users != nil {
		seen := make(map[string]string, len(cfg.Users))
		for id, u := range cfg.Users {
			login := u.Login
			if login == "" {
				login = id
			}
			if u.Password == "" {
				return config{}, fmt.Errorf("user %q has empty password", id)
			}
			if prevID, dup := seen[login]; dup {
				return config{}, fmt.Errorf("duplicate login %q (users %q and %q)", login, prevID, id)
			}
			seen[login] = id
		}
	}
	return cfg, nil
}

// buildServer creates a socks5.Server from the validated configuration.
func buildServer(cfg config, logger *slog.Logger) (*socks5.Server, error) {
	scfg := socks5.Config{
		Logger: logger,
	}

	if cfg.Bind != "" {
		scfg.Dial = ifaceDial(cfg.Bind)
	}

	if cfg.Users != nil {
		creds := make(socks5.MapCredentials, len(cfg.Users))
		privateSet := make(map[string]bool, len(cfg.Users))
		for id, u := range cfg.Users {
			login := u.Login
			if login == "" {
				login = id
			}
			creds[login] = u.Password
			privateSet[login] = u.Private
		}
		scfg.Authenticators = []socks5.Authenticator{
			socks5.UserPassAuthenticator{Credentials: creds},
		}
		scfg.AllowPrivateDestinations = func(identity string) bool {
			return privateSet[identity]
		}
	} else {
		scfg.Authenticators = []socks5.Authenticator{socks5.NoAuthAuthenticator{}}
		scfg.AllowPrivateDestinations = func(string) bool { return true }
	}

	return socks5.NewServer(scfg)
}

// ifaceAddr returns the first address on iface that matches the given network
// ("tcp4" or "tcp6"). Returns nil when no address of that family exists.
func ifaceAddr(iface *net.Interface, network string) net.Addr {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	wantV4 := network == "tcp4"
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if (ip.To4() != nil) == wantV4 {
			return &net.TCPAddr{IP: ip}
		}
	}
	return nil
}

// ifaceDial returns a DialFunc that binds outgoing connections to the named
// network interface, selecting an IP matching the destination's address family.
func ifaceDial(ifaceName string) socks5.DialFunc {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("bind interface %q: %w", ifaceName, err)
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// Resolve destination to determine address family.
		var dstIP net.IP
		if ip := net.ParseIP(host); ip != nil {
			dstIP = ip
		} else {
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if ip.To4() != nil {
					dstIP = ip
					break
				}
				if dstIP == nil {
					dstIP = ip
				}
			}
		}
		if dstIP == nil {
			return nil, fmt.Errorf("no addresses for %s", host)
		}

		dstNetwork := "tcp4"
		if dstIP.To4() == nil {
			dstNetwork = "tcp6"
		}

		localAddr := ifaceAddr(iface, dstNetwork)
		d := net.Dialer{LocalAddr: localAddr}
		return d.DialContext(ctx, dstNetwork, net.JoinHostPort(dstIP.String(), port))
	}
}
