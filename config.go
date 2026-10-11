package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is everything needed to bring the WARP tunnel up.
type Config struct {
	// Base64 WireGuard private key of this device.
	PrivateKey string `toml:"private_key"`
	// WARP-assigned IPv4, e.g. "172.16.0.2" (no prefix).
	AddressV4 string `toml:"address_v4"`
	// WARP-assigned IPv6, if the account got one.
	AddressV6 string `toml:"address_v6,omitempty"`
	// Cloudflare's WireGuard public key.
	PeerPublicKey string `toml:"peer_public_key"`
	// "host:port" WireGuard endpoint.
	Endpoint string `toml:"endpoint"`

	// Tailscale hostname for the embedded node (default "warp-exit-node").
	Hostname string `toml:"hostname,omitempty"`

	// Cloudflare device id / token (for future account ops).
	DeviceID    string `toml:"device_id,omitempty"`
	AccessToken string `toml:"access_token,omitempty"`
	License     string `toml:"license,omitempty"`
}

func (c *Config) hostname() string {
	if c.Hostname == "" {
		return "warp-exit-node"
	}
	return c.Hostname
}

func loadConfig(path string) (*Config, error) {
	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, fmt.Errorf("cannot read %s — run `warp-exit up` or `warp-exit import` first: %w", path, err)
	}
	return &c, nil
}

func (c *Config) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(c)
}

// importWgcf parses a wgcf-style wg-quick config into a Config.
func importWgcf(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var section string
	var priv, v4, v6, peerKey, endpoint string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case section == "Interface" && k == "PrivateKey":
			priv = v
		case section == "Interface" && k == "Address":
			for _, a := range strings.Split(v, ",") {
				a, _, _ = strings.Cut(strings.TrimSpace(a), "/")
				if strings.Contains(a, ":") {
					v6 = a
				} else if a != "" {
					v4 = a
				}
			}
		case section == "Peer" && k == "PublicKey":
			peerKey = v
		case section == "Peer" && k == "Endpoint":
			endpoint = v
		}
	}
	if priv == "" || v4 == "" || peerKey == "" || endpoint == "" {
		return nil, fmt.Errorf("%s: missing required fields (PrivateKey/Address/PublicKey/Endpoint)", path)
	}
	return &Config{
		PrivateKey:    priv,
		AddressV4:     v4,
		AddressV6:     v6,
		PeerPublicKey: peerKey,
		Endpoint:      endpoint,
	}, nil
}

// resolveEndpoint resolves the WireGuard endpoint to an IPv4 UDPAddr.
// Must be called in the host netns (normal DNS) before namespace setup.
func resolveEndpoint(ep string) (*net.UDPAddr, error) {
	host, port := ep, "2408"
	if h, p, err := net.SplitHostPort(ep); err == nil {
		host, port = h, p
	} else {
		host = strings.Trim(host, "[]")
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve WARP endpoint %q: %w", host, err)
	}
	p := 2408
	fmt.Sscanf(port, "%d", &p)
	return &net.UDPAddr{IP: ips[0], Port: p}, nil
}
