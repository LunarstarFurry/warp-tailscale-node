package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	regAPI          = "https://api.cloudflareclient.com/v0a5641/reg"
	regUserAgent    = "1.1.1.1/6.38.9-5641 (Android 16.0.0)"
	regClientVer    = "a-6.38.9-5641"
	defaultPeerName = "PC"
)

type regResponse struct {
	ID    string `json:"id"`
	Token string `json:"token"`
	Acct  struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host  string `json:"host"`
				V4    string `json:"v4"`
				V6    string `json:"v6"`
				Ports []int  `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

// registerDevice creates a new free WARP account, mirroring `wgcf register`.
// If Cloudflare ever starts rejecting non-Android TLS fingerprints, fall back
// to `wgcf register && wgcf generate` + `warp-exit import`.
func registerDevice(model string) (*Config, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(map[string]any{
		"key":           base64.StdEncoding.EncodeToString(pub),
		"fcm_token":     "",
		"install_id":    "",
		"locale":        "en_US",
		"model":         model,
		"tos":           time.Now().UTC().Format(time.RFC3339),
		"serial_number": "",
		"os_version":    "16.0.0",
		"key_type":      "curve25519",
		"tunnel_type":   "wireguard",
	})

	req, err := http.NewRequest("POST", regAPI, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", regUserAgent)
	req.Header.Set("CF-Client-Version", regClientVer)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WARP registration request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("Cloudflare rejected registration (HTTP %d): %s\n"+
			"hint: run `wgcf register && wgcf generate`, then `warp-exit import wgcf-profile.conf`",
			resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var reg regResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, fmt.Errorf("malformed registration response: %w", err)
	}
	if len(reg.Config.Peers) == 0 {
		return nil, fmt.Errorf("registration response contains no peer")
	}
	peer := reg.Config.Peers[0]

	host := peer.Endpoint.Host
	if host == "" {
		host = peer.Endpoint.V4
	}
	if host == "" {
		host = peer.Endpoint.V6
	}
	// Strip any port/brackets; we always use ports[0] or 2408.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return nil, fmt.Errorf("registration response has no usable endpoint host")
	}
	port := 2408
	if len(peer.Endpoint.Ports) > 0 {
		port = peer.Endpoint.Ports[0]
	}

	cutPrefix := func(s string) string {
		a, _, _ := strings.Cut(s, "/")
		return a
	}
	return &Config{
		PrivateKey:    base64.StdEncoding.EncodeToString(priv[:]),
		AddressV4:     cutPrefix(reg.Config.Interface.Addresses.V4),
		AddressV6:     cutPrefix(reg.Config.Interface.Addresses.V6),
		PeerPublicKey: peer.PublicKey,
		Endpoint:      fmt.Sprintf("%s:%d", host, port),
		DeviceID:      reg.ID,
		AccessToken:   reg.Token,
		License:       reg.Acct.License,
	}, nil
}
