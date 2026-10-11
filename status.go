package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

func status(cfg *Config) {
	if cfg != nil {
		v6 := cfg.AddressV6
		if v6 == "" {
			v6 = "none"
		}
		fmt.Printf("config:    endpoint=%s v4=%s v6=%s hostname=%s\n",
			cfg.Endpoint, cfg.AddressV4, v6, cfg.hostname())
	} else {
		fmt.Println("config:    none (run `warp-exit up` — registers automatically — or `import`)")
	}

	// host-side link (peer + warp0 live in the daemon's netns)
	_, err := netlink.LinkByName(vethHost)
	fmt.Printf("underlay:  %s\n", map[bool]string{true: "up", false: "down"}[err == nil])

	if b, err := os.ReadFile(pidPath); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		alive := false
		if p, err := os.FindProcess(pid); err == nil {
			// EPERM means the daemon exists but is owned by root
			// and status was run without sudo.
			err = p.Signal(syscall.Signal(0))
			alive = err == nil || errors.Is(err, syscall.EPERM)
		}
		fmt.Printf("daemon:    pid %d (%s)\n", pid, map[bool]string{true: "running", false: "dead"}[alive])
	} else {
		fmt.Println("daemon:    not running")
	}

	if b, err := os.ReadFile(statusPath); err == nil {
		var s nodeStatus
		if json.Unmarshal(b, &s) == nil {
			if age := time.Since(s.Updated); age > 15*time.Second {
				fmt.Printf("tailscale: (status stale, %ds old — daemon may be dead)\n", int(age.Seconds()))
			}
			exit := "false"
			switch {
			case s.AdvertiseExitNode:
				exit = "approved"
			case s.WantsExitNode:
				exit = "awaiting admin approval"
			}
			fmt.Printf("tailscale: state=%s ips=[%s] advertise_exit=%s\n",
				s.BackendState, strings.Join(s.TailscaleIPs, ","), exit)
			if s.AuthURL != "" {
				fmt.Printf("login:     %s\n", s.AuthURL)
			}
			hs := "never"
			if s.WGHandshakeAgoSecs != nil {
				hs = fmt.Sprintf("%ds ago", *s.WGHandshakeAgoSecs)
			}
			fmt.Printf("warp:      handshake=%s rx=%dB tx=%dB\n", hs, s.WGRxBytes, s.WGTxBytes)
		}
	}
}
