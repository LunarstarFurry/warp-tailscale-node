package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

// nodeStatus is what the daemon periodically writes to /run/warp-exit/status.json.
type nodeStatus struct {
	Updated            time.Time `json:"updated"`
	BackendState       string    `json:"backend_state"`
	AuthURL            string    `json:"auth_url,omitempty"`
	TailscaleIPs       []string  `json:"tailscale_ips,omitempty"`
	AdvertiseExitNode  bool      `json:"advertise_exit_node"`
	WantsExitNode      bool      `json:"wants_exit_node"`
	WGHandshakeAgoSecs *int64    `json:"wg_handshake_ago_secs,omitempty"`
	WGRxBytes          int64     `json:"wg_rx_bytes"`
	WGTxBytes          int64     `json:"wg_tx_bytes"`
}

// serve runs inside the fresh CLONE_NEWNET|CLONE_NEWNS namespace created by
// `up`. It waits for the host to move warp0 + ve-warp-n in, configures
// addresses/routes, then spawns a real tailscaled in userspace mode and
// drives it over its localapi socket. A real tailscaled (unlike tsnet)
// creates an OS DNS configurator that reads our resolv.conf, so clients
// using this node as an exit get their DNS resolved via 1.1.1.1 over WARP.
func serve(cfg *Config) error {
	log.SetOutput(os.Stderr)
	log.SetPrefix("[warp-exit] ")

	if err := setupNetNS(cfg); err != nil {
		return err
	}
	log.Printf("netns ready: %s default via veth, payload via %s", nsAddr, wgIface)

	tsd, err := startTailscaled()
	if err != nil {
		return err
	}
	defer tsd.Process.Kill()
	tsdDied := make(chan error, 1)
	go func() { tsdDied <- tsd.Wait() }()

	ctx := context.Background()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	lc := &local.Client{Socket: tsdSocket}
	if err := waitLocalAPI(lc, sig, tsdDied); err != nil {
		return err
	}
	if err := lc.Start(ctx, ipn.Options{
		AuthKey: os.Getenv("TS_AUTHKEY"),
		UpdatePrefs: &ipn.Prefs{
			ControlURL:  os.Getenv("TS_CONTROL_URL"),
			Hostname:    cfg.hostname(),
			WantRunning: true,
		},
	}); err != nil {
		return fmt.Errorf("tailscaled start: %w", err)
	}

	wgc, _ := wgctrl.New() // we are inside the netns: sees warp0
	defer func() {
		if wgc != nil {
			wgc.Close()
		}
	}()

	advertised, loggedURL, loginStarted := false, false, false
	var lastAuthURL string
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		st, err := lc.Status(ctx)
		if err == nil {
			s := collectStatus(st, wgc)
			if prefs, err := lc.GetPrefs(ctx); err == nil {
				s.WantsExitNode = wantsExitNode(prefs.AdvertiseRoutes)
			}
			// tailscaled clears AuthURL once it thinks the URL was shown;
			// keep publishing the last one while login is still needed.
			if s.AuthURL != "" {
				lastAuthURL = s.AuthURL
			} else if st.BackendState == "NeedsLogin" {
				s.AuthURL = lastAuthURL
			}
			writeStatus(s)
			// Start alone doesn't fetch an auth URL — the interactive
			// login flow must be kicked explicitly (same as `tailscale up`
			// does on a node without a node key).
			if st.BackendState == "NeedsLogin" && !loginStarted {
				if err := lc.StartLoginInteractive(ctx); err != nil {
					log.Printf("start interactive login: %v", err)
				} else {
					loginStarted = true
				}
			}
			if s.AuthURL != "" && !loggedURL {
				log.Printf("tailscale login required: %s", s.AuthURL)
				loggedURL = true
			}
			if st.BackendState == "Running" && !advertised {
				if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
					Prefs: ipn.Prefs{AdvertiseRoutes: []netip.Prefix{
						netip.MustParsePrefix("0.0.0.0/0"),
						netip.MustParsePrefix("::/0"),
					}},
					AdvertiseRoutesSet: true,
				}); err != nil {
					log.Printf("advertise exit node: %v", err)
				} else {
					advertised = true
					log.Printf("advertising exit node as %q", cfg.hostname())
				}
			}
		}
		select {
		case <-sig:
			log.Printf("shutting down")
			return nil
		case err := <-tsdDied:
			return fmt.Errorf("tailscaled exited: %w", err)
		case <-tick.C:
		}
	}
}

// startTailscaled spawns tailscaled as a child process in this namespace.
// -tun=userspace-networking gives it gVisor netstack so exit-node forwarding
// needs no TUN device and no kernel ip_forward inside the netns.
func startTailscaled() (*exec.Cmd, error) {
	bin, err := exec.LookPath("tailscaled")
	if err != nil {
		return nil, fmt.Errorf("tailscaled not found in PATH — install the tailscale package")
	}
	if err := os.MkdirAll(tsdStateDir, 0o700); err != nil {
		return nil, err
	}
	os.Remove(tsdSocket) // stale socket from a previous run
	cmd := exec.Command(bin,
		"-statedir", tsdStateDir,
		"-socket", tsdSocket,
		"-tun", "userspace-networking",
		// Pin magicsock's UDP port: userspace-networking disables
		// netns.SetEnabled, so tailscaled's sockets can carry neither
		// SO_MARK nor SO_BINDTODEVICE — the fixed listen port is the
		// only discriminator policy routing can use to steer its
		// underlay traffic (STUN, disco, WireGuard) onto the host veth.
		"-port", fmt.Sprint(tsUDPPort),
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn tailscaled: %w", err)
	}
	log.Printf("tailscaled started (pid %d)", cmd.Process.Pid)
	return cmd, nil
}

// waitLocalAPI blocks until tailscaled's socket answers Status.
func waitLocalAPI(lc *local.Client, sig chan os.Signal, died chan error) error {
	ctx := context.Background()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := lc.StatusWithoutPeers(ctx); err == nil {
			return nil
		}
		select {
		case <-sig:
			return fmt.Errorf("interrupted")
		case err := <-died:
			return fmt.Errorf("tailscaled exited during startup: %w", err)
		case <-time.After(300 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out waiting for tailscaled localapi at %s", tsdSocket)
}

// setupNetNS isolates this process's mounts, then waits for warp0/ve-warp-n
// to be moved in by the parent and applies addresses + routes.
func setupNetNS(cfg *Config) error {
	// Private mount propagation so the resolv.conf bind-mount can't leak
	// back to the host.
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := unix.Mount(resolvSrc, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind resolv.conf: %w", err)
	}
	// Read-only so tailscaled's DNS manager can't rewrite it — keeps both
	// the daemon's own lookups and the forwarder's upstream pinned to
	// 1.1.1.1 via warp0.
	if err := unix.Mount("", "/etc/resolv.conf", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("ro resolv.conf: %w", err)
	}
	// Hide the host's system DBus so tailscaled's DNS probe picks "direct"
	// mode and reads the resolv.conf above, instead of adopting the host's
	// systemd-resolved upstreams.
	for _, sock := range []string{"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket"} {
		if _, err := os.Stat(sock); err != nil {
			continue
		}
		if err := unix.Mount("/dev/null", sock, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("shadow %s: %w", sock, err)
		}
	}

	// Parent moves links in after spawn — wait for them.
	deadline := time.Now().Add(20 * time.Second)
	var veth, wg netlink.Link
	for time.Now().Before(deadline) {
		if veth == nil {
			veth, _ = netlink.LinkByName(vethNS)
		}
		if wg == nil {
			wg, _ = netlink.LinkByName(wgIface)
		}
		if veth != nil && wg != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if veth == nil || wg == nil {
		return fmt.Errorf("timed out waiting for parent to move links in (veth=%v wg=%v)", veth != nil, wg != nil)
	}

	if lo, err := netlink.LinkByName("lo"); err == nil {
		netlink.LinkSetUp(lo)
	}
	if err := netlink.AddrAdd(veth, addrOf(nsAddr)); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		return err
	}

	// Underlay: the default route goes via the host veth — tailscaled's
	// own traffic (control, DERP, magicsock) reaches the real internet
	// whether its sockets are fwmarked or SO_BINDTODEVICE'd to the
	// default-route interface.
	epIP := net.ParseIP(os.Getenv("WARP_EXIT_ENDPOINT_IP"))
	if epIP == nil {
		return fmt.Errorf("missing WARP_EXIT_ENDPOINT_IP")
	}
	vethRoute := func(dst *net.IPNet, gw net.IP, table int) error {
		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: veth.Attrs().Index,
			Dst:       dst,
			Gw:        gw,
			Table:     table,
		})
	}
	epCIDR := mustCIDR(epIP.String() + "/32")
	for _, table := range []int{unix.RT_TABLE_MAIN, warpTable} {
		if err := vethRoute(epCIDR, net.ParseIP(nsGateway), table); err != nil {
			return fmt.Errorf("endpoint route table %d: %w", table, err)
		}
	}
	// The warp table also needs to reach the veth peer — payload replies
	// to the host side route back through it.
	if err := vethRoute(mustCIDR("10.200.200.0/30"), nil, warpTable); err != nil {
		return fmt.Errorf("warp-table subnet route: %w", err)
	}
	if err := vethRoute(nil, net.ParseIP(nsGateway), unix.RT_TABLE_MAIN); err != nil {
		return fmt.Errorf("underlay default route: %w", err)
	}

	// WARP addresses on warp0.
	if err := netlink.AddrAdd(wg, addrOf(cfg.AddressV4+"/32")); err != nil {
		return err
	}
	if cfg.AddressV6 != "" {
		if err := netlink.AddrAdd(wg, addrOf(cfg.AddressV6+"/128")); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetMTU(wg, wgMTU); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(wg); err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: wg.Attrs().Index,
		Dst:       mustCIDR("0.0.0.0/0"),
		Table:     warpTable,
	}); err != nil {
		return fmt.Errorf("warp default route: %w", err)
	}
	if cfg.AddressV6 != "" {
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: wg.Attrs().Index,
			Dst:       mustCIDR("::/0"),
			Table:     warpTable,
		}); err != nil {
			return fmt.Errorf("warp v6 default route: %w", err)
		}
	}
	return setupPolicyRouting()
}

// setupPolicyRouting steers traffic inside the netns. tailscaled runs
// in userspace-networking mode, which disables its netns socket control
// entirely — every socket it creates is plain, so underlay and payload
// are indistinguishable by mark. The discriminators that DO work:
//
//   - magicsock's UDP source port is pinned via -port (tsUDPPort);
//     routing it via the main table sends STUN/disco/peer WireGuard
//     over the host veth, so the advertised endpoint is the host's real
//     NAT address and direct peer connections can form. Without this,
//     the only public endpoint is a WARP address that can never receive
//     inbound packets — every peer stays on a DERP relay and throughput
//     collapses.
//   - Everything else (forwarded exit-node payload, DERP/control TCP)
//     falls into the warp table → warp0 → Cloudflare.
func setupPolicyRouting() error {
	for _, p := range []string{
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/" + vethNS + "/rp_filter",
	} {
		_ = os.WriteFile(p, []byte("2"), 0o644)
	}
	port := netlink.NewRulePortRange(tsUDPPort, tsUDPPort)
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		r := netlink.NewRule()
		r.Priority, r.IPProto, r.Sport = 80, unix.IPPROTO_UDP, port
		r.Table, r.Family = unix.RT_TABLE_MAIN, fam
		if err := netlink.RuleAdd(r); err != nil {
			return fmt.Errorf("underlay sport rule af%d: %w", fam, err)
		}
	}
	mask := tsBypassMark
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		r := netlink.NewRule()
		r.Priority, r.Mark, r.Mask, r.Invert = 100, tsBypassMark, &mask, true
		r.Table, r.Family = warpTable, fam
		if err := netlink.RuleAdd(r); err != nil {
			return fmt.Errorf("payload warp rule af%d: %w", fam, err)
		}
	}
	return nil
}

func collectStatus(st *ipnstate.Status, wgc *wgctrl.Client) nodeStatus {
	s := nodeStatus{
		Updated:      time.Now(),
		BackendState: st.BackendState,
		AuthURL:      st.AuthURL,
	}
	for _, ip := range st.TailscaleIPs {
		s.TailscaleIPs = append(s.TailscaleIPs, ip.String())
	}
	if st.Self != nil {
		// ExitNodeOption is the same check `tailscale status` uses for
		// "offers exit node" — control-approved exit routes land in the
		// node's AllowedIPs, not PrimaryRoutes.
		s.AdvertiseExitNode = st.Self.ExitNodeOption
	}
	if wgc != nil {
		if dev, err := wgc.Device(wgIface); err == nil && len(dev.Peers) > 0 {
			p := dev.Peers[0]
			s.WGRxBytes, s.WGTxBytes = p.ReceiveBytes, p.TransmitBytes
			if !p.LastHandshakeTime.IsZero() {
				ago := int64(time.Since(p.LastHandshakeTime).Seconds())
				s.WGHandshakeAgoSecs = &ago
			}
		}
	}
	return s
}

// wantsExitNode reports whether the route set contains the v4 exit-node
// route.
func wantsExitNode(routes []netip.Prefix) bool {
	for _, r := range routes {
		if r == netip.MustParsePrefix("0.0.0.0/0") {
			return true
		}
	}
	return false
}

func writeStatus(s nodeStatus) {
	_ = os.MkdirAll(filepath.Dir(statusPath), 0o755)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(statusPath, b, 0o644)
}
