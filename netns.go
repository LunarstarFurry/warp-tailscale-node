package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Topology: the daemon runs in a fresh anonymous netns (CLONE_NEWNET) holding
// BOTH the WARP WireGuard interface and a userspace tailscaled. The namespace's
// default route is the host veth. tailscaled's underlay UDP (magicsock, on
// pinned port tsUDPPort) is routed over the veth to the real internet so
// peers can hole-punch directly; everything else — forwarded exit-node
// payload, DERP, control — falls into the warp table (dev warp0 →
// Cloudflare) via a catch-all policy rule. The WARP endpoint handshake
// escapes via a /32 route over the same veth. The host's routing table,
// DNS, and tailscaled are never touched.
const (
	wgIface     = "warp0"
	vethHost    = "ve-warp-h"
	vethNS      = "ve-warp-n"
	hostAddr    = "10.200.200.1/30"
	nsAddr      = "10.200.200.2/30"
	nsGateway   = "10.200.200.1"
	nftTable    = "warp-exit"
	wgMTU       = 1280
	runDir      = "/run/warp-exit"
	statusPath  = runDir + "/status.json"
	pidPath     = runDir + "/daemon.pid"
	statePath   = runDir + "/state.txt"
	resolvSrc   = runDir + "/resolv.conf"
	logPath     = "/var/log/warp-exit.log"
	tsdStateDir = "/var/lib/warp-exit/tailscaled"
	tsdSocket   = runDir + "/tailscaled.sock"
	sysctlV4Fwd = "/proc/sys/net/ipv4/ip_forward"

	// tailscaled in userspace-networking mode disables its netns socket
	// control, so underlay and payload sockets are both unmarked. The
	// policy split instead uses magicsock's pinned UDP port: sport
	// tsUDPPort → main table (host veth); everything else → warpTable
	// (warp0 → Cloudflare). The port is above the kernel ephemeral
	// range (32768-60999) so forwarded payload can never collide.
	tsUDPPort           = 62416
	warpTable           = 100
	tsBypassMark uint32 = 0x80000
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func addrOf(s string) *netlink.Addr {
	a, err := netlink.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// configureWG sets the private key + Cloudflare peer on warp0 in the host
// netns, before the link is moved into the daemon's namespace.
func configureWG(cfg *Config, endpoint *net.UDPAddr) error {
	priv, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	pub, err := wgtypes.ParseKey(cfg.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}
	keepalive := 25 * time.Second
	allowed := []net.IPNet{*mustCIDR("0.0.0.0/0")}
	if cfg.AddressV6 != "" {
		allowed = append(allowed, *mustCIDR("::/0"))
	}
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice(wgIface, wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   pub,
			Endpoint:                    endpoint,
			PersistentKeepaliveInterval: &keepalive,
			AllowedIPs:                  allowed,
			ReplaceAllowedIPs:           true,
		}},
	})
}

// up builds the tunnel + namespace on the host and launches the daemon.
func up(cfg *Config) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("needs root — run with sudo")
	}
	if _, err := os.Stat("/sys/module/wireguard"); err != nil {
		return fmt.Errorf("wireguard kernel module not loaded — `modprobe wireguard`")
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return err
	}
	if daemonAlive() {
		fmt.Fprintln(os.Stderr, "existing daemon found — restarting it")
		stopDaemon()
	}
	// Resolv.conf the daemon will bind-mount: inside its namespace the only
	// reachable resolver is one reachable through the tunnel. Note 1.1.1.1
	// is blackholed inside WARP (Cloudflare intercepts its own anycast), so
	// use off-net resolvers.
	if err := os.WriteFile(resolvSrc, []byte("nameserver 9.9.9.9\nnameserver 8.8.8.8\n"), 0o644); err != nil {
		return err
	}

	// Resolve the WARP endpoint with the host's normal DNS — inside the
	// namespace there is no underlay DNS.
	endpoint, err := resolveEndpoint(cfg.Endpoint)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "endpoint %s -> %s\n", cfg.Endpoint, endpoint)

	// Spawn the daemon directly into a fresh network+mount namespace.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logf.Close()
	configPath, _ := filepath.Abs(cfgPathFlag)
	cmd := exec.Command(self, "serve", "--config", configPath)
	cmd.Env = append(os.Environ(), "WARP_EXIT_ENDPOINT_IP="+endpoint.IP.String())
	cmd.Stdout, cmd.Stderr = io.MultiWriter(os.Stdout, logf), io.MultiWriter(os.Stderr, logf)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		Setpgid:    true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn daemon: %w", err)
	}
	pid := cmd.Process.Pid
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return err
	}

	// WireGuard interface on the host, then move it into the daemon's netns.
	if l, err := netlink.LinkByName(wgIface); err == nil {
		netlink.LinkDel(l)
	}
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: wgIface}}); err != nil {
		return fmt.Errorf("create %s: %w", wgIface, err)
	}
	if err := configureWG(cfg, endpoint); err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	wg, err := netlink.LinkByName(wgIface)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetNsPid(wg, pid); err != nil {
		return fmt.Errorf("move %s into netns: %w", wgIface, err)
	}
	fmt.Fprintf(os.Stderr, "wireguard %s: peer %s @ %s (moved into daemon netns)\n", wgIface, cfg.PeerPublicKey, endpoint)

	// veth pair: host side keeps an address; peer end goes into the netns.
	if l, err := netlink.LinkByName(vethHost); err == nil {
		netlink.LinkDel(l)
	}
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: vethHost},
		PeerName:  vethNS,
	}); err != nil {
		return fmt.Errorf("create veth pair: %w", err)
	}
	vh, err := netlink.LinkByName(vethHost)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(vh, addrOf(hostAddr)); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(vh); err != nil {
		return err
	}
	vn, err := netlink.LinkByName(vethNS)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetNsPid(vn, pid); err != nil {
		return fmt.Errorf("move %s into netns: %w", vethNS, err)
	}

	// Host NAT for the namespace's underlay (WG handshake only), and
	// forwarding — remembering the previous value for `down`.
	state := loadState()
	if state.IPForward == "" {
		state.IPForward = sysctlGet(sysctlV4Fwd)
		saveState(state)
	}
	sysctlSet(sysctlV4Fwd, "1")
	if err := hostNAT(); err != nil {
		return err
	}

	fmt.Printf("\ndaemon started (pid %d)\nlogs: %s\n", pid, logPath)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		teardown()
		os.Exit(0)
	}()
	_ = waitForLogin()
	return cmd.Wait()
}

// waitForLogin watches the daemon's status file and surfaces the auth URL —
// no log-file digging needed on first run.
func waitForLogin() error {
	var loggedURL bool
	deadline := time.Now().Add(15 * time.Minute)
	var approveDeadline time.Time
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(statusPath); err == nil {
			var s nodeStatus
			if json.Unmarshal(b, &s) == nil {
				switch {
				case s.BackendState == "Running":
					if !s.AdvertiseExitNode {
						if approveDeadline.IsZero() {
							approveDeadline = time.Now().Add(10 * time.Second)
						}
						if time.Now().Before(approveDeadline) {
							break
						}
					}
					fmt.Printf("\nnode online: %s", strings.Join(s.TailscaleIPs, ", "))
					if s.AdvertiseExitNode {
						fmt.Println(" — exit-node routes approved")
					} else {
						fmt.Println(" — approve exit-node routes in the admin console")
					}
					return nil
				case s.AuthURL != "" && !loggedURL:
					fmt.Printf("\nnode login required — open:\n\n  %s\n\n", s.AuthURL)
					fmt.Println("waiting for node registration on Headscale...")
					loggedURL = true
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Println("timed out waiting for login")
	return nil
}

// hostNAT installs an inet table masquerading the veth subnet.
func hostNAT() error {
	c := &nftables.Conn{}
	// Drop a stale table first (idempotent re-up); ignore failure.
	d := &nftables.Conn{}
	d.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable})
	d.Flush()

	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable})
	ch := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    t,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	c.AddRule(&nftables.Rule{
		Table: t,
		Chain: ch,
		Exprs: []expr.Any{
			// ip saddr 10.200.200.0/30 → masquerade
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: net.IP{255, 255, 255, 252}, Xor: net.IP{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: net.IP{10, 200, 200, 0}},
			&expr.Masq{},
		},
	})
	return c.Flush()
}

// teardown stops the daemon and removes the links/NAT it created.
func teardown() {
	stopDaemon()

	if l, err := netlink.LinkByName(vethHost); err == nil {
		netlink.LinkDel(l)
	}
	if l, err := netlink.LinkByName(wgIface); err == nil {
		netlink.LinkDel(l)
	}
	c := &nftables.Conn{}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable})
	_ = c.Flush()

	if state := loadState(); state.IPForward != "" && state.IPForward != "1" {
		sysctlSet(sysctlV4Fwd, state.IPForward)
	}
	os.RemoveAll(runDir)
}

// down stops the daemon; its anonymous netns (and everything in it) dies with it.
func down() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("needs root — run with sudo")
	}
	teardown()
	fmt.Println("warp-exit-node torn down.")
	return nil
}

// daemonAlive reports whether the pid recorded in the pidfile is a live
// process. EPERM counts as alive (owned by root, we're not).
func daemonAlive() bool {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return false
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

func stopDaemon() {
	b, err := os.ReadFile(pidPath)
	if err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 0 {
			stopPID(pid)
		}
	}
	// Sweep daemons that leaked without a pidfile (crashed `up`s etc.) —
	// matched by our internal subcommand / state dir so the host's own
	// tailscaled is never touched.
	for _, pid := range findOurDaemons() {
		stopPID(pid)
	}
}

func findOurDaemons() []int {
	var pids []int
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return pids
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		cmd := string(b)
		if strings.Contains(cmd, "warp-exit\x00serve") || strings.Contains(cmd, tsdStateDir) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func stopPID(pid int) {
	fmt.Fprintf(os.Stderr, "stopping daemon pid %d\n", pid)
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(syscall.SIGTERM)
	for range 50 {
		if err := p.Signal(syscall.Signal(0)); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = p.Kill()
}

// --- tiny saved state (host ip_forward restore) ---

type savedState struct{ IPForward string }

func loadState() savedState {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return savedState{}
	}
	return savedState{IPForward: strings.TrimSpace(string(b))}
}

func saveState(s savedState) {
	_ = os.WriteFile(statePath, []byte(s.IPForward), 0o644)
}

func sysctlGet(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func sysctlSet(path, value string) {
	fmt.Fprintf(os.Stderr, "sysctl %s = %s\n", path, value)
	_ = os.WriteFile(path, []byte(value), 0o644)
}
