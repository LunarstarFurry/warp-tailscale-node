// Command warp-exit runs a standalone Tailscale exit node ("warp-exit-node")
// whose internet traffic egresses through Cloudflare WARP. The node lives in
// its own network namespace — the host's networking is never modified.
package main

import (
	"errors"
	"fmt"
	"os"
)

var cfgPathFlag string

func usage() {
	fmt.Fprintf(os.Stderr, `warp-exit — a Tailscale exit node egressing through Cloudflare WARP

usage: warp-exit <command> [flags]

  up                        build the namespace + tunnel and start the node
                            (registers a WARP device on first run)
  down                      stop the node and remove the tunnel
  status                    show node/tunnel state
  import <wgcf-profile>     import an existing WireGuard/WARP profile
  install                   copy this binary to %s
  uninstall [--keep-config] stop the node and remove all state

flags: --config <path>  (default /etc/warp-exit/config.toml, env WARP_EXIT_CONFIG)
env:   TS_AUTHKEY, TS_CONTROL_URL — used by the node when started with 'up'
`, installPath)
	os.Exit(2)
}

func main() {
	args := os.Args[1:]
	// crude flag parse: pull --config out wherever it appears
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			cfgPathFlag = args[i+1]
			i++
		} else {
			rest = append(rest, args[i])
		}
	}
	if cfgPathFlag == "" {
		cfgPathFlag = os.Getenv("WARP_EXIT_CONFIG")
	}
	if cfgPathFlag == "" {
		cfgPathFlag = "/etc/warp-exit/config.toml"
	}
	if len(rest) == 0 {
		usage()
	}

	fail := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}

	switch rest[0] {
	case "import":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: warp-exit import <wgcf-profile.conf>")
			os.Exit(2)
		}
		cfg, err := importWgcf(rest[1])
		fail(err)
		fail(cfg.save(cfgPathFlag))
		fmt.Println("Imported", rest[1], "->", cfgPathFlag)

	case "up":
		cfg, err := loadConfig(cfgPathFlag)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "no config — registering a new WARP device\n")
			cfg, err = registerDevice(defaultPeerName)
			fail(err)
			fail(cfg.save(cfgPathFlag))
			fmt.Fprintf(os.Stderr, "registered %s (config: %s)\n", cfg.AddressV4, cfgPathFlag)
		}
		fail(err)
		fail(up(cfg))

	case "down":
		fail(down())

	case "status":
		cfg, _ := loadConfig(cfgPathFlag)
		status(cfg)

	case "install":
		fail(install())

	case "uninstall":
		keep := len(rest) > 1 && rest[1] == "--keep-config"
		fail(uninstall(keep))

	case "serve": // internal: runs inside the netns
		cfg, err := loadConfig(cfgPathFlag)
		fail(err)
		fail(serve(cfg))

	default:
		usage()
	}
}
