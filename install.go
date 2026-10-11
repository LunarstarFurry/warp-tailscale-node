package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const installPath = "/usr/local/bin/warp-exit"

// install copies the running binary to a system location.
func install() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("needs root — run with sudo")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	if self == installPath {
		fmt.Println("already installed at", installPath)
		return nil
	}
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(installPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	fmt.Println("installed to", installPath)
	fmt.Println("next: sudo warp-exit up")
	return nil
}

// uninstall stops the node, removes all state, and removes the installed
// binary. The tailnet machine and the WARP device registration persist
// server-side — delete the node in the admin console if wanted.
func uninstall(keepConfig bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("needs root — run with sudo")
	}
	teardown()

	removed := func(path string) {
		if err := os.RemoveAll(path); err == nil {
			fmt.Println("removed", path)
		} else {
			fmt.Fprintf(os.Stderr, "warning: cannot remove %s: %v\n", path, err)
		}
	}
	removed("/var/lib/warp-exit")     // node + tailscaled state
	removed("/var/log/warp-exit.log") // daemon log
	if !keepConfig {
		if filepath.Dir(cfgPathFlag) == "/etc/warp-exit" {
			removed("/etc/warp-exit") // config + WARP keys
		} else {
			removed(cfgPathFlag) // custom --config path: remove the file only
		}
	}
	// Safe to unlink even while running from it on Linux.
	removed(installPath)

	fmt.Println("uninstalled.")
	fmt.Println("note: the node still appears in the tailnet admin console — delete it there if unused.")
	return nil
}
