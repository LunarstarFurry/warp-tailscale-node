# Warp exit node

A standalone Tailscale exit node whose internet traffic egresses through Cloudflare WARP. The node lives in its own network namespace — the host's networking is never modified.

## Running with Docker (e.g. on Unraid)

Once published by the GitHub Action, pull the multi-arch image:

```bash
docker run -d \
  --name warp-exit-node \
  --restart unless-stopped \
  --privileged \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  -v /mnt/user/appdata/warp-exit/config:/etc/warp-exit \
  -v /mnt/user/appdata/warp-exit/data:/var/lib/warp-exit \
  -e TS_AUTHKEY="your-tailscale-or-headscale-preauth-key" \
  -e TS_CONTROL_URL="https://headscale.yourdomain.com" \
  ghcr.io/lunarstarfurry/warp-tailscale-node:latest
```

### Docker Compose
```yaml
services:
  warp-exit-node:
    image: ghcr.io/lunarstarfurry/warp-tailscale-node:latest
    container_name: warp-exit-node
    restart: unless-stopped
    privileged: true
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      - TS_AUTHKEY=your-authkey
      - TS_CONTROL_URL=https://headscale.yourdomain.com  # Optional: for Headscale
    volumes:
      - /mnt/user/appdata/warp-exit/config:/etc/warp-exit
      - /mnt/user/appdata/warp-exit/data:/var/lib/warp-exit
```

---

## Running as a Host Binary

### Build & Install
```bash
go build -o warp-exit .
sudo ./warp-exit install
```

### Run
```bash
# Official Tailscale
sudo TS_AUTHKEY="tskey-auth-..." warp-exit up

# Headscale
sudo TS_AUTHKEY="..." TS_CONTROL_URL="https://headscale.yourdomain.com" warp-exit up
```

### Commands
- `warp-exit status`: See node & tunnel state
- `warp-exit down`: Stop the node and clean up interfaces
- `warp-exit import <wgcf-profile.conf>`: Import existing WARP / WireGuard configuration
