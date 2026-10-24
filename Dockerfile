# syntax=docker/dockerfile:1

# Build natively on runner architecture using Go's built-in cross compilation
FROM --platform=$BUILDPLATFORM golang:bookworm AS builder

WORKDIR /src

# Allow Go to automatically download required toolchain (e.g. go1.27 for tailscale.com)
ENV GOTOOLCHAIN=auto

COPY go.mod go.sum ./
COPY . .

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w" -o /warp-exit .

# Final runtime image for target platform
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    iptables \
    nftables \
    iproute2 \
    procps \
    wireguard-tools \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install official tailscale via package repository
RUN mkdir -p /usr/share/keyrings /etc/apt/sources.list.d && \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null && \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list && \
    apt-get update && apt-get install -y --no-install-recommends tailscale && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /warp-exit /usr/local/bin/warp-exit

# Create directories for config, status and tailscaled socket/state
RUN mkdir -p /etc/warp-exit /var/lib/warp-exit /run/warp-exit

VOLUME ["/etc/warp-exit", "/var/lib/warp-exit"]

ENTRYPOINT ["/usr/local/bin/warp-exit", "up"]
