# Multi-stage build for warp-tailscale-node
FROM golang:1.24-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build statically linked binary
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -v -ldflags="-s -w" -o /warp-exit .

# Final runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    iptables \
    nftables \
    iproute2 \
    procps \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

# Install official tailscale binary
RUN curl -fsSL https://tailscale.com/install.sh | sh

COPY --from=builder /warp-exit /usr/local/bin/warp-exit

# Create directories for config, status and tailscaled socket/state
RUN mkdir -p /etc/warp-exit /var/lib/warp-exit /run/warp-exit

VOLUME ["/etc/warp-exit", "/var/lib/warp-exit"]

ENTRYPOINT ["/usr/local/bin/warp-exit", "up"]
