# ── Stage 1: Build reconkit ───────────────────────────────────────────────────
FROM golang:1.23-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o reconkit ./cmd/recon

# ── Stage 2: Download ProjectDiscovery tool binaries ─────────────────────────
FROM debian:bookworm-slim AS tools

ARG HTTPX_VERSION=1.9.0
ARG SUBFINDER_VERSION=2.6.6
ARG DNSX_VERSION=1.2.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
        -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip httpx -d /usr/local/bin \
    && chmod +x /usr/local/bin/httpx

RUN curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
        -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip subfinder -d /usr/local/bin \
    && chmod +x /usr/local/bin/subfinder

RUN curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip" \
        -o /tmp/dnsx.zip \
    && unzip -q /tmp/dnsx.zip dnsx -d /usr/local/bin \
    && chmod +x /usr/local/bin/dnsx

# ── Stage 3: Final image ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

# System packages: nmap + tools + chromium for httpx -ss
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        git \
        dnsutils \
        ca-certificates \
        curl \
        chromium \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery binaries from stage 2
COPY --from=tools /usr/local/bin/httpx      /usr/local/bin/httpx
COPY --from=tools /usr/local/bin/subfinder  /usr/local/bin/subfinder
COPY --from=tools /usr/local/bin/dnsx       /usr/local/bin/dnsx

# reconkit binary from stage 1
COPY --from=builder /build/reconkit /usr/local/bin/reconkit

# Default Docker config (paths point to mounted volumes)
COPY config.docker.yaml /etc/reconkit/config.yaml

# Persistent data directories
RUN mkdir -p /data /scan_results /reports /screenshots

VOLUME ["/data", "/scan_results", "/reports", "/screenshots"]

# Entrypoint injects -config so the default is always the Docker config.
# Users can override by mounting their own file at /etc/reconkit/config.yaml.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["web"]
