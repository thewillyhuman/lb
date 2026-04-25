# Multi-stage Dockerfile for `lb-node`.
#
# Stage 1 builds the binary against a pinned Rust toolchain so the image is
# reproducible — bumping the Rust version is an explicit edit. We build for
# the host's native target by default; cross-compiles can be driven from the
# release workflow via `--platform=linux/amd64,linux/arm64`.
#
# Stage 2 ships only the runtime artifact + the systemd unit + the
# config helpers. The base image is a stripped Debian slim — `distroless`
# would be smaller but breaks `lb-node --check-config` debug ergonomics
# and leaves the operator with no shell to inspect the live container.
#
# Image is *not* the recommended deploy path for production (we ship as
# a systemd service per `deploy/lb-node.service`); it exists for CI
# integration tests and for environments that already standardise on
# container delivery.

FROM rust:1.87-bookworm AS builder
WORKDIR /src

# Copy the manifest first to maximise Docker layer caching: the dep build
# only re-runs when Cargo.lock or any Cargo.toml changes.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# `--locked` so the build fails if Cargo.lock is out of date; this is a
# release artifact, not a dev iteration.
RUN cargo build --release --locked --bin lb-node


FROM debian:bookworm-slim AS runtime
ARG VERSION=unknown
ARG REVISION=unknown

LABEL org.opencontainers.image.title="lb-node"
LABEL org.opencontainers.image.description="Maglev-inspired L4 load balancer"
LABEL org.opencontainers.image.source="https://github.com/thewillyhuman/lb"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"

# Minimal runtime deps. `ca-certificates` is needed for HTTPS health
# probes (rustls verifies against the system trust store).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user. The systemd unit grants the necessary
# capabilities at the host level; in a container, the operator is
# responsible for `--cap-add=NET_ADMIN --cap-add=NET_RAW` (and
# `--cap-add=BPF` if using AF_XDP).
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 65532 lb-node \
 && mkdir -p /var/lib/lb /etc/lb \
 && chown lb-node:lb-node /var/lib/lb

COPY --from=builder /src/target/release/lb-node /usr/local/bin/lb-node
COPY deploy/lb-node.service /usr/lib/systemd/system/lb-node.service

USER lb-node
EXPOSE 9100

ENTRYPOINT ["/usr/local/bin/lb-node"]
CMD ["--config", "/etc/lb/config.toml"]
