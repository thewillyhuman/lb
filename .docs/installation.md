# Installation

## Prerequisites

- **Rust toolchain** -- stable channel (1.75+). The project pins to stable via `rust-toolchain.toml`.
- **cargo** -- comes with the Rust toolchain.

No other system dependencies are required for development builds. The project uses `MockIo` by default, so all crates compile and test on macOS and Linux without kernel bypass libraries.

### Production (Linux only)

For kernel bypass packet I/O, additional dependencies are needed depending on the chosen backend:

| Backend | Feature flag | Dependencies |
|---------|-------------|--------------|
| AF_XDP | `af-xdp` | Linux >= 4.18, libbpf headers, `CAP_NET_ADMIN`. The backend is currently a scaffold and returns `Err(Unsupported)` at init — a proper XSK-ring implementation is planned; see the roadmap note in `crates/lb-io/src/af_xdp.rs` |

## Building from source

```bash
git clone https://github.com/thewillyhuman/lb.git
cd lb
cargo build --release
```

Binaries are at:
- `target/release/lb-node` -- main LB node (forwarder + controller)
- `target/release/lb-trace` -- packet tracing CLI

### With AF_XDP support (Linux)

```bash
cargo build --release --features lb-io/af-xdp
```

> The DPDK backend was removed (see PR 4 / commit removing `crates/lb-io/src/dpdk.rs`). Strategic direction is AF_XDP only — kernel-native, no userspace SDK toolchain.

## Cross-compilation (static binary)

For deployment on minimal containers (`scratch`, `distroless`), build a fully static binary with musl:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The resulting binary has no runtime dependencies beyond the kernel.

## Verify the build

```bash
# Check the binary runs
./target/release/lb-node --help

# Validate the example config
./target/release/lb-node --config config/lb.example.toml --check-config

# Run the test suite (159 tests)
cargo test --workspace

# Run clippy
cargo clippy --workspace --all-targets

# Run benchmarks
cargo bench -p lb-hashing
cargo bench -p lb-forwarder
cargo bench -p lb-controller
```

## Docker

Example `Dockerfile` for a minimal image:

```dockerfile
FROM rust:latest AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/lb-node /usr/local/bin/lb-node
COPY config/ /etc/lb/
EXPOSE 9090/tcp
ENTRYPOINT ["lb-node", "--config", "/etc/lb/config.toml"]
```

For a static musl build, replace the builder target and use `FROM scratch` as the runtime image.

## System preparation (Linux production)

### Hugepages (AF_XDP / DPDK)

```bash
# Allocate 1024 x 2MB hugepages
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Make persistent across reboots
echo "vm.nr_hugepages = 1024" >> /etc/sysctl.conf
```

### CPU isolation (recommended)

Isolate cores for the forwarder threads to avoid scheduler interference:

```bash
# In /etc/default/grub
GRUB_CMDLINE_LINUX="isolcpus=1-8 nohz_full=1-8 rcu_nocbs=1-8"
```

### File descriptor limits

```bash
# In /etc/security/limits.conf
* soft nofile 1048576
* hard nofile 1048576
```
