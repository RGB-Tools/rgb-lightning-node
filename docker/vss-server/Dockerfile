# Multi-stage build for lightningdevkit/vss-server (Rust)
# Builds with signature-based authentication (SigsAuthProvider)

# Stage 1: Build
FROM rust:1.85.0-bookworm AS builder

RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone https://github.com/lightningdevkit/vss-server.git . && \
    git checkout e4c835902cdec97676ee8d11b4fa418b23711d9e

WORKDIR /build/rust
RUN cargo build --release --no-default-features --features sigs

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/rust/target/release/vss-server /usr/local/bin/vss-server
COPY --from=builder /build/rust/server/vss-server-config.toml /etc/vss/vss-server-config.toml

EXPOSE 8080

CMD ["vss-server", "/etc/vss/vss-server-config.toml"]
