# Multi-stage build for lightningdevkit/rapid-gossip-sync-server (Rust)

FROM rust:1.85.0-bookworm AS builder

RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone https://github.com/lightningdevkit/rapid-gossip-sync-server.git . && \
    git checkout ad079707df0735128a64ae8bfbfe7908852ebcfb

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/rapid-gossip-sync-server /usr/local/bin/rapid-gossip-sync-server

CMD ["rapid-gossip-sync-server"]
