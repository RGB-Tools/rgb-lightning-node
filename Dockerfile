FROM rust:1.91-slim-trixie AS builder

WORKDIR /app
COPY . .

RUN apt-get update && apt install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN cargo build --release --locked


FROM debian:trixie-slim

COPY --from=builder /app/target/release/rgb-lightning-node /usr/bin/rgb-lightning-node

RUN apt-get update && apt install -y --no-install-recommends \
    ca-certificates openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/usr/bin/rgb-lightning-node"]
