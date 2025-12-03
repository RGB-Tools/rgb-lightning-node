FROM rust:1.91-slim-trixie AS builder

COPY . .

RUN cargo build --release


FROM debian:trixie-slim

COPY --from=builder ./target/release/rgb-lightning-node /usr/bin/rgb-lightning-node

RUN apt-get update && apt install -y --no-install-recommends \
    ca-certificates openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/usr/bin/rgb-lightning-node"]
