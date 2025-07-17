FROM rust:1.89-slim-bookworm AS builder

COPY . .

RUN cargo build


FROM debian:bookworm-slim

COPY --from=builder ./target/debug/rgb-lightning-node /usr/bin/rgb-lightning-node

RUN apt-get update && apt install -y --no-install-recommends \
    ca-certificates openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/usr/bin/rgb-lightning-node"]
