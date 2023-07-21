FROM rust:1.71.0-bookworm as builder

COPY . .

RUN cargo build


FROM debian:bookworm-slim

COPY --from=builder ./target/debug/rgb-lightning-node /usr/bin/rgb-lightning-node

RUN apt-get update && apt install -y openssl

CMD ["/usr/bin/rgb-lightning-node"]
