# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p sts-cli

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system sts \
    && useradd --system --gid sts --home-dir /nonexistent --shell /usr/sbin/nologin sts

COPY --from=builder /src/target/release/sts-cli /usr/local/bin/sts-cli

USER sts:sts
EXPOSE 8888
ENTRYPOINT ["sts-cli"]
CMD ["serve"]

