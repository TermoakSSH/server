# syntax=docker/dockerfile:1
# Termoak server image.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml build.rs ./
COPY src ./src
COPY web ./web
COPY locales ./locales
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/termoak-server /usr/local/bin/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssh-client tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /var/lib/termoak --create-home termoak
COPY --from=build /usr/local/bin/termoak-server /usr/local/bin/
COPY deploy/config.example.toml /etc/termoak/config.toml
ENV TERMOAK_CONFIG=/etc/termoak/config.toml \
    TERMOAK_DATA_DIR=/var/lib/termoak \
    TERMOAK_LISTEN=0.0.0.0:7722
USER termoak
VOLUME ["/var/lib/termoak"]
EXPOSE 7722
ENTRYPOINT ["/usr/bin/tini", "--", "termoak-server"]
CMD ["serve"]
