# retail server image: retaild hosting a network (no tunnel of its own).
#
#   docker build -f packaging/docker/Dockerfile -t retail-server .
#   docker exec <container> retail server invite      # invite a device
#
# Build context is the repository root.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Patched boringtun (see vendor/boringtun/RETAIL-CHANGES.md), which Cargo
# needs for every workspace member
COPY vendor ./vendor
RUN cargo build --release -p retail-daemon -p retail-cli --locked \
 && strip target/release/retaild target/release/retail

# distroless/cc: glibc + CA certificates (needed for Let's Encrypt), no shell
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/retaild /usr/local/bin/retaild
COPY --from=build /src/target/release/retail /usr/local/bin/retail
ENV RETAIL_STATE_DIR=/data \
    RETAIL_SERVE=1 \
    RETAIL_NO_PORTMAP=1
VOLUME ["/data"]
EXPOSE 443/tcp 3478/udp
ENTRYPOINT ["/usr/local/bin/retaild"]
