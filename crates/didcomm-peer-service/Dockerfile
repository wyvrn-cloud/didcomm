# Built with the *workspace root* as build context (not this directory) so Cargo can see
# the whole workspace -- e.g. `docker build -f crates/didcomm-peer-service/Dockerfile .`
# from the wyrvn-didcomm repo root, or docker-compose.yml in didcomm-v2-test-util pointing
# its build context at a checkout of this repo with this as the dockerfile.
FROM rust:1-slim-bookworm AS builder

# aws-lc-rs (rustls' default crypto provider, pulled in via reqwest for did:web/did:webvh)
# builds a C library at compile time and needs a C compiler + cmake for that; nothing here
# needs OpenSSL or ring, per this workspace's askar-crypto/rustls choices (see PLAN.md §2).
RUN apt-get update && apt-get install -y --no-install-recommends cmake gcc perl && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .
# Capping concurrency trades a slower build for not getting OOM-killed in a constrained
# build environment: `cargo -j 2` limits rustc's own parallelism, but aws-lc-rs's build
# script separately shells out to cmake/make to build the AWS-LC C library, and that
# ignores cargo's -j entirely -- left uncapped it spawns one job per host CPU on its own,
# stacking on top of whatever cargo is already running concurrently.
ENV CMAKE_BUILD_PARALLEL_LEVEL=2
RUN cargo build --release -j 2 -p didcomm-peer-service

FROM debian:bookworm-slim
# curl: used by docker-compose.yml's healthcheck against GET /did. ca-certificates: without
# it, reqwest::Client::new() (built eagerly for the did:web resolver in setup_default,
# before this binary ever makes a request) panics at startup with "No CA certificates were
# loaded from the system" -- debian-slim ships no CA store at all by default.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/didcomm-peer-service /usr/local/bin/didcomm-peer-service
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/didcomm-peer-service"]
