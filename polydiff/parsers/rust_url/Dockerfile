# Pinned for reproducibility against devcontainer/ Rust 1.79 line.
# Two-stage: build the wrapper in rust:1.79-slim, run from
# distroless to keep the runtime image small and rootless.

FROM rust:1.79.0-slim AS build
WORKDIR /opt/parser
COPY Cargo.toml /opt/parser/Cargo.toml
COPY wrapper.rs /opt/parser/wrapper.rs
RUN cargo build --release --bin wrapper

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /opt/parser
COPY --from=build /opt/parser/target/release/wrapper /opt/parser/wrapper
USER nonroot:nonroot
ENTRYPOINT ["/opt/parser/wrapper"]
