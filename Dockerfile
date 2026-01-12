# Build stage
FROM rust:1.92 AS builder

WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release binary
RUN cargo build --release -p kasa-prometheus

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/kasa-prometheus /usr/local/bin/

EXPOSE 9101

ENTRYPOINT ["kasa-prometheus"]
CMD ["--listen", "0.0.0.0:9101"]
