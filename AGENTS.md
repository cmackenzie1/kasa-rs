# AGENTS.md - Coding Agent Guidelines for kasa-rs

This document provides guidelines for AI coding agents working on the kasa-rs codebase.

## Project Overview

kasa-rs is a Rust workspace for communicating with TP-Link Kasa smart home devices. It supports multiple protocols:

- **Legacy XOR** - Simple XOR autokey cipher over TCP/UDP port 9999 (older devices)
- **KLAP v1/v2** - HTTP-based protocol with AES encryption on port 80 (newer firmware)
- **TPAP** - TLS-based protocol with SPAKE2+ authentication on port 4433 (newest devices)

Devices using KLAP or TPAP require TP-Link cloud credentials (`KASA_USERNAME`/`KASA_PASSWORD`).

### Workspace Structure

```
kasa-rs/
├── Cargo.toml              # Workspace configuration (Rust 2024 edition, resolver v3)
├── crates/
│   ├── kasa/               # CLI binary (clap-based)
│   │   └── src/main.rs
│   ├── kasa-core/          # Core async library (tokio-based)
│   │   └── src/lib.rs
│   └── kasa-prometheus/    # Prometheus metrics exporter
│       └── src/main.rs
```

## Build, Test, and Lint Commands

### Build

```bash
cargo build                    # Build all crates
cargo build -p kasa            # Build specific crate
cargo build --release          # Release build
```

### Test

```bash
cargo test                              # Run all tests (unit + doctests)
cargo test -p kasa-core                 # Run tests for specific crate
cargo test test_encrypt_decrypt_roundtrip  # Run a single test by name
cargo test encrypt                      # Run tests matching a pattern
cargo test --lib                        # Run only unit tests (no doctests)
cargo test --doc                        # Run only doctests
cargo test -- --nocapture               # Run tests with output shown
```

### Lint and Format

```bash
# Run clippy (must pass with no warnings - CI enforces -D warnings)
cargo clippy --all-targets --all-features -- -D warnings

cargo fmt              # Format code
cargo fmt --check      # Check formatting without modifying
cargo doc --open       # Generate documentation
```

## Code Style Guidelines

### Rust Edition and Toolchain

- **Edition**: Rust 2024
- **Resolver**: Version 3
- **Minimum supported Rust version**: Latest stable

### Import Organization

Imports should be organized in this order, separated by blank lines:

1. Standard library (`std::`)
2. External crates (alphabetically)
3. Workspace crates (`kasa_core::`)
4. Local modules (`crate::`, `super::`, `self::`)

```rust
use std::{net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tracing::debug;

use kasa_core::{commands, send_command, DEFAULT_PORT};
```

### Naming Conventions

- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `DEFAULT_PORT`, `BROADCAST_ADDR`)
- **Functions**: `snake_case` (e.g., `send_command`, `encrypt_udp`)
- **Types/Structs**: `PascalCase` (e.g., `DiscoveredDevice`, `BroadcastResult`)
- **Modules**: `snake_case`
- **Crate names**: `kebab-case` in Cargo.toml, `snake_case` when importing

### Type Annotations

- Prefer explicit types for public API function signatures
- Use type inference for local variables when the type is obvious
- Always annotate `Duration`, `IpAddr`, and other non-obvious types

### Error Handling

- Use `std::io::Result<T>` for I/O operations
- Create descriptive error messages with context:

```rust
Err(std::io::Error::new(
    std::io::ErrorKind::TimedOut,
    "Connection timed out",
))
```

- Use `?` operator for propagating errors
- For CLI, print errors to stderr and exit with code 1:

```rust
Err(e) => {
    eprintln!("Error: {}", e);
    std::process::exit(1);
}
```

### Async Code

- Use `tokio` for async runtime
- Wrap blocking operations with appropriate timeouts
- Use `timeout()` from tokio for all network operations:

```rust
timeout(command_timeout, stream.write_all(&encrypted))
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Write timed out"))??;
```

### Documentation

- All public items must have doc comments (`///`)
- Include `# Example` sections with `no_run` for network-dependent code
- Document `# Errors` for functions returning `Result`
- Document `# Arguments` for functions with multiple parameters
- Use `# Safety` for any unsafe code (none currently exists)

### Serde Attributes

- Use `#[serde(skip_serializing_if = "Option::is_none")]` for optional fields
- Use `#[serde(rename = "camelCase")]` to match JSON field names from devices
- Use `#[serde(default)]` for fields that may be missing in responses

### CLI Design (clap)

- Use derive macros for argument parsing
- Provide sensible defaults for all optional arguments
- Use `value_parser` for custom type parsing (e.g., `Duration`)
- Output JSON for machine-readable commands
- Use `--verbose` / `-v` flag for debug logging

### Testing

- Unit tests go in `#[cfg(test)] mod tests` at bottom of file
- Test function names: `test_<what_is_being_tested>`
- Test encryption/decryption roundtrips
- Doctests should be `no_run` if they require network access

## Dependencies Policy

- Minimize dependencies; use `default-features = false` where possible
- Pin major versions in workspace Cargo.toml
- All crates share dependencies via `[workspace.dependencies]`

## CI Requirements

The GitHub Actions workflow enforces:

1. `cargo build` must succeed
2. `cargo test` must pass
3. `cargo clippy -- -D warnings` must pass with zero warnings

All PRs must pass CI before merging.
