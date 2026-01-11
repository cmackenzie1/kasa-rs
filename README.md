# kasa-rs

[![CI](https://github.com/cmackenzie1/kasa-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/cmackenzie1/kasa-rs/actions/workflows/rust.yml)

A CLI and library for communicating with [TP-Link Kasa](https://www.kasasmart.com/us) smart home devices.

## Crates

| Crate | Version | Docs | Description |
|-------|---------|------|-------------|
| [kasa](https://crates.io/crates/kasa) | [![Crates.io](https://img.shields.io/crates/v/kasa)](https://crates.io/crates/kasa) | - | CLI for communicating with TP-Link Kasa smart devices |
| [kasa-core](https://crates.io/crates/kasa-core) | [![Crates.io](https://img.shields.io/crates/v/kasa-core)](https://crates.io/crates/kasa-core) | [![docs.rs](https://img.shields.io/docsrs/kasa-core)](https://docs.rs/kasa-core) | Core library for communicating with TP-Link Kasa smart devices |
| [kasa-prometheus](https://crates.io/crates/kasa-prometheus) | [![Crates.io](https://img.shields.io/crates/v/kasa-prometheus)](https://crates.io/crates/kasa-prometheus) | - | Prometheus metrics exporter for TP-Link Kasa smart home devices |

## Quickstart

### Installation

#### Using cargo-binstall (recommended)

[cargo-binstall](https://github.com/cargo-bins/cargo-binstall) provides a convenient way to install pre-built binaries:

```bash
cargo binstall kasa
```

#### Using cargo install

```bash
cargo install kasa
```

#### From source

```bash
git clone https://github.com/cmackenzie1/kasa-rs.git
cd kasa-rs
cargo install --path crates/kasa
```

### Basic Usage

```bash
# Discover devices on your local network
kasa discover | jq

# Get device info
kasa device 192.168.1.100 info | jq

# Turn on a smart plug
kasa device 192.168.1.100 on

# Turn off a smart plug  
kasa device 192.168.1.100 off

# Get energy meter readings (for devices with energy monitoring)
kasa device 192.168.1.100 energy | jq

# Turn off all devices on the network
kasa broadcast off | jq
```

## Project Structure

This project is organized as a Cargo workspace with two crates:

```
kasa-rs/
├── Cargo.toml              # Workspace configuration
├── README.md
└── crates/
    ├── kasa/               # CLI binary
    │   ├── Cargo.toml
    │   └── src/
    │       └── main.rs     # Command-line interface using clap
    └── kasa-core/          # Core library (async)
        ├── Cargo.toml
        └── src/
            └── lib.rs      # Protocol implementation and device communication
```

### `kasa-core`

The core library crate that implements the TP-Link Smart Home Protocol. Use this crate if you want to integrate Kasa device communication into your own Rust application.

**Features:**
- Async API using Tokio
- Protocol encryption/decryption (XOR autokey cipher)
- TCP communication with Kasa devices
- UDP broadcast discovery to find devices on the local network
- Broadcast commands to all devices in parallel
- Predefined command constants for common operations
- Support for both IP addresses and hostnames

**Add to your project:**

```toml
[dependencies]
kasa-core = "0.1.0"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

**Example usage:**

```rust
use kasa_core::{commands, send_command, DEFAULT_PORT, DEFAULT_TIMEOUT};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Get device info
    let response = send_command(
        "192.168.1.100",
        DEFAULT_PORT,
        DEFAULT_TIMEOUT,
        commands::INFO,
    ).await?;
    println!("{}", response);

    // Turn on the relay
    send_command(
        "192.168.1.100",
        DEFAULT_PORT,
        DEFAULT_TIMEOUT,
        commands::RELAY_ON,
    ).await?;

    Ok(())
}
```

### `kasa`

The command-line interface for interacting with Kasa devices. Outputs JSON by default for easy piping to tools like `jq`.

**Commands:**

```
kasa discover                # Discover devices on the local network
kasa device <TARGET> ...     # Send commands to a specific device
kasa broadcast ...           # Send commands to all devices on the network
kasa version                 # Show CLI and library versions
```

**Device Commands:**

| Command | Description |
|---------|-------------|
| `info` | Get system information |
| `on` | Turn relay on |
| `off` | Turn relay off |
| `energy` | Get real-time energy readings |
| `energy-reset` | Reset energy meter statistics |
| `ledon` | Turn LED indicator on |
| `ledoff` | Turn LED indicator off |
| `time` | Get device time |
| `schedule` | Get schedule rules |
| `countdown` | Get countdown rules |
| `antitheft` | Get anti-theft rules |
| `cloudinfo` | Get cloud connection info |
| `wlanscan` | Scan for wireless networks |
| `reboot` | Reboot the device |
| `reset` | Factory reset the device |
| `runtime-reset` | Reset runtime statistics |
| `raw <JSON>` | Send a raw JSON command |

**Broadcast Commands:**

The `broadcast` command sends a command to all discovered devices in parallel. For safety, destructive commands (`reset`, `reboot`, `energy-reset`, `runtime-reset`, `raw`) are not available for broadcast.

| Command | Description |
|---------|-------------|
| `info` | Get system info from all devices |
| `on` | Turn relay on for all devices |
| `off` | Turn relay off for all devices |
| `energy` | Get energy readings from all devices |
| `ledon` | Turn LED on for all devices |
| `ledoff` | Turn LED off for all devices |
| `time` | Get time from all devices |
| `schedule` | Get schedules from all devices |
| `countdown` | Get countdowns from all devices |
| `antitheft` | Get anti-theft rules from all devices |
| `cloudinfo` | Get cloud info from all devices |
| `wlanscan` | Scan networks from all devices |

**Options:**

```
kasa device <TARGET> [OPTIONS] <COMMAND>

Arguments:
  <TARGET>  Target hostname or IP address

Options:
  -p, --port <PORT>        Target port [default: 9999]
      --timeout <TIMEOUT>  Timeout in seconds [default: 10]

kasa broadcast [OPTIONS] <COMMAND>

Options:
      --discovery-timeout <SECS>  Discovery timeout in seconds [default: 3]
      --timeout <TIMEOUT>         Per-device command timeout in seconds [default: 10]
```

## Supported Devices

The following devices have been tested, but others using the same protocol should work:

- [HS100](https://www.kasasmart.com/us/products/smart-plugs/kasa-smart-plug-hs100) - Smart Wi-Fi Plug
- [HS103](https://www.kasasmart.com/us/products/smart-plugs/kasa-smart-plug-lite-hs103) - Smart Wi-Fi Plug Lite
- [HS110](https://www.kasasmart.com/us/products/smart-plugs/kasa-smart-plug-energy-monitoring-hs110) - Smart Wi-Fi Plug with Energy Monitoring
- [KP115](https://www.kasasmart.com/us/products/smart-plugs/kasa-smart-plug-slim-energy-monitoring-kp115) - Smart Wi-Fi Plug Slim with Energy Monitoring

## Examples

```bash
# Discover all Kasa devices on the local network
kasa discover | jq

# Discover with a longer timeout (5 seconds)
kasa discover --timeout 5 | jq

# List discovered device names and IPs
kasa discover | jq -r '.[] | "\(.alias): \(.ip)"'

# Get device info and format with jq
kasa device 192.168.1.100 info | jq

# Get just the device alias
kasa device 192.168.1.100 info | jq -r '.system.get_sysinfo.alias'

# Get current power consumption in watts
kasa device 192.168.1.100 energy | jq '.emeter.get_realtime.power'

# Use hostname instead of IP address
kasa device my-smart-plug.local info

# Send a custom JSON command
kasa device 192.168.1.100 raw '{"system":{"get_sysinfo":{}}}'

# Enable verbose logging to see protocol details
kasa -v device 192.168.1.100 info

# Turn off all devices on the network
kasa broadcast off | jq

# Get info from all devices
kasa broadcast info | jq

# Check which devices succeeded/failed
kasa broadcast info | jq '.[] | select(.success == false)'

# Get all device aliases
kasa broadcast info | jq -r '.[] | select(.success) | .alias'
```

## Building from Source

[Install Rust](https://www.rust-lang.org/tools/install), then:

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Build documentation
cargo doc --open
```

## Acknowledgements

This project builds upon the work of several others who have reverse-engineered and documented the TP-Link Smart Home Protocol:

- [softScheck/tplink-smartplug](https://github.com/softScheck/tplink-smartplug) - Original Python implementation and protocol reverse engineering by Lubomir Stroetmann
- [TP-Link Smart Home Protocol Reverse Engineering](https://www.softscheck.com/en/blog/tp-link-reverse-engineering/) - Detailed blog post explaining the XOR autokey cipher used by TP-Link devices
- [bobrik/kasa_exporter](https://github.com/bobrik/kasa_exporter) - Prometheus exporter for Kasa devices that inspired this project
- [cshjsc/tplink-shome-protocol](https://github.com/cshjsc/tplink-shome-protocol) - Rust implementation of the TP-Link Smart Home Protocol

## License

MIT
