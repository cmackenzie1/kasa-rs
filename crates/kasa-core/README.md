# kasa-core

Core library for communicating with [TP-Link Kasa](https://www.kasasmart.com/us) smart home devices.

This crate implements the TP-Link Smart Home Protocol, which uses an XOR autokey cipher for encryption over TCP/UDP port 9999.

## Features

- Async API using Tokio
- Protocol encryption/decryption (XOR autokey cipher)
- TCP communication with Kasa devices
- UDP broadcast discovery to find devices on the local network
- Broadcast commands to all devices in parallel
- Predefined command constants for common operations
- Support for both IP addresses and hostnames

## Installation

```toml
[dependencies]
kasa-core = "0.1.0"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Usage

```rust
use kasa_core::{commands, send_command, discover, DEFAULT_PORT, DEFAULT_TIMEOUT, DEFAULT_DISCOVERY_TIMEOUT};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Discover devices on the local network
    let devices = discover(DEFAULT_DISCOVERY_TIMEOUT).await?;
    for device in &devices {
        println!("Found: {} ({}) at {}", device.alias, device.model, device.ip);
    }

    // Send a command to a specific device
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

## Available Commands

The `commands` module provides constants for common operations:

| Command | Description |
|---------|-------------|
| `INFO` | Get system information |
| `RELAY_ON` | Turn relay on |
| `RELAY_OFF` | Turn relay off |
| `ENERGY` | Get real-time energy readings |
| `LED_ON` | Turn LED indicator on |
| `LED_OFF` | Turn LED indicator off |
| `TIME` | Get device time |
| `SCHEDULE` | Get schedule rules |
| `COUNTDOWN` | Get countdown rules |
| `ANTITHEFT` | Get anti-theft rules |
| `CLOUDINFO` | Get cloud connection info |
| `WLANSCAN` | Scan for wireless networks |
| `REBOOT` | Reboot the device |
| `RESET` | Factory reset the device |
| `ENERGY_RESET` | Reset energy meter statistics |
| `RUNTIME_RESET` | Reset runtime statistics |

## Supported Devices

The following devices have been tested, but others using the same protocol should work:

- HS100 - Smart Wi-Fi Plug
- HS103 - Smart Wi-Fi Plug Lite
- HS110 - Smart Wi-Fi Plug with Energy Monitoring
- KP115 - Smart Wi-Fi Plug Slim with Energy Monitoring

## License

MIT
