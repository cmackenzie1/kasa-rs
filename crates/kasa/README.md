# kasa

A CLI for communicating with [TP-Link Kasa](https://www.kasasmart.com/us) smart home devices.

## Installation

### Using cargo-binstall (recommended)

[cargo-binstall](https://github.com/cargo-bins/cargo-binstall) provides a convenient way to install pre-built binaries:

```bash
cargo binstall kasa
```

### Using cargo install

```bash
cargo install kasa
```

### From source

```bash
git clone https://github.com/cmackenzie1/kasa-rs.git
cd kasa-rs
cargo install --path crates/kasa
```

## Usage

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

## Commands

```
kasa discover                # Discover devices on the local network
kasa device <TARGET> ...     # Send commands to a specific device
kasa broadcast ...           # Send commands to all devices on the network
kasa version                 # Show CLI and library versions
```

### Device Commands

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

### Broadcast Commands

The `broadcast` command sends a command to all discovered devices in parallel. For safety, destructive commands (`reset`, `reboot`, `energy-reset`, `runtime-reset`, `raw`) are not available for broadcast.

### Options

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

- HS100 - Smart Wi-Fi Plug
- HS103 - Smart Wi-Fi Plug Lite
- HS110 - Smart Wi-Fi Plug with Energy Monitoring
- KP115 - Smart Wi-Fi Plug Slim with Energy Monitoring

## License

MIT
