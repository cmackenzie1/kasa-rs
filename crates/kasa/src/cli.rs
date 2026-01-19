use std::time::Duration;

use clap::{Parser, Subcommand};
use kasa_core::commands;

pub fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(Duration::from_secs(seconds))
}

/// TP-Link Wi-Fi Smart Plug Protocol client
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// TP-Link cloud account username (email).
    /// Required for devices with newer firmware (KLAP protocol).
    /// Can also be set via KASA_USERNAME environment variable.
    #[arg(short, long, global = true, env = "KASA_USERNAME")]
    pub username: Option<String>,

    /// Read password from stdin.
    /// Useful for scripting: echo "password" | kasa -u user@example.com --password-stdin device 192.168.1.100 info
    #[arg(long, global = true)]
    pub password_stdin: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Discover devices on the local network
    Discover {
        /// Discovery timeout in seconds
        #[arg(long, value_parser = parse_duration, default_value = "3")]
        timeout: Duration,
    },

    /// Show version information for CLI and core library
    Version,

    /// Send a command to a specific device
    Device {
        /// Target hostname or IP address
        target: String,

        /// Target port (default: auto-detect based on protocol)
        #[arg(short, long)]
        port: Option<u16>,

        /// Timeout in seconds to establish connection
        #[arg(long, value_parser = parse_duration, default_value = "10")]
        timeout: Duration,

        /// Child plug ID for power strips (e.g., HS300).
        /// Use 'info' command to see available child IDs in the 'children' array.
        /// Can be the full ID or just the slot number (0-5).
        #[arg(long)]
        plug: Option<String>,

        /// Force legacy protocol (XOR on port 9999).
        /// Use this to skip KLAP protocol detection.
        #[arg(long)]
        legacy: bool,

        #[command(subcommand)]
        command: DeviceCommand,
    },

    /// Broadcast a command to all devices on the local network
    Broadcast {
        /// Discovery timeout in seconds
        #[arg(long, value_parser = parse_duration, default_value = "3")]
        discovery_timeout: Duration,

        /// Command timeout in seconds (per device)
        #[arg(long, value_parser = parse_duration, default_value = "10")]
        timeout: Duration,

        #[command(subcommand)]
        command: BroadcastCommand,
    },

    /// WiFi provisioning commands for devices in AP mode.
    ///
    /// When a Kasa device is new or factory reset, it creates an open WiFi
    /// access point (SSID: TP-LINK_Smart Plug_XXXX). Connect to this AP,
    /// then use these commands to configure the device's WiFi connection.
    Wifi {
        /// Target hostname or IP address (default: 192.168.0.1 for AP mode)
        #[arg(long, default_value = "192.168.0.1")]
        host: String,

        /// Target port (default: auto-detect based on protocol, or 9999 for legacy)
        #[arg(short, long)]
        port: Option<u16>,

        /// Timeout in seconds
        #[arg(long, value_parser = parse_duration, default_value = "10")]
        timeout: Duration,

        /// Force legacy protocol (XOR on port 9999).
        /// Use this to skip KLAP protocol detection.
        #[arg(long)]
        legacy: bool,

        #[command(subcommand)]
        command: WifiCommand,
    },
}

/// Commands available for single device operations
#[derive(Subcommand)]
pub enum DeviceCommand {
    /// Get anti-theft rules
    Antitheft,
    /// Get cloud info
    Cloudinfo,
    /// Unbind device from TP-Link cloud account
    CloudUnbind,
    /// Bind device to TP-Link cloud account
    CloudBind {
        /// TP-Link account email address
        #[arg(long, short)]
        username: String,

        /// Read password from stdin instead of prompting.
        /// Useful for scripting: echo "pass" | kasa device <ip> cloud-bind -u user --password-stdin
        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,

        /// Password (not recommended - use --password-stdin or interactive prompt instead)
        #[arg(long, hide = true)]
        password: Option<String>,
    },
    /// Get countdown rules
    Countdown,
    /// Reset energy meter statistics
    EnergyReset,
    /// Get real-time energy readings
    Energy,
    /// Get system info
    Info,
    /// Turn LED off
    Ledoff,
    /// Turn LED on
    Ledon,
    /// Turn relay off
    Off,
    /// Turn relay on
    On,
    /// Reboot the device
    Reboot,
    /// Reset the device to factory defaults
    Reset,
    /// Reset runtime statistics
    RuntimeReset,
    /// Get schedule rules
    Schedule,
    /// Get device time
    Time,
    /// Scan for wireless networks
    Wlanscan,
    /// Send raw JSON command
    Raw {
        /// JSON command string
        json: String,
    },
}

/// Safe commands available for broadcast operations.
/// Excludes destructive commands like reset, reboot, and raw.
#[derive(Subcommand)]
pub enum BroadcastCommand {
    /// Get anti-theft rules from all devices
    Antitheft,
    /// Get cloud info from all devices
    Cloudinfo,
    /// Unbind all devices from TP-Link cloud account
    CloudUnbind,
    /// Get countdown rules from all devices
    Countdown,
    /// Get real-time energy readings from all devices
    Energy,
    /// Get system info from all devices
    Info,
    /// Turn LED off on all devices
    Ledoff,
    /// Turn LED on on all devices
    Ledon,
    /// Turn relay off on all devices
    Off,
    /// Turn relay on on all devices
    On,
    /// Get schedule rules from all devices
    Schedule,
    /// Get device time from all devices
    Time,
    /// Scan for wireless networks from all devices
    Wlanscan,
}

/// WiFi provisioning commands for devices in AP mode.
#[derive(Subcommand)]
pub enum WifiCommand {
    /// Scan for available WiFi networks visible to the device
    Scan,

    /// Connect device to a WiFi network
    Join {
        /// Network name (SSID)
        ssid: String,

        /// Security type: 0=none, 1=WEP, 2=WPA, 3=WPA2 (default: 3)
        #[arg(long, default_value = "3")]
        keytype: u8,

        /// Read password from stdin instead of prompting.
        /// Useful for scripting: echo "pass" | kasa wifi join SSID --password-stdin
        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,

        /// Password (not recommended - use --password-stdin or interactive prompt instead)
        #[arg(long, hide = true)]
        password: Option<String>,
    },
}

/// Represents the result of converting a command to JSON.
/// Some commands require special handling (like password prompts).
pub enum CommandJson {
    /// A static command string
    Static(&'static str),
    /// A dynamically generated command string
    Dynamic(String),
    /// Command requires special handling
    Special(SpecialCommand),
}

pub enum SpecialCommand {
    CloudBind {
        username: String,
        password_stdin: bool,
        password: Option<String>,
    },
}

impl DeviceCommand {
    pub fn to_command_json(&self) -> CommandJson {
        match self {
            DeviceCommand::Antitheft => CommandJson::Static(commands::ANTITHEFT),
            DeviceCommand::Cloudinfo => CommandJson::Static(commands::CLOUDINFO),
            DeviceCommand::CloudUnbind => CommandJson::Static(commands::CLOUD_UNBIND),
            DeviceCommand::CloudBind {
                username,
                password_stdin,
                password,
            } => CommandJson::Special(SpecialCommand::CloudBind {
                username: username.clone(),
                password_stdin: *password_stdin,
                password: password.clone(),
            }),
            DeviceCommand::Countdown => CommandJson::Static(commands::COUNTDOWN),
            DeviceCommand::EnergyReset => CommandJson::Static(commands::ENERGY_RESET),
            DeviceCommand::Energy => CommandJson::Static(commands::ENERGY),
            DeviceCommand::Info => CommandJson::Static(commands::INFO),
            DeviceCommand::Ledoff => CommandJson::Static(commands::LED_OFF),
            DeviceCommand::Ledon => CommandJson::Static(commands::LED_ON),
            DeviceCommand::Off => CommandJson::Static(commands::RELAY_OFF),
            DeviceCommand::On => CommandJson::Static(commands::RELAY_ON),
            DeviceCommand::Reboot => CommandJson::Static(commands::REBOOT),
            DeviceCommand::Reset => CommandJson::Static(commands::RESET),
            DeviceCommand::RuntimeReset => CommandJson::Static(commands::RUNTIME_RESET),
            DeviceCommand::Schedule => CommandJson::Static(commands::SCHEDULE),
            DeviceCommand::Time => CommandJson::Static(commands::TIME),
            DeviceCommand::Wlanscan => CommandJson::Static(commands::WLANSCAN),
            DeviceCommand::Raw { json } => CommandJson::Dynamic(json.clone()),
        }
    }
}

impl BroadcastCommand {
    pub fn to_json(&self) -> &str {
        match self {
            BroadcastCommand::Antitheft => commands::ANTITHEFT,
            BroadcastCommand::Cloudinfo => commands::CLOUDINFO,
            BroadcastCommand::CloudUnbind => commands::CLOUD_UNBIND,
            BroadcastCommand::Countdown => commands::COUNTDOWN,
            BroadcastCommand::Energy => commands::ENERGY,
            BroadcastCommand::Info => commands::INFO,
            BroadcastCommand::Ledoff => commands::LED_OFF,
            BroadcastCommand::Ledon => commands::LED_ON,
            BroadcastCommand::Off => commands::RELAY_OFF,
            BroadcastCommand::On => commands::RELAY_ON,
            BroadcastCommand::Schedule => commands::SCHEDULE,
            BroadcastCommand::Time => commands::TIME,
            BroadcastCommand::Wlanscan => commands::WLANSCAN,
        }
    }
}
