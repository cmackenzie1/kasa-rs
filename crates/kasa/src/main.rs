use std::time::Duration;

use clap::{Parser, Subcommand};
use kasa_core::{DEFAULT_PORT, broadcast, commands, discover, send_command};
use tracing::{debug, error};

// Source - https://stackoverflow.com/a/77615625
// Posted by kmdreko, modified by community. See post 'Timeline' for change history
// Retrieved 2026-01-10, License - CC BY-SA 4.0
fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(Duration::from_secs(seconds))
}

/// TP-Link Wi-Fi Smart Plug Protocol client
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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

        /// Target port
        #[arg(short, long, default_value_t = DEFAULT_PORT)]
        port: u16,

        /// Timeout in seconds to establish connection
        #[arg(long, value_parser = parse_duration, default_value = "10")]
        timeout: Duration,

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
}

/// Commands available for single device operations
#[derive(Subcommand)]
enum DeviceCommand {
    /// Get anti-theft rules
    Antitheft,
    /// Get cloud info
    Cloudinfo,
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
enum BroadcastCommand {
    /// Get anti-theft rules from all devices
    Antitheft,
    /// Get cloud info from all devices
    Cloudinfo,
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

impl DeviceCommand {
    fn to_json(&self) -> &str {
        match self {
            DeviceCommand::Antitheft => commands::ANTITHEFT,
            DeviceCommand::Cloudinfo => commands::CLOUDINFO,
            DeviceCommand::Countdown => commands::COUNTDOWN,
            DeviceCommand::EnergyReset => commands::ENERGY_RESET,
            DeviceCommand::Energy => commands::ENERGY,
            DeviceCommand::Info => commands::INFO,
            DeviceCommand::Ledoff => commands::LED_OFF,
            DeviceCommand::Ledon => commands::LED_ON,
            DeviceCommand::Off => commands::RELAY_OFF,
            DeviceCommand::On => commands::RELAY_ON,
            DeviceCommand::Reboot => commands::REBOOT,
            DeviceCommand::Reset => commands::RESET,
            DeviceCommand::RuntimeReset => commands::RUNTIME_RESET,
            DeviceCommand::Schedule => commands::SCHEDULE,
            DeviceCommand::Time => commands::TIME,
            DeviceCommand::Wlanscan => commands::WLANSCAN,
            DeviceCommand::Raw { json } => json.as_str(),
        }
    }
}

impl BroadcastCommand {
    fn to_json(&self) -> &str {
        match self {
            BroadcastCommand::Antitheft => commands::ANTITHEFT,
            BroadcastCommand::Cloudinfo => commands::CLOUDINFO,
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    match cli.command {
        Command::Version => {
            println!("kasa {}", env!("CARGO_PKG_VERSION"));
            println!("kasa-core {}", kasa_core::VERSION);
        }

        Command::Discover { timeout } => match discover(timeout).await {
            Ok(devices) => {
                let json = serde_json::to_value(&devices).unwrap_or_default();
                println!("{}", json);
            }
            Err(e) => {
                error!("Discovery failed: {}", e);
                eprintln!("Error: Discovery failed: {}", e);
                std::process::exit(1);
            }
        },

        Command::Device {
            target,
            port,
            timeout,
            command,
        } => {
            let command_json = command.to_json();
            debug!("Command: {}", command_json);

            match send_command(&target, port, timeout, command_json).await {
                Ok(response) => {
                    // Validate it's proper JSON and output
                    match serde_json::from_str::<serde_json::Value>(&response) {
                        Ok(json) => println!("{}", json),
                        Err(_) => println!("{}", response),
                    }
                }
                Err(e) => {
                    error!("Could not connect to host {}:{}: {}", target, port, e);
                    eprintln!(
                        "Error: Could not connect to host {}:{}: {}",
                        target, port, e
                    );
                    std::process::exit(1);
                }
            }
        }

        Command::Broadcast {
            discovery_timeout,
            timeout,
            command,
        } => {
            let command_json = command.to_json();
            debug!("Broadcasting command: {}", command_json);

            match broadcast(discovery_timeout, timeout, command_json).await {
                Ok(results) => {
                    let json = serde_json::to_value(&results).unwrap_or_default();
                    println!("{}", json);
                }
                Err(e) => {
                    error!("Broadcast failed: {}", e);
                    eprintln!("Error: Broadcast failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
