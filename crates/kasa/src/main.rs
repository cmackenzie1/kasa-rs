use std::{io::IsTerminal, time::Duration};

use clap::{Parser, Subcommand};
use kasa_core::{
    Credentials, DEFAULT_PORT, broadcast, commands, discovery, send_command,
    transport::{DeviceConfig, Transport, TransportExt, connect},
};
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

    /// TP-Link cloud account username (email).
    /// Required for devices with newer firmware (KLAP protocol).
    /// Can also be set via KASA_USERNAME environment variable.
    #[arg(short, long, global = true, env = "KASA_USERNAME")]
    username: Option<String>,

    /// Read password from stdin.
    /// Useful for scripting: echo "password" | kasa -u user@example.com --password-stdin device 192.168.1.100 info
    #[arg(long, global = true)]
    password_stdin: bool,

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

        /// Target port
        #[arg(short, long, default_value_t = DEFAULT_PORT)]
        port: u16,

        /// Timeout in seconds
        #[arg(long, value_parser = parse_duration, default_value = "10")]
        timeout: Duration,

        #[command(subcommand)]
        command: WifiCommand,
    },
}

/// Commands available for single device operations
#[derive(Subcommand)]
enum DeviceCommand {
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
enum BroadcastCommand {
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
enum WifiCommand {
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
enum CommandJson {
    /// A static command string
    Static(&'static str),
    /// A dynamically generated command string
    Dynamic(String),
    /// Command requires special handling
    Special(SpecialCommand),
}

enum SpecialCommand {
    CloudBind {
        username: String,
        password_stdin: bool,
        password: Option<String>,
    },
}

impl DeviceCommand {
    fn to_command_json(&self) -> CommandJson {
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
    fn to_json(&self) -> &str {
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

/// Read password securely based on the provided options.
///
/// # Arguments
///
/// * `password_stdin` - Whether to read from stdin
/// * `password` - Pre-provided password (hidden CLI option)
/// * `prompt` - The prompt to display when reading interactively
///
/// # Priority
///
/// 1. If `password` was provided (hidden option), use it
/// 2. If `password_stdin` is true, read from stdin
/// 3. Otherwise, prompt interactively (if terminal is available)
fn read_password(
    password_stdin: bool,
    password: Option<String>,
    prompt: &str,
) -> Result<String, String> {
    // Option 1: Password provided directly (hidden flag, not recommended)
    if let Some(pass) = password {
        return Ok(pass);
    }

    // Option 2: Read from stdin
    if password_stdin {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read password from stdin: {}", e))?;
        return Ok(input.trim().to_string());
    }

    // Option 3: Interactive prompt
    if std::io::stdin().is_terminal() {
        eprint!("{}: ", prompt);
        rpassword::read_password().map_err(|e| format!("Failed to read password: {}", e))
    } else {
        Err("No password provided. Use --password-stdin when piping input.".to_string())
    }
}

/// Get credentials from CLI options and environment.
///
/// Password is read from KASA_PASSWORD env var, stdin (if --password-stdin),
/// or interactively prompted.
fn get_credentials(
    username: Option<String>,
    password_stdin: bool,
) -> Result<Option<Credentials>, String> {
    let Some(user) = username else {
        return Ok(None);
    };

    // Check KASA_PASSWORD env var first
    if let Ok(pass) = std::env::var("KASA_PASSWORD") {
        return Ok(Some(Credentials::new(user, pass)));
    }

    // Read password via stdin or prompt
    let prompt = format!("Password for {}", user);
    let pass = read_password(password_stdin, None, &prompt)?;
    Ok(Some(Credentials::new(user, pass)))
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

        Command::Discover { timeout } => match discovery::discover_all(timeout).await {
            Ok(devices) => {
                debug!("Discovered {} devices", devices.len());
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
            plug,
            legacy,
            command,
        } => {
            // Get credentials if provided
            let credentials = match get_credentials(cli.username.clone(), cli.password_stdin) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            // Send command using appropriate transport
            if legacy {
                // Force legacy protocol - use send_command directly
                let port = port.unwrap_or(DEFAULT_PORT);
                debug!("Using legacy protocol on port {}", port);

                // Build command JSON (plug resolution uses legacy transport too)
                let command_json =
                    build_command_json_legacy(&command, &plug, &target, port, timeout).await;

                match send_command(&target, port, timeout, &command_json).await {
                    Ok(response) => print_json_response(&response),
                    Err(e) => {
                        error!("Could not connect to host {}:{}: {}", target, port, e);
                        eprintln!(
                            "Error: Could not connect to host {}:{}: {}",
                            target, port, e
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                // Auto-detect protocol - create transport first
                let mut config = DeviceConfig::new(&target).with_timeout(timeout);
                if let Some(p) = port {
                    config = config.with_port(p);
                }
                if let Some(creds) = credentials {
                    config = config.with_credentials(creds);
                }

                debug!("Connecting to {} with auto-detection", target);
                match connect(config).await {
                    Ok(mut transport) => {
                        debug!(
                            "Connected using {} protocol on port {}",
                            transport.encryption_type(),
                            transport.port()
                        );

                        // Build command JSON using the established transport
                        let command_json = match build_command_json_with_transport(
                            &command,
                            &plug,
                            &mut transport,
                        )
                        .await
                        {
                            Ok(json) => json,
                            Err(e) => {
                                eprintln!("Error: {}", e);
                                std::process::exit(1);
                            }
                        };

                        match transport.send(&command_json).await {
                            Ok(response) => print_json_response(&response),
                            Err(e) => {
                                error!("Command failed: {}", e);
                                eprintln!("Error: Command failed: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Could not connect to {}: {}", target, e);
                        eprintln!("Error: Could not connect to {}: {}", target, e);
                        eprintln!();
                        eprintln!("If your device has newer firmware (KLAP protocol), try:");
                        eprintln!("  kasa -u your-email@example.com device {} info", target);
                        eprintln!();
                        eprintln!("Or set credentials via environment variables:");
                        eprintln!("  export KASA_USERNAME=your-email@example.com");
                        eprintln!("  export KASA_PASSWORD=your-password");
                        std::process::exit(1);
                    }
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

        Command::Wifi {
            host,
            port,
            timeout,
            command,
        } => match command {
            WifiCommand::Scan => {
                debug!("Scanning for WiFi networks via {}", host);

                // Try netif first
                match send_command(&host, port, timeout, commands::WLANSCAN).await {
                    Ok(response) => {
                        debug!("netif response: {}", response);
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                            let scaninfo = json.get("netif").and_then(|n| n.get("get_scaninfo"));

                            if let Some(info) = scaninfo {
                                // Success if ap_list exists or err_code is 0
                                let has_ap_list = info.get("ap_list").is_some();
                                let err_code = info.get("err_code").and_then(|e| e.as_i64());

                                if has_ap_list || err_code == Some(0) {
                                    println!("{}", json);
                                    return;
                                }
                                debug!("scaninfo present but no ap_list, err_code: {:?}", err_code);
                            } else {
                                debug!(
                                    "no scaninfo in response, keys: {:?}",
                                    json.as_object().map(|o| o.keys().collect::<Vec<_>>())
                                );
                            }
                        } else {
                            debug!("failed to parse netif response as JSON");
                        }
                        // netif didn't work, try softap fallback
                        debug!("netif scan failed, trying softaponboarding fallback");
                    }
                    Err(e) => {
                        debug!("netif scan error: {}, trying softaponboarding fallback", e);
                    }
                }

                // Fallback to softaponboarding
                match send_command(&host, port, timeout, commands::WLANSCAN_SOFTAP).await {
                    Ok(response) => {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                            // Check if softap returned an error
                            let err_code = json
                                .get("smartlife.iot.common.softaponboarding")
                                .and_then(|s| s.get("err_code"))
                                .and_then(|e| e.as_i64());

                            if let Some(code) = err_code
                                && code != 0
                            {
                                eprintln!(
                                    "Error: WiFi scan not supported by this device (err_code: {})",
                                    code
                                );
                                std::process::exit(1);
                            }
                            println!("{}", json);
                        } else {
                            println!("{}", response);
                        }
                    }
                    Err(e) => {
                        error!("Could not connect to host {}:{}: {}", host, port, e);
                        eprintln!("Error: Could not connect to host {}:{}: {}", host, port, e);
                        eprintln!();
                        eprintln!("Make sure you are connected to the device's WiFi AP");
                        eprintln!("(SSID looks like: TP-LINK_Smart Plug_XXXX)");
                        std::process::exit(1);
                    }
                }
            }

            WifiCommand::Join {
                ssid,
                keytype,
                password_stdin,
                password,
            } => {
                let prompt = format!("WiFi password for '{}'", ssid);
                let pass = match read_password(password_stdin, password, &prompt) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };

                debug!("Joining WiFi network '{}' with key_type {}", ssid, keytype);

                // Try netif first
                let cmd = commands::wifi_join(&ssid, &pass, keytype);
                match send_command(&host, port, timeout, &cmd).await {
                    Ok(response) => {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                            let stainfo = json.get("netif").and_then(|n| n.get("set_stainfo"));

                            if let Some(info) = stainfo {
                                let err_code = info.get("err_code").and_then(|e| e.as_i64());

                                // err_code 0 means success, missing err_code also treated as success
                                if err_code.is_none() || err_code == Some(0) {
                                    println!("{}", json);
                                    print_wifi_join_success(&ssid);
                                    return;
                                }
                            }
                        }
                        // netif didn't work, try softap fallback
                        debug!("netif join failed, trying softaponboarding fallback");
                    }
                    Err(e) => {
                        debug!("netif join error: {}, trying softaponboarding fallback", e);
                    }
                }

                // Fallback to softaponboarding
                let cmd_softap = commands::wifi_join_softap(&ssid, &pass, keytype);
                match send_command(&host, port, timeout, &cmd_softap).await {
                    Ok(response) => {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                            // Check if softap returned an error
                            let err_code = json
                                .get("smartlife.iot.common.softaponboarding")
                                .and_then(|s| s.get("err_code"))
                                .and_then(|e| e.as_i64());

                            if let Some(code) = err_code
                                && code != 0
                            {
                                let err_msg = json
                                    .get("smartlife.iot.common.softaponboarding")
                                    .and_then(|s| s.get("err_msg"))
                                    .and_then(|m| m.as_str())
                                    .unwrap_or("unknown error");
                                eprintln!("Error: WiFi join failed: {}", err_msg);
                                std::process::exit(1);
                            }
                            println!("{}", json);
                        } else {
                            println!("{}", response);
                        }
                        print_wifi_join_success(&ssid);
                    }
                    Err(e) => {
                        error!("Could not connect to host {}:{}: {}", host, port, e);
                        eprintln!("Error: Could not connect to host {}:{}: {}", host, port, e);
                        eprintln!();
                        eprintln!("Make sure you are connected to the device's WiFi AP");
                        eprintln!("(SSID looks like: TP-LINK_Smart Plug_XXXX)");
                        std::process::exit(1);
                    }
                }
            }
        },
    }
}

/// Build the command JSON using legacy transport, resolving plug IDs if needed.
async fn build_command_json_legacy(
    command: &DeviceCommand,
    plug: &Option<String>,
    target: &str,
    port: u16,
    timeout: Duration,
) -> String {
    // Resolve plug ID if specified
    let child_id = match plug {
        Some(plug_arg) => resolve_child_id_legacy(plug_arg, target, port, timeout).await,
        None => String::new(),
    };

    build_final_command_json(command, &child_id)
}

/// Build the command JSON using an existing transport, resolving plug IDs if needed.
async fn build_command_json_with_transport(
    command: &DeviceCommand,
    plug: &Option<String>,
    transport: &mut Box<dyn Transport>,
) -> Result<String, String> {
    // Resolve plug ID if specified
    let child_id = match plug {
        Some(plug_arg) => resolve_child_id_with_transport(plug_arg, transport).await?,
        None => String::new(),
    };

    Ok(build_final_command_json(command, &child_id))
}

/// Build the final command JSON with optional child context.
fn build_final_command_json(command: &DeviceCommand, child_id: &str) -> String {
    if !child_id.is_empty() {
        // Wrap command with child context
        match command {
            DeviceCommand::Energy => commands::energy_for_child(child_id),
            DeviceCommand::On => commands::relay_on_for_child(child_id),
            DeviceCommand::Off => commands::relay_off_for_child(child_id),
            _ => {
                // For other commands, check if they can be wrapped
                match command.to_command_json() {
                    CommandJson::Static(s) => {
                        let inner = s.trim_start_matches('{').trim_end_matches('}');
                        commands::with_child_context(child_id, inner)
                    }
                    CommandJson::Dynamic(s) => {
                        let inner = s.trim_start_matches('{').trim_end_matches('}');
                        commands::with_child_context(child_id, inner)
                    }
                    CommandJson::Special(SpecialCommand::CloudBind { .. }) => {
                        eprintln!("Error: cloud-bind command cannot be used with --plug");
                        std::process::exit(1);
                    }
                }
            }
        }
    } else {
        match command.to_command_json() {
            CommandJson::Static(s) => s.to_string(),
            CommandJson::Dynamic(s) => s,
            CommandJson::Special(SpecialCommand::CloudBind {
                username,
                password_stdin,
                password,
            }) => {
                let prompt = format!("Password for {}", username);
                let pass = match read_password(password_stdin, password, &prompt) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
                commands::cloud_bind(&username, &pass)
            }
        }
    }
}

/// Resolve a plug slot number or ID using legacy transport.
async fn resolve_child_id_legacy(
    plug_arg: &str,
    target: &str,
    port: u16,
    timeout: Duration,
) -> String {
    // Check if it's a slot number (0-9) or a full ID
    if plug_arg.len() <= 2 && plug_arg.chars().all(|c| c.is_ascii_digit()) {
        let slot: usize = plug_arg.parse().unwrap_or_else(|_| {
            eprintln!("Error: Invalid plug number: {}", plug_arg);
            std::process::exit(1);
        });

        debug!(
            "Resolving plug slot {} to child ID via legacy transport",
            slot
        );
        match send_command(target, port, timeout, commands::INFO).await {
            Ok(response) => extract_child_id_from_response(&response, slot),
            Err(e) => {
                eprintln!("Error: Failed to get sysinfo: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // It's a full child ID
        plug_arg.to_string()
    }
}

/// Resolve a plug slot number or ID using an existing transport.
async fn resolve_child_id_with_transport(
    plug_arg: &str,
    transport: &mut Box<dyn Transport>,
) -> Result<String, String> {
    // Check if it's a slot number (0-9) or a full ID
    if plug_arg.len() <= 2 && plug_arg.chars().all(|c| c.is_ascii_digit()) {
        let slot: usize = plug_arg
            .parse()
            .map_err(|_| format!("Invalid plug number: {}", plug_arg))?;

        debug!("Resolving plug slot {} to child ID via transport", slot);
        let sysinfo = transport
            .get_sysinfo()
            .await
            .map_err(|e| format!("Failed to get sysinfo: {}", e))?;

        if sysinfo.children.is_empty() {
            return Err(
                "Device does not have child plugs. The --plug option is only for power strips."
                    .to_string(),
            );
        }

        if slot >= sysinfo.children.len() {
            return Err(format!(
                "Plug {} not found. Device has {} plugs (0-{})",
                slot,
                sysinfo.children.len(),
                sysinfo.children.len() - 1
            ));
        }

        Ok(sysinfo.children[slot].id.clone())
    } else {
        // It's a full child ID
        Ok(plug_arg.to_string())
    }
}

/// Extract child ID from sysinfo response.
fn extract_child_id_from_response(response: &str, slot: usize) -> String {
    match serde_json::from_str::<serde_json::Value>(response) {
        Ok(json) => {
            let children = json
                .get("system")
                .and_then(|s| s.get("get_sysinfo"))
                .and_then(|s| s.get("children"))
                .and_then(|c| c.as_array());

            match children {
                Some(children) => {
                    if slot >= children.len() {
                        eprintln!(
                            "Error: Plug {} not found. Device has {} plugs (0-{})",
                            slot,
                            children.len(),
                            children.len() - 1
                        );
                        std::process::exit(1);
                    }
                    children[slot]
                        .get("id")
                        .and_then(|id| id.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| {
                            eprintln!("Error: Plug {} has no ID", slot);
                            std::process::exit(1);
                        })
                }
                None => {
                    eprintln!(
                        "Error: Device does not have child plugs. \
                            The --plug option is only for power strips."
                    );
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: Failed to parse sysinfo: {}", e);
            std::process::exit(1);
        }
    }
}

/// Print a JSON response, validating it first.
fn print_json_response(response: &str) {
    match serde_json::from_str::<serde_json::Value>(response) {
        Ok(json) => println!("{}", json),
        Err(_) => println!("{}", response),
    }
}

/// Print guidance message after successful WiFi join command.
fn print_wifi_join_success(ssid: &str) {
    eprintln!();
    eprintln!("WiFi credentials sent successfully!");
    eprintln!();
    eprintln!("The device will now:");
    eprintln!("  1. Disconnect from its access point (you will lose connection)");
    eprintln!("  2. Attempt to connect to '{}'", ssid);
    eprintln!();
    eprintln!("To verify the device joined your network, reconnect to your");
    eprintln!("normal WiFi and run:");
    eprintln!("  kasa discover");
}
