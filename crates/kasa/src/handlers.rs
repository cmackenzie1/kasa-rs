use std::time::Duration;

use kasa_core::{
    Credentials, DEFAULT_PORT, broadcast, commands, discovery, send_command,
    transport::{DeviceConfig, connect},
};
use tracing::{debug, error};

use crate::cli::{BroadcastCommand, DeviceCommand, WifiCommand};
use crate::utils::{
    build_command_json_legacy, build_command_json_with_transport, get_credentials,
    handle_energy_command, print_json_response, print_wifi_join_success, read_password,
};

/// Handle the discover command.
pub async fn handle_discover(timeout: Duration) {
    match discovery::discover_all(timeout).await {
        Ok(devices) => {
            debug!(device_count = devices.len(), "discovered devices");
            let json = serde_json::to_value(&devices).unwrap_or_default();
            println!("{}", json);
        }
        Err(e) => {
            error!(error = %e, "discovery failed");
            eprintln!("Error: Discovery failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Handle the device command.
#[allow(clippy::too_many_arguments)]
pub async fn handle_device(
    target: String,
    port: Option<u16>,
    timeout: Duration,
    plug: Option<String>,
    legacy: bool,
    command: DeviceCommand,
    username: Option<String>,
    password_stdin: bool,
) {
    // Get credentials if provided
    let credentials = match get_credentials(username, password_stdin) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Send command using appropriate transport
    if legacy {
        handle_device_legacy(&target, port, timeout, &plug, &command).await;
    } else {
        handle_device_auto(&target, port, timeout, plug, command, credentials).await;
    }
}

/// Handle device command with legacy (XOR) protocol.
async fn handle_device_legacy(
    target: &str,
    port: Option<u16>,
    timeout: Duration,
    plug: &Option<String>,
    command: &DeviceCommand,
) {
    let port = port.unwrap_or(DEFAULT_PORT);
    debug!(port, protocol = "legacy", "using legacy protocol");

    // Build command JSON (plug resolution uses legacy transport too)
    let command_json = build_command_json_legacy(command, plug, target, port, timeout).await;

    match send_command(target, port, timeout, &command_json).await {
        Ok(response) => print_json_response(&response),
        Err(e) => {
            error!(host = %target, port, error = %e, "could not connect to host");
            eprintln!(
                "Error: Could not connect to host {}:{}: {}",
                target, port, e
            );
            std::process::exit(1);
        }
    }
}

/// Handle device command with auto-detection protocol.
async fn handle_device_auto(
    target: &str,
    port: Option<u16>,
    timeout: Duration,
    plug: Option<String>,
    command: DeviceCommand,
    credentials: Option<Credentials>,
) {
    let mut config = DeviceConfig::new(target).with_timeout(timeout);
    if let Some(p) = port {
        config = config.with_port(p);
    }
    if let Some(creds) = credentials {
        config = config.with_credentials(creds);
    }

    debug!(host = %target, "connecting with auto-detection");
    match connect(config).await {
        Ok(transport) => {
            debug!(
                protocol = %transport.encryption_type(),
                port = transport.port(),
                "connected"
            );

            // Handle energy command specially for power strips
            if matches!(command, DeviceCommand::Energy) && plug.is_none() {
                match handle_energy_command(transport.as_ref()).await {
                    Ok(()) => {}
                    Err(e) => {
                        error!(error = %e, "energy command failed");
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // Build command JSON using the established transport
                let command_json =
                    match build_command_json_with_transport(&command, &plug, transport.as_ref())
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
                        error!(error = %e, "command failed");
                        eprintln!("Error: Command failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        Err(e) => {
            error!(host = %target, error = %e, "could not connect");
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

/// Handle the broadcast command.
pub async fn handle_broadcast(
    discovery_timeout: Duration,
    timeout: Duration,
    command: BroadcastCommand,
    username: Option<String>,
    password_stdin: bool,
) {
    // Get credentials if provided (for KLAP/TPAP devices)
    let credentials = match get_credentials(username, password_stdin) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let command_json = command.to_json();
    debug!(command = %command_json, "broadcasting command");

    match broadcast(discovery_timeout, timeout, command_json, credentials).await {
        Ok(results) => {
            let json = serde_json::to_value(&results).unwrap_or_default();
            println!("{}", json);
        }
        Err(e) => {
            error!(error = %e, "broadcast failed");
            eprintln!("Error: Broadcast failed: {}", e);
            std::process::exit(1);
        }
    }
}

// ============================================================================
// WiFi Provisioning Handlers
// ============================================================================

/// Handle WiFi provisioning commands.
#[allow(clippy::too_many_arguments)]
pub async fn handle_wifi(
    host: String,
    port: Option<u16>,
    timeout: Duration,
    legacy: bool,
    command: WifiCommand,
    username: Option<String>,
    password_stdin: bool,
) {
    // Get credentials if provided (for KLAP devices)
    let credentials = match get_credentials(username, password_stdin) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match command {
        WifiCommand::Scan => {
            if legacy {
                handle_wifi_scan_legacy(&host, port, timeout).await;
            } else {
                handle_wifi_scan_auto(&host, port, timeout, credentials).await;
            }
        }
        WifiCommand::Join {
            ssid,
            keytype,
            password_stdin: wifi_password_stdin,
            password,
        } => {
            // Read WiFi password before attempting connection
            let prompt = format!("WiFi password for '{}'", ssid);
            let pass = match read_password(wifi_password_stdin, password, &prompt) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            if legacy {
                handle_wifi_join_legacy(&host, port, timeout, &ssid, &pass, keytype).await;
            } else {
                handle_wifi_join_auto(&host, port, timeout, credentials, &ssid, &pass, keytype)
                    .await;
            }
        }
    }
}

/// Handle WiFi scan with legacy (XOR) protocol.
async fn handle_wifi_scan_legacy(host: &str, port: Option<u16>, timeout: Duration) {
    let port = port.unwrap_or(DEFAULT_PORT);
    debug!(host, port, "WiFi scan using legacy protocol");

    if let Some(json) = try_wifi_scan_with_legacy(host, port, timeout).await {
        println!("{}", json);
        return;
    }

    wifi_scan_failed(host, port);
}

/// Handle WiFi scan with protocol auto-detection.
async fn handle_wifi_scan_auto(
    host: &str,
    port: Option<u16>,
    timeout: Duration,
    credentials: Option<Credentials>,
) {
    let legacy_port = port.unwrap_or(DEFAULT_PORT);
    debug!(host, ?port, "WiFi scan with auto-detection");

    // Try auto-detection first
    let mut config = DeviceConfig::new(host).with_timeout(timeout);
    if let Some(p) = port {
        config = config.with_port(p);
    }
    if let Some(creds) = credentials {
        config = config.with_credentials(creds);
    }

    match connect(config).await {
        Ok(transport) => {
            debug!(
                protocol = %transport.encryption_type(),
                port = transport.port(),
                "connected for WiFi scan"
            );

            if let Some(json) = try_wifi_scan_with_transport(transport.as_ref()).await {
                println!("{}", json);
                return;
            }

            // Transport connected but command failed - try legacy fallback
            debug!("transport command failed, trying legacy fallback");
        }
        Err(e) => {
            debug!(error = %e, "auto-detection failed, trying legacy fallback");
        }
    }

    // Fallback to legacy
    if let Some(json) = try_wifi_scan_with_legacy(host, legacy_port, timeout).await {
        println!("{}", json);
        return;
    }

    wifi_scan_failed(host, legacy_port);
}

/// Handle WiFi join with legacy (XOR) protocol.
async fn handle_wifi_join_legacy(
    host: &str,
    port: Option<u16>,
    timeout: Duration,
    ssid: &str,
    password: &str,
    keytype: u8,
) {
    let port = port.unwrap_or(DEFAULT_PORT);
    debug!(host, port, ssid, "WiFi join using legacy protocol");

    let cmd_netif = commands::wifi_join(ssid, password, keytype);
    let cmd_softap = commands::wifi_join_softap(ssid, password, keytype);

    match try_wifi_join_with_legacy(host, port, timeout, &cmd_netif, &cmd_softap).await {
        WifiJoinResult::Success(json) => {
            println!("{}", json);
            print_wifi_join_success(ssid);
        }
        WifiJoinResult::DeviceError(e) => {
            eprintln!("Error: WiFi join failed: {}", e);
            std::process::exit(1);
        }
        WifiJoinResult::ConnectionFailed => {
            wifi_join_failed(host, port);
        }
    }
}

/// Handle WiFi join with protocol auto-detection.
#[allow(clippy::too_many_arguments)]
async fn handle_wifi_join_auto(
    host: &str,
    port: Option<u16>,
    timeout: Duration,
    credentials: Option<Credentials>,
    ssid: &str,
    password: &str,
    keytype: u8,
) {
    let legacy_port = port.unwrap_or(DEFAULT_PORT);
    debug!(host, ?port, ssid, "WiFi join with auto-detection");

    let cmd_netif = commands::wifi_join(ssid, password, keytype);
    let cmd_softap = commands::wifi_join_softap(ssid, password, keytype);

    // Try auto-detection first
    let mut config = DeviceConfig::new(host).with_timeout(timeout);
    if let Some(p) = port {
        config = config.with_port(p);
    }
    if let Some(creds) = credentials {
        config = config.with_credentials(creds);
    }

    match connect(config).await {
        Ok(transport) => {
            debug!(
                protocol = %transport.encryption_type(),
                port = transport.port(),
                "connected for WiFi join"
            );

            match try_wifi_join_with_transport(transport.as_ref(), &cmd_netif, &cmd_softap).await {
                WifiJoinResult::Success(json) => {
                    println!("{}", json);
                    print_wifi_join_success(ssid);
                    return;
                }
                WifiJoinResult::DeviceError(e) => {
                    eprintln!("Error: WiFi join failed: {}", e);
                    std::process::exit(1);
                }
                WifiJoinResult::ConnectionFailed => {
                    debug!("transport command failed, trying legacy fallback");
                }
            }
        }
        Err(e) => {
            debug!(error = %e, "auto-detection failed, trying legacy fallback");
        }
    }

    // Fallback to legacy
    match try_wifi_join_with_legacy(host, legacy_port, timeout, &cmd_netif, &cmd_softap).await {
        WifiJoinResult::Success(json) => {
            println!("{}", json);
            print_wifi_join_success(ssid);
        }
        WifiJoinResult::DeviceError(e) => {
            eprintln!("Error: WiFi join failed: {}", e);
            std::process::exit(1);
        }
        WifiJoinResult::ConnectionFailed => {
            wifi_join_failed(host, legacy_port);
        }
    }
}

// ----------------------------------------------------------------------------
// WiFi scan helpers
// ----------------------------------------------------------------------------

/// Try WiFi scan using legacy protocol. Returns parsed response on success.
async fn try_wifi_scan_with_legacy(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Option<serde_json::Value> {
    // Try netif endpoint first
    if let Ok(response) = send_command(host, port, timeout, commands::WLANSCAN).await
        && let Some(json) = parse_wifi_scan_response(&response)
    {
        return Some(json);
    }

    // Fallback to softaponboarding endpoint
    if let Ok(response) = send_command(host, port, timeout, commands::WLANSCAN_SOFTAP).await
        && let Some(json) = parse_wifi_scan_response(&response)
    {
        return Some(json);
    }

    None
}

/// Try WiFi scan using an established transport. Returns parsed response on success.
async fn try_wifi_scan_with_transport(
    transport: &dyn kasa_core::Transport,
) -> Option<serde_json::Value> {
    // Try netif endpoint first
    if let Ok(response) = transport.send(commands::WLANSCAN).await
        && let Some(json) = parse_wifi_scan_response(&response)
    {
        return Some(json);
    }

    // Fallback to softaponboarding endpoint
    if let Ok(response) = transport.send(commands::WLANSCAN_SOFTAP).await
        && let Some(json) = parse_wifi_scan_response(&response)
    {
        return Some(json);
    }

    None
}

/// Parse a WiFi scan response. Returns the JSON if the scan was successful.
fn parse_wifi_scan_response(response: &str) -> Option<serde_json::Value> {
    let json: serde_json::Value = serde_json::from_str(response).ok()?;

    // Check netif response format
    if let Some(info) = json.get("netif").and_then(|n| n.get("get_scaninfo")) {
        let has_ap_list = info.get("ap_list").is_some();
        let err_code = info.get("err_code").and_then(|e| e.as_i64());
        if has_ap_list || err_code == Some(0) {
            return Some(json);
        }
    }

    // Check softaponboarding response format
    if let Some(softap) = json.get("smartlife.iot.common.softaponboarding") {
        let err_code = softap.get("err_code").and_then(|e| e.as_i64());
        if err_code.is_none() || err_code == Some(0) {
            return Some(json);
        }
    }

    None
}

/// Print error and exit for failed WiFi scan.
fn wifi_scan_failed(host: &str, port: u16) -> ! {
    error!(host, port, "WiFi scan failed");
    eprintln!("Error: Could not scan WiFi networks on {}:{}", host, port);
    eprintln!();
    eprintln!("Make sure you are connected to the device's WiFi AP");
    eprintln!("(SSID looks like: TP-LINK_Smart Plug_XXXX)");
    std::process::exit(1);
}

// ----------------------------------------------------------------------------
// WiFi join helpers
// ----------------------------------------------------------------------------

/// Result of a WiFi join attempt.
enum WifiJoinResult {
    /// Successfully sent WiFi credentials to the device.
    Success(serde_json::Value),
    /// Device returned an error.
    DeviceError(String),
    /// Could not communicate with the device.
    ConnectionFailed,
}

/// Try WiFi join using legacy protocol.
async fn try_wifi_join_with_legacy(
    host: &str,
    port: u16,
    timeout: Duration,
    cmd_netif: &str,
    cmd_softap: &str,
) -> WifiJoinResult {
    // Try netif endpoint first
    if let Ok(response) = send_command(host, port, timeout, cmd_netif).await {
        match parse_wifi_join_response(&response) {
            WifiJoinResult::ConnectionFailed => {} // Try next endpoint
            result => return result,
        }
    }

    // Fallback to softaponboarding endpoint
    if let Ok(response) = send_command(host, port, timeout, cmd_softap).await {
        return parse_wifi_join_response(&response);
    }

    WifiJoinResult::ConnectionFailed
}

/// Try WiFi join using an established transport.
async fn try_wifi_join_with_transport(
    transport: &dyn kasa_core::Transport,
    cmd_netif: &str,
    cmd_softap: &str,
) -> WifiJoinResult {
    // Try netif endpoint first
    if let Ok(response) = transport.send(cmd_netif).await {
        match parse_wifi_join_response(&response) {
            WifiJoinResult::ConnectionFailed => {} // Try next endpoint
            result => return result,
        }
    }

    // Fallback to softaponboarding endpoint
    if let Ok(response) = transport.send(cmd_softap).await {
        return parse_wifi_join_response(&response);
    }

    WifiJoinResult::ConnectionFailed
}

/// Parse a WiFi join response.
fn parse_wifi_join_response(response: &str) -> WifiJoinResult {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(response) else {
        return WifiJoinResult::ConnectionFailed;
    };

    // Check netif response format
    if let Some(info) = json.get("netif").and_then(|n| n.get("set_stainfo")) {
        let err_code = info.get("err_code").and_then(|e| e.as_i64());
        if err_code.is_none() || err_code == Some(0) {
            return WifiJoinResult::Success(json);
        }
    }

    // Check softaponboarding response format
    if let Some(softap) = json.get("smartlife.iot.common.softaponboarding") {
        let err_code = softap.get("err_code").and_then(|e| e.as_i64());
        if let Some(code) = err_code
            && code != 0
        {
            let err_msg = softap
                .get("err_msg")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return WifiJoinResult::DeviceError(err_msg.to_string());
        }
        return WifiJoinResult::Success(json);
    }

    WifiJoinResult::ConnectionFailed
}

/// Print error and exit for failed WiFi join.
fn wifi_join_failed(host: &str, port: u16) -> ! {
    error!(host, port, "WiFi join failed");
    eprintln!("Error: Could not join WiFi network on {}:{}", host, port);
    eprintln!();
    eprintln!("Make sure you are connected to the device's WiFi AP");
    eprintln!("(SSID looks like: TP-LINK_Smart Plug_XXXX)");
    std::process::exit(1);
}
