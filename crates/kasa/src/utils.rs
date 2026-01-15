use std::{io::IsTerminal, time::Duration};

use kasa_core::{
    Credentials, commands, send_command,
    transport::{Transport, TransportExt},
};
use tracing::debug;

use crate::cli::{CommandJson, DeviceCommand, SpecialCommand};

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
pub fn read_password(
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
pub fn get_credentials(
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

/// Build the command JSON using legacy transport, resolving plug IDs if needed.
pub async fn build_command_json_legacy(
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
pub async fn build_command_json_with_transport(
    command: &DeviceCommand,
    plug: &Option<String>,
    transport: &dyn Transport,
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

        debug!(slot, "resolving plug slot to child ID via legacy transport");
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
pub async fn resolve_child_id_with_transport(
    plug_arg: &str,
    transport: &dyn Transport,
) -> Result<String, String> {
    // Check if it's a slot number (0-9) or a full ID
    if plug_arg.len() <= 2 && plug_arg.chars().all(|c| c.is_ascii_digit()) {
        let slot: usize = plug_arg
            .parse()
            .map_err(|_| format!("Invalid plug number: {}", plug_arg))?;

        debug!(slot, "resolving plug slot to child ID via transport");
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
pub fn print_json_response(response: &str) {
    match serde_json::from_str::<serde_json::Value>(response) {
        Ok(json) => println!("{}", json),
        Err(_) => println!("{}", response),
    }
}

/// Print guidance message after successful WiFi join command.
pub fn print_wifi_join_success(ssid: &str) {
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

/// Handle the energy command using the unified get_all_energy() method.
///
/// This automatically handles both single devices and power strips,
/// returning energy readings for all plugs.
pub async fn handle_energy_command(transport: &dyn Transport) -> Result<(), String> {
    let energy = transport
        .get_all_energy()
        .await
        .map_err(|e| format!("Failed to get energy: {}", e))?;

    // Output as JSON
    let output = serde_json::to_string_pretty(&energy)
        .map_err(|e| format!("Failed to serialize energy data: {}", e))?;

    println!("{}", output);
    Ok(())
}
