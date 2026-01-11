//! Core library for communicating with TP-Link Kasa smart home devices.
//!
//! This crate implements the TP-Link Smart Home Protocol, which uses an
//! XOR autokey cipher for encryption. It provides async functions for
//! encrypting/decrypting messages and sending commands to Kasa devices.
//!
//! # Overview
//!
//! TP-Link Kasa devices communicate over TCP port 9999 using a simple
//! JSON-based protocol. Messages are encrypted using an XOR autokey cipher
//! with a starting key of 171. Each message is prefixed with a 4-byte
//! big-endian length header.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use kasa_core::{commands, send_command, DEFAULT_PORT, DEFAULT_TIMEOUT};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     // Get device system information
//!     let response = send_command(
//!         "192.168.1.100",
//!         DEFAULT_PORT,
//!         DEFAULT_TIMEOUT,
//!         commands::INFO,
//!     ).await?;
//!
//!     println!("{}", response);
//!     Ok(())
//! }
//! ```
//!
//! # Protocol Details
//!
//! The TP-Link Smart Home Protocol works as follows:
//!
//! 1. Commands are JSON strings (e.g., `{"system":{"get_sysinfo":{}}}`)
//! 2. The JSON is encrypted using XOR autokey cipher with initial key 171
//! 3. A 4-byte big-endian length prefix is prepended
//! 4. The message is sent over TCP to port 9999
//! 5. The response follows the same format and is decrypted the same way

use std::{net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tracing::debug;

/// The version of the kasa-core library.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default TCP port for TP-Link Kasa smart devices.
///
/// All Kasa devices listen on port 9999 for the Smart Home Protocol.
pub const DEFAULT_PORT: u16 = 9999;

/// Default connection timeout.
///
/// This timeout applies to connection establishment, read, and write operations.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default discovery timeout.
///
/// How long to wait for devices to respond to broadcast discovery.
pub const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Broadcast address for UDP discovery.
const BROADCAST_ADDR: &str = "255.255.255.255:9999";

/// Predefined JSON command strings for common TP-Link Kasa device operations.
///
/// These constants can be passed directly to [`send_command`] to perform
/// common operations without constructing JSON manually.
///
/// # Example
///
/// ```no_run
/// use kasa_core::{commands, send_command, DEFAULT_PORT, DEFAULT_TIMEOUT};
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     // Turn on a smart plug
///     send_command("192.168.1.100", DEFAULT_PORT, DEFAULT_TIMEOUT, commands::RELAY_ON).await?;
///     Ok(())
/// }
/// ```
pub mod commands {
    /// Get anti-theft rules configuration.
    pub const ANTITHEFT: &str = r#"{"anti_theft":{"get_rules":{}}}"#;

    /// Get cloud connection information.
    pub const CLOUDINFO: &str = r#"{"cnCloud":{"get_info":{}}}"#;

    /// Unbind device from TP-Link cloud account.
    ///
    /// This removes the device from cloud control but it continues to work locally.
    pub const CLOUD_UNBIND: &str = r#"{"cnCloud":{"unbind":{}}}"#;

    /// Bind device to TP-Link cloud account.
    ///
    /// Requires username and password - use [`cloud_bind_command`] to generate
    /// the command with credentials.
    ///
    /// [`cloud_bind_command`]: fn.cloud_bind_command.html
    pub const CLOUD_BIND_TEMPLATE: &str =
        r#"{"cnCloud":{"bind":{"username":"{{USERNAME}}","password":"{{PASSWORD}}"}}}"#;

    /// Get countdown timer rules.
    pub const COUNTDOWN: &str = r#"{"count_down":{"get_rules":{}}}"#;

    /// Erase all energy meter statistics.
    ///
    /// **Warning:** This permanently deletes energy usage history.
    pub const ENERGY_RESET: &str = r#"{"emeter":{"erase_emeter_stat":{}}}"#;

    /// Get real-time energy meter readings.
    ///
    /// Returns current voltage, current, power, and total energy consumption.
    /// Only available on devices with energy monitoring (e.g., HS110, KP115).
    pub const ENERGY: &str = r#"{"emeter":{"get_realtime":{}}}"#;

    /// Get system information.
    ///
    /// Returns device model, alias, MAC address, firmware version, relay state, and more.
    pub const INFO: &str = r#"{"system":{"get_sysinfo":{}}}"#;

    /// Turn off the LED indicator light.
    pub const LED_OFF: &str = r#"{"system":{"set_led_off":{"off":1}}}"#;

    /// Turn on the LED indicator light.
    pub const LED_ON: &str = r#"{"system":{"set_led_off":{"off":0}}}"#;

    /// Turn off the relay (power off the connected device).
    pub const RELAY_OFF: &str = r#"{"system":{"set_relay_state":{"state":0}}}"#;

    /// Turn on the relay (power on the connected device).
    pub const RELAY_ON: &str = r#"{"system":{"set_relay_state":{"state":1}}}"#;

    /// Reboot the device with a 1-second delay.
    pub const REBOOT: &str = r#"{"system":{"reboot":{"delay":1}}}"#;

    /// Factory reset the device with a 1-second delay.
    ///
    /// **Warning:** This will erase all settings and require re-setup.
    pub const RESET: &str = r#"{"system":{"reset":{"delay":1}}}"#;

    /// Erase runtime statistics.
    pub const RUNTIME_RESET: &str = r#"{"schedule":{"erase_runtime_stat":{}}}"#;

    /// Get schedule rules.
    pub const SCHEDULE: &str = r#"{"schedule":{"get_rules":{}}}"#;

    /// Get the device's current time.
    pub const TIME: &str = r#"{"time":{"get_time":{}}}"#;

    /// Scan for available wireless networks.
    pub const WLANSCAN: &str = r#"{"netif":{"get_scaninfo":{"refresh":0}}}"#;

    /// Scan for available wireless networks (alternative endpoint for newer devices).
    ///
    /// Some newer devices use the `smartlife.iot.common.softaponboarding` module
    /// instead of `netif`. Try [`WLANSCAN`] first, then fall back to this.
    pub const WLANSCAN_SOFTAP: &str =
        r#"{"smartlife.iot.common.softaponboarding":{"get_scaninfo":{"refresh":0}}}"#;

    /// Generate a cloud bind command with the given credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - TP-Link account email address
    /// * `password` - TP-Link account password
    ///
    /// # Example
    ///
    /// ```
    /// use kasa_core::commands;
    ///
    /// let cmd = commands::cloud_bind("user@example.com", "secret123");
    /// assert!(cmd.contains("user@example.com"));
    /// ```
    ///
    /// # Security Note
    ///
    /// The password is sent in plaintext within the JSON command, though it is
    /// encrypted using the TP-Link protocol before transmission over the network.
    pub fn cloud_bind(username: &str, password: &str) -> String {
        format!(
            r#"{{"cnCloud":{{"bind":{{"username":"{}","password":"{}"}}}}}}"#,
            username, password
        )
    }

    /// Generate a command to connect the device to a WiFi network.
    ///
    /// This command is used during device provisioning when the device is in AP mode.
    ///
    /// # Arguments
    ///
    /// * `ssid` - Network name (SSID) to connect to
    /// * `password` - Network password
    /// * `key_type` - Security type: 0=none, 1=WEP, 2=WPA, 3=WPA2
    ///
    /// # Example
    ///
    /// ```
    /// use kasa_core::commands;
    ///
    /// let cmd = commands::wifi_join("MyNetwork", "secret123", 3);
    /// assert!(cmd.contains("MyNetwork"));
    /// assert!(cmd.contains("key_type"));
    /// ```
    ///
    /// # Security Note
    ///
    /// The password is sent in plaintext within the JSON command, though it is
    /// encrypted using the TP-Link protocol before transmission over the network.
    pub fn wifi_join(ssid: &str, password: &str, key_type: u8) -> String {
        format!(
            r#"{{"netif":{{"set_stainfo":{{"ssid":"{}","password":"{}","key_type":{}}}}}}}"#,
            ssid, password, key_type
        )
    }

    /// Generate a command to connect the device to a WiFi network (alternative endpoint).
    ///
    /// Some newer devices use the `smartlife.iot.common.softaponboarding` module
    /// instead of `netif`. Try [`wifi_join`] first, then fall back to this.
    ///
    /// # Arguments
    ///
    /// * `ssid` - Network name (SSID) to connect to
    /// * `password` - Network password
    /// * `key_type` - Security type: 0=none, 1=WEP, 2=WPA, 3=WPA2
    pub fn wifi_join_softap(ssid: &str, password: &str, key_type: u8) -> String {
        format!(
            r#"{{"smartlife.iot.common.softaponboarding":{{"set_stainfo":{{"ssid":"{}","password":"{}","key_type":{}}}}}}}"#,
            ssid, password, key_type
        )
    }
}

/// Information about a discovered Kasa device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    /// IP address of the device.
    pub ip: IpAddr,
    /// TCP port (typically 9999).
    pub port: u16,
    /// Device alias/name set by the user.
    pub alias: String,
    /// Device model (e.g., "HS103", "KP115").
    pub model: String,
    /// MAC address of the device.
    pub mac: String,
    /// Unique device ID.
    pub device_id: String,
    /// Hardware version.
    pub hw_ver: String,
    /// Software/firmware version.
    pub sw_ver: String,
    /// Current relay state (true = on, false = off).
    pub relay_state: bool,
    /// Whether the LED is off.
    pub led_off: bool,
    /// WiFi signal strength in dBm.
    pub rssi: i32,
    /// Seconds since the relay was turned on (0 if off).
    pub on_time: u64,
    /// Whether a firmware update is in progress.
    pub updating: bool,
}

/// Security type for WiFi networks.
///
/// Used when scanning for networks or joining a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum KeyType {
    /// Open network (no security)
    None = 0,
    /// WEP encryption (legacy, insecure)
    Wep = 1,
    /// WPA-PSK encryption
    Wpa = 2,
    /// WPA2-PSK encryption (most common)
    #[default]
    Wpa2 = 3,
}

impl From<KeyType> for u8 {
    fn from(key_type: KeyType) -> Self {
        key_type as u8
    }
}

impl TryFrom<u8> for KeyType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyType::None),
            1 => Ok(KeyType::Wep),
            2 => Ok(KeyType::Wpa),
            3 => Ok(KeyType::Wpa2),
            _ => Err("Invalid key type: must be 0-3"),
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::None => write!(f, "None"),
            KeyType::Wep => write!(f, "WEP"),
            KeyType::Wpa => write!(f, "WPA"),
            KeyType::Wpa2 => write!(f, "WPA2"),
        }
    }
}

/// Information about a WiFi network from a scan.
///
/// Returned by the device when scanning for available networks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiNetwork {
    /// Network name (SSID)
    pub ssid: String,
    /// Security type
    pub key_type: u8,
    /// Signal strength in dBm (negative, closer to 0 = stronger)
    pub rssi: i32,
}

/// Result of a broadcast command to a single device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastResult {
    /// IP address of the device.
    pub ip: IpAddr,
    /// Device alias/name.
    pub alias: String,
    /// Device model.
    pub model: String,
    /// Whether the command succeeded.
    pub success: bool,
    /// The response from the device (if successful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response structure for parsing sysinfo from devices.
#[derive(Debug, Deserialize)]
struct SysInfoResponse {
    system: SystemWrapper,
}

#[derive(Debug, Deserialize)]
struct SystemWrapper {
    get_sysinfo: SysInfo,
}

#[derive(Debug, Deserialize)]
struct SysInfo {
    alias: String,
    model: String,
    #[serde(default)]
    mac: String,
    #[serde(rename = "deviceId", default)]
    device_id: String,
    #[allow(dead_code)]
    #[serde(rename = "hwId", default)]
    hw_id: String,
    #[serde(rename = "hw_ver", default)]
    hw_ver: String,
    #[serde(rename = "sw_ver", default)]
    sw_ver: String,
    #[serde(default)]
    relay_state: u8,
    #[serde(default)]
    led_off: u8,
    // Some devices use mic_mac instead of mac
    #[serde(rename = "mic_mac", default)]
    mic_mac: String,
    #[serde(default)]
    rssi: i32,
    #[serde(default)]
    on_time: u64,
    #[serde(default)]
    updating: u8,
}

/// Encrypts a plaintext string using the TP-Link Smart Home Protocol.
///
/// The encryption uses an XOR autokey cipher with a starting key of 171.
/// The result includes a 4-byte big-endian length prefix followed by the
/// encrypted payload.
///
/// # Arguments
///
/// * `plaintext` - The JSON command string to encrypt
///
/// # Returns
///
/// A byte vector containing the length prefix and encrypted payload,
/// ready to be sent over TCP.
///
/// # Example
///
/// ```
/// use kasa_core::encrypt;
///
/// let command = r#"{"system":{"get_sysinfo":{}}}"#;
/// let encrypted = encrypt(command);
///
/// // First 4 bytes are the length header
/// assert_eq!(encrypted.len(), 4 + command.len());
/// ```
pub fn encrypt(plaintext: &str) -> Vec<u8> {
    let mut key: u8 = 171;
    let bytes = plaintext.as_bytes();
    let len = bytes.len() as u32;

    let mut result = Vec::with_capacity(4 + bytes.len());
    result.extend_from_slice(&len.to_be_bytes());

    for &byte in bytes {
        let encrypted = key ^ byte;
        key = encrypted;
        result.push(encrypted);
    }

    result
}

/// Encrypts for UDP broadcast (no length prefix).
///
/// UDP discovery uses the same XOR cipher but without the 4-byte length header.
fn encrypt_udp(plaintext: &str) -> Vec<u8> {
    let mut key: u8 = 171;
    let bytes = plaintext.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());

    for &byte in bytes {
        let encrypted = key ^ byte;
        key = encrypted;
        result.push(encrypted);
    }

    result
}

/// Decrypts ciphertext using the TP-Link Smart Home Protocol.
///
/// The decryption uses an XOR autokey cipher with a starting key of 171.
/// This function expects the raw encrypted payload **without** the 4-byte
/// length prefix.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted payload bytes (excluding length header)
///
/// # Returns
///
/// The decrypted string. Invalid UTF-8 sequences are replaced with the
/// Unicode replacement character.
///
/// # Example
///
/// ```
/// use kasa_core::{encrypt, decrypt};
///
/// let original = r#"{"system":{"get_sysinfo":{}}}"#;
/// let encrypted = encrypt(original);
///
/// // Decrypt, skipping the 4-byte length header
/// let decrypted = decrypt(&encrypted[4..]);
/// assert_eq!(original, decrypted);
/// ```
pub fn decrypt(ciphertext: &[u8]) -> String {
    let mut key: u8 = 171;
    let mut result = Vec::with_capacity(ciphertext.len());

    for &byte in ciphertext {
        let decrypted = key ^ byte;
        key = byte;
        result.push(decrypted);
    }

    String::from_utf8_lossy(&result).to_string()
}

/// Sends a command to a TP-Link Kasa device and returns the response.
///
/// This function establishes a TCP connection to the specified device,
/// sends an encrypted command, and returns the decrypted response.
///
/// # Arguments
///
/// * `target` - Hostname or IP address of the device (e.g., "192.168.1.100" or "my-plug.local")
/// * `port` - TCP port number (typically [`DEFAULT_PORT`] which is 9999)
/// * `command_timeout` - Connection and I/O timeout
/// * `command` - JSON command string to send (see [`commands`] module for predefined commands)
///
/// # Returns
///
/// On success, returns the decrypted JSON response from the device.
///
/// # Errors
///
/// Returns an `io::Error` if:
/// - The hostname cannot be resolved
/// - The connection times out or fails
/// - The device response is malformed (less than 4 bytes)
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
/// use kasa_core::{commands, send_command, DEFAULT_PORT, DEFAULT_TIMEOUT};
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     // Get device information
///     let response = send_command(
///         "192.168.1.100",
///         DEFAULT_PORT,
///         DEFAULT_TIMEOUT,
///         commands::INFO,
///     ).await?;
///
///     println!("Device info: {}", response);
///     Ok(())
/// }
/// ```
///
/// # Protocol Details
///
/// The function performs the following steps:
/// 1. Resolves the target hostname to a socket address
/// 2. Establishes a TCP connection with the specified timeout
/// 3. Encrypts the command using [`encrypt`]
/// 4. Sends the encrypted message
/// 5. Receives and decrypts the response using [`decrypt`]
pub async fn send_command(
    target: &str,
    port: u16,
    command_timeout: Duration,
    command: &str,
) -> std::io::Result<String> {
    let addr = format!("{}:{}", target, port);
    debug!("Connecting to {}", addr);

    // Connect with timeout
    let mut stream = timeout(command_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timed out"))??;

    debug!("Connected to {}", addr);

    let encrypted = encrypt(command);
    debug!("Sending {} bytes", encrypted.len());

    // Write with timeout
    timeout(command_timeout, stream.write_all(&encrypted))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Write timed out"))??;

    // Read the 4-byte length header first
    let mut len_buf = [0u8; 4];
    timeout(command_timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Read timed out"))??;

    let payload_len = u32::from_be_bytes(len_buf) as usize;
    debug!("Response payload length: {} bytes", payload_len);

    // Read the full payload
    let mut payload = vec![0u8; payload_len];
    timeout(command_timeout, stream.read_exact(&mut payload))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Read timed out"))??;

    debug!("Received {} bytes", payload_len);

    let decrypted = decrypt(&payload);
    Ok(decrypted)
}

/// Discovers Kasa devices on the local network using UDP broadcast.
///
/// This function sends a UDP broadcast to find all Kasa devices on the local
/// network. Devices respond with their system information, which is parsed
/// and returned as a list of [`DiscoveredDevice`] structs.
///
/// # Arguments
///
/// * `discovery_timeout` - How long to wait for device responses.
///   Use [`DEFAULT_DISCOVERY_TIMEOUT`] for a reasonable default (3 seconds).
///
/// # Returns
///
/// A vector of discovered devices. The vector may be empty if no devices
/// are found or if there are network issues.
///
/// # Errors
///
/// Returns an `io::Error` if:
/// - Unable to bind to a UDP socket
/// - Unable to enable broadcast mode
/// - Unable to send the discovery packet
///
/// # Example
///
/// ```no_run
/// use kasa_core::{discover, DEFAULT_DISCOVERY_TIMEOUT};
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     let devices = discover(DEFAULT_DISCOVERY_TIMEOUT).await?;
///
///     for device in devices {
///         println!("Found: {} ({}) at {}", device.alias, device.model, device.ip);
///     }
///     Ok(())
/// }
/// ```
///
/// # Network Requirements
///
/// - The calling machine must be on the same network/subnet as the Kasa devices
/// - UDP broadcast must not be blocked by firewall rules
/// - Some networks (e.g., guest networks) may isolate devices and prevent discovery
pub async fn discover(discovery_timeout: Duration) -> std::io::Result<Vec<DiscoveredDevice>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    let encrypted = encrypt_udp(commands::INFO);
    debug!("Sending discovery broadcast to {}", BROADCAST_ADDR);
    socket.send_to(&encrypted, BROADCAST_ADDR).await?;

    let mut devices = Vec::new();
    let mut buf = [0u8; 4096];

    let deadline = tokio::time::Instant::now() + discovery_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            debug!("Discovery timeout reached");
            break;
        }

        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, addr))) => {
                debug!("Received {} bytes from {}", n, addr);
                let decrypted = decrypt(&buf[..n]);
                debug!("Decrypted response: {}", decrypted);

                if let Ok(response) = serde_json::from_str::<SysInfoResponse>(&decrypted) {
                    let info = response.system.get_sysinfo;
                    let mac = if info.mac.is_empty() {
                        info.mic_mac.clone()
                    } else {
                        info.mac.clone()
                    };

                    devices.push(DiscoveredDevice {
                        ip: addr.ip(),
                        port: DEFAULT_PORT,
                        alias: info.alias,
                        model: info.model,
                        mac,
                        device_id: info.device_id,
                        hw_ver: info.hw_ver,
                        sw_ver: info.sw_ver,
                        relay_state: info.relay_state == 1,
                        led_off: info.led_off == 1,
                        rssi: info.rssi,
                        on_time: info.on_time,
                        updating: info.updating == 1,
                    });
                }
            }
            Ok(Err(e)) => {
                debug!("Error receiving discovery response: {}", e);
                break;
            }
            Err(_) => {
                // Timeout
                debug!("Discovery timeout reached");
                break;
            }
        }
    }

    debug!("Discovered {} devices", devices.len());
    Ok(devices)
}

/// Broadcasts a command to all discovered Kasa devices on the local network.
///
/// This function first discovers all devices, then sends the specified command
/// to each device in parallel. Results are collected and returned for each device.
///
/// # Arguments
///
/// * `discovery_timeout` - How long to wait for device discovery
/// * `command_timeout` - Timeout for each device command
/// * `command` - JSON command string to send to all devices
///
/// # Returns
///
/// A vector of [`BroadcastResult`] containing the result for each discovered device.
///
/// # Example
///
/// ```no_run
/// use kasa_core::{broadcast, commands, DEFAULT_DISCOVERY_TIMEOUT, DEFAULT_TIMEOUT};
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     // Turn off all devices
///     let results = broadcast(
///         DEFAULT_DISCOVERY_TIMEOUT,
///         DEFAULT_TIMEOUT,
///         commands::RELAY_OFF,
///     ).await?;
///
///     for result in results {
///         if result.success {
///             println!("{}: OK", result.alias);
///         } else {
///             println!("{}: FAILED - {}", result.alias, result.error.unwrap_or_default());
///         }
///     }
///     Ok(())
/// }
/// ```
pub async fn broadcast(
    discovery_timeout: Duration,
    command_timeout: Duration,
    command: &str,
) -> std::io::Result<Vec<BroadcastResult>> {
    // First, discover all devices
    let devices = discover(discovery_timeout).await?;
    debug!("Broadcasting command to {} devices", devices.len());

    if devices.is_empty() {
        return Ok(Vec::new());
    }

    // Send command to all devices in parallel
    let command = command.to_string();
    let futures: Vec<_> = devices
        .into_iter()
        .map(|device| {
            let cmd = command.clone();
            async move {
                let result =
                    send_command(&device.ip.to_string(), device.port, command_timeout, &cmd).await;

                match result {
                    Ok(response) => {
                        let json_response = serde_json::from_str(&response).ok();
                        BroadcastResult {
                            ip: device.ip,
                            alias: device.alias,
                            model: device.model,
                            success: true,
                            response: json_response,
                            error: None,
                        }
                    }
                    Err(e) => BroadcastResult {
                        ip: device.ip,
                        alias: device.alias,
                        model: device.model,
                        success: false,
                        response: None,
                        error: Some(e.to_string()),
                    },
                }
            }
        })
        .collect();

    let results = futures::future::join_all(futures).await;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = r#"{"system":{"get_sysinfo":{}}}"#;
        let encrypted = encrypt(original);
        // Skip the 4-byte length header for decryption
        let decrypted = decrypt(&encrypted[4..]);
        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_encrypt_has_length_header() {
        let input = "test";
        let encrypted = encrypt(input);
        // First 4 bytes should be the length in big-endian
        let len = u32::from_be_bytes([encrypted[0], encrypted[1], encrypted[2], encrypted[3]]);
        assert_eq!(len as usize, input.len());
    }

    #[test]
    fn test_decrypt_empty() {
        let result = decrypt(&[]);
        assert_eq!(result, "");
    }

    #[test]
    fn test_encrypt_produces_correct_length() {
        let input = "hello world";
        let encrypted = encrypt(input);
        assert_eq!(encrypted.len(), 4 + input.len());
    }

    #[test]
    fn test_encrypt_udp_no_length_header() {
        let input = "test";
        let encrypted = encrypt_udp(input);
        // UDP encryption has no length header
        assert_eq!(encrypted.len(), input.len());
    }

    #[test]
    fn test_encrypt_udp_decrypt_roundtrip() {
        let original = r#"{"system":{"get_sysinfo":{}}}"#;
        let encrypted = encrypt_udp(original);
        let decrypted = decrypt(&encrypted);
        assert_eq!(original, decrypted);
    }
}
