//! Core library for communicating with TP-Link Kasa smart home devices.
//!
//! This crate implements both the legacy TP-Link Smart Home Protocol (XOR cipher)
//! and the newer KLAP protocol (AES encryption with authentication).
//!
//! # Protocols
//!
//! ## Legacy Protocol (XOR)
//!
//! Older devices use a simple XOR autokey cipher on TCP port 9999.
//! No authentication is required. Use [`send_command`] for quick access.
//!
//! ## KLAP Protocol
//!
//! Newer firmware versions use the KLAP (Kasa Local Authentication Protocol)
//! over HTTP port 80. This requires TP-Link cloud credentials. Use the
//! [`transport`] module for KLAP support.
//!
//! # Quick Start
//!
//! For legacy devices (no credentials needed):
//!
//! ```no_run
//! use kasa_core::{commands, send_command, DEFAULT_PORT, DEFAULT_TIMEOUT};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let response = send_command(
//!         "192.168.1.100",
//!         DEFAULT_PORT,
//!         DEFAULT_TIMEOUT,
//!         commands::INFO,
//!     ).await?;
//!     println!("{}", response);
//!     Ok(())
//! }
//! ```
//!
//! For newer devices with KLAP (credentials required):
//!
//! ```no_run
//! use kasa_core::{Credentials, transport::{DeviceConfig, connect, Transport}};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = DeviceConfig::new("192.168.1.100")
//!         .with_credentials(Credentials::new("user@example.com", "password"));
//!
//!     let transport = connect(config).await?;
//!     let response = transport.send(r#"{"system":{"get_sysinfo":{}}}"#).await?;
//!     println!("{}", response);
//!     Ok(())
//! }
//! ```
//!
//! # Auto-Detection
//!
//! The [`transport::connect`] function automatically detects which protocol
//! a device uses and connects appropriately.
//!
//! # Concurrency
//!
//! When working with multiple devices, you can communicate with them concurrently.
//! However, **requests to a single device must be sequential** - TP-Link devices
//! cannot handle concurrent requests and will return errors.
//!
//! ```no_run
//! use kasa_core::transport::{DeviceConfig, connect, TransportExt};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to multiple devices
//!     let device1 = connect(DeviceConfig::new("192.168.1.100")).await?;
//!     let device2 = connect(DeviceConfig::new("192.168.1.101")).await?;
//!
//!     // Query both devices concurrently (safe - different devices)
//!     let (info1, info2) = tokio::join!(
//!         device1.get_sysinfo(),
//!         device2.get_sysinfo(),
//!     );
//!
//!     println!("Device 1: {}", info1?.alias);
//!     println!("Device 2: {}", info2?.alias);
//!     Ok(())
//! }
//! ```

use std::{net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::{net::UdpSocket, time::timeout};
use tracing::debug;

// Public modules
pub mod commands;
pub mod credentials;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod response;
pub mod transport;

// Re-exports for convenience
pub use credentials::Credentials;
pub use discovery::DiscoveredDevice;
pub use error::Error;
pub use transport::{DeviceConfig, EncryptionType, Transport, TransportExt, connect};

// Re-export crypto functions for backward compatibility
pub use crypto::xor::{decrypt, encrypt};

/// The version of the kasa-core library.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default TCP port for legacy TP-Link Kasa smart devices.
///
/// Legacy devices listen on port 9999 for the XOR-encrypted Smart Home Protocol.
/// Newer devices use port 80 (HTTP) for the KLAP protocol.
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

/// Sends a command to a TP-Link Kasa device using the legacy XOR protocol.
///
/// This function uses the legacy protocol (TCP port 9999, XOR encryption).
/// For devices with newer firmware that use KLAP, use [`transport::connect`] instead.
///
/// # Arguments
///
/// * `target` - Hostname or IP address of the device
/// * `port` - TCP port number (typically [`DEFAULT_PORT`] which is 9999)
/// * `command_timeout` - Connection and I/O timeout
/// * `command` - JSON command string to send
///
/// # Returns
///
/// On success, returns the decrypted JSON response from the device.
///
/// # Errors
///
/// Returns an `io::Error` if the connection fails or times out.
///
/// # Example
///
/// ```no_run
/// use kasa_core::{commands, send_command, DEFAULT_PORT, DEFAULT_TIMEOUT};
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     let response = send_command(
///         "192.168.1.100",
///         DEFAULT_PORT,
///         DEFAULT_TIMEOUT,
///         commands::INFO,
///     ).await?;
///     println!("{}", response);
///     Ok(())
/// }
/// ```
pub async fn send_command(
    target: &str,
    port: u16,
    command_timeout: Duration,
    command: &str,
) -> std::io::Result<String> {
    use transport::LegacyTransport;

    let transport = LegacyTransport::new(target, port, command_timeout);
    transport
        .send(command)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Discovers Kasa devices on the local network using UDP broadcast.
///
/// This function sends a UDP broadcast to find all Kasa devices on the local
/// network. Note that devices using KLAP may not respond to legacy discovery.
///
/// # Arguments
///
/// * `discovery_timeout` - How long to wait for device responses.
///
/// # Returns
///
/// A vector of discovered devices.
///
/// # Example
///
/// ```no_run
/// use kasa_core::{discover, DEFAULT_DISCOVERY_TIMEOUT};
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     let devices = discover(DEFAULT_DISCOVERY_TIMEOUT).await?;
///     for device in devices {
///         println!("Found: {} ({}) at {}", device.alias, device.model, device.ip);
///     }
///     Ok(())
/// }
/// ```
pub async fn discover(discovery_timeout: Duration) -> std::io::Result<Vec<DiscoveredDevice>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    let encrypted = crypto::xor::encrypt_udp(commands::INFO);
    debug!(addr = BROADCAST_ADDR, "sending discovery broadcast");
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
                debug!(bytes = n, addr = %addr, "received discovery response");
                let decrypted = decrypt(&buf[..n]);
                debug!(response = %decrypted, "decrypted discovery response");

                if let Ok(response) = serde_json::from_str::<response::SysInfoResponse>(&decrypted)
                {
                    let info = response.system.get_sysinfo;

                    devices.push(DiscoveredDevice {
                        ip: addr.ip(),
                        port: DEFAULT_PORT,
                        mac: info.mac_address().to_string(),
                        relay_state: info.is_on(),
                        led_off: info.is_led_off(),
                        updating: info.is_updating(),
                        rssi: info.rssi,
                        on_time: info.on_time,
                        alias: info.alias,
                        model: info.model,
                        device_id: info.device_id,
                        hw_ver: info.hw_ver,
                        sw_ver: info.sw_ver,
                        encryption_type: EncryptionType::Xor, // Legacy discovery
                        http_port: None,
                        new_klap: None,
                        login_version: None,
                    });
                }
            }
            Ok(Err(e)) => {
                debug!(error = %e, "error receiving discovery response");
                break;
            }
            Err(_) => {
                debug!("discovery timeout reached");
                break;
            }
        }
    }

    debug!(device_count = devices.len(), "discovery completed");
    Ok(devices)
}

/// Broadcasts a command to all discovered Kasa devices on the local network.
///
/// This function first discovers all devices, then sends the specified command
/// to each device concurrently. It uses the appropriate protocol for each device
/// based on discovery results (encryption hints).
///
/// # Arguments
///
/// * `discovery_timeout` - How long to wait for device discovery
/// * `command_timeout` - Timeout for each device command
/// * `command` - JSON command string to send to all devices
/// * `credentials` - Optional TP-Link cloud credentials for KLAP/TPAP devices
///
/// # Returns
///
/// A vector of [`BroadcastResult`] containing the result for each discovered device.
///
/// # Protocol Selection
///
/// For each discovered device, the function uses [`DeviceConfig::from_discovered`]
/// to configure the connection with the appropriate encryption hint. This ensures
/// devices using KLAP or TPAP protocols are handled correctly when credentials
/// are provided.
///
/// # Energy Command Handling
///
/// For energy commands (`{"emeter":{"get_realtime":{}}}`), this function
/// automatically uses [`TransportExt::get_all_energy`] to fetch energy data
/// for all plugs on power strips, not just the first plug.
pub async fn broadcast(
    discovery_timeout: Duration,
    command_timeout: Duration,
    command: &str,
    credentials: Option<Credentials>,
) -> std::io::Result<Vec<BroadcastResult>> {
    let devices = discovery::discover_all(discovery_timeout).await?;
    debug!(device_count = devices.len(), "broadcasting command");

    if devices.is_empty() {
        return Ok(Vec::new());
    }

    let command = command.to_string();
    let credentials = credentials.map(std::sync::Arc::new);
    let is_energy_command = command.contains("emeter") && command.contains("get_realtime");

    let futures: Vec<_> = devices
        .into_iter()
        .map(|device| {
            let cmd = command.clone();
            let creds = credentials.clone();
            async move {
                // Build config from discovered device (includes encryption hint)
                let mut config =
                    DeviceConfig::from_discovered(&device).with_timeout(command_timeout);

                if let Some(creds) = creds {
                    config = config.with_credentials((*creds).clone());
                }

                // Try to connect using the appropriate protocol
                let transport = match transport::connect(config).await {
                    Ok(t) => t,
                    Err(e) => {
                        return BroadcastResult {
                            ip: device.ip,
                            alias: device.alias,
                            model: device.model,
                            success: false,
                            response: None,
                            error: Some(e.to_string()),
                        };
                    }
                };

                // Use get_all_energy() for energy commands to handle power strips
                let result = if is_energy_command {
                    transport
                        .get_all_energy()
                        .await
                        .map(|energy| serde_json::to_value(&energy).ok())
                } else {
                    transport
                        .send(&cmd)
                        .await
                        .map(|response| serde_json::from_str(&response).ok())
                };

                match result {
                    Ok(json_response) => BroadcastResult {
                        ip: device.ip,
                        alias: device.alias,
                        model: device.model,
                        success: true,
                        response: json_response,
                        error: None,
                    },
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
        let decrypted = decrypt(&encrypted[4..]);
        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_encrypt_has_length_header() {
        let input = "test";
        let encrypted = encrypt(input);
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
}
