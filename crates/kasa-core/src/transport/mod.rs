//! Transport layer for communicating with TP-Link Kasa devices.
//!
//! This module provides different transport implementations for the various
//! protocols used by TP-Link devices:
//!
//! - [`LegacyTransport`]: XOR-encrypted TCP on port 9999 (older firmware)
//! - [`KlapTransport`]: HTTP with AES encryption on port 80 (newer firmware)
//!
//! Use [`connect`] to automatically detect and connect using the appropriate protocol.

pub mod klap;
pub mod legacy;
pub mod tpap;

pub use klap::KlapTransport;
pub use legacy::LegacyTransport;
pub use tpap::TpapTransport;

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{Credentials, DiscoveredDevice, error::Error};

/// Default timeout for transport operations.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Encryption type used by a device.
///
/// This is detected during discovery or connection to determine
/// which transport protocol to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EncryptionType {
    /// Legacy XOR cipher on port 9999 (no authentication).
    #[default]
    Xor,
    /// KLAP protocol on port 80 (requires authentication).
    Klap,
    /// AES protocol on port 443 (Tapo devices, requires authentication).
    Aes,
    /// TPAP protocol on port 4433 (SPAKE2+ authentication).
    Tpap,
}

impl std::fmt::Display for EncryptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionType::Xor => write!(f, "XOR"),
            EncryptionType::Klap => write!(f, "KLAP"),
            EncryptionType::Aes => write!(f, "AES"),
            EncryptionType::Tpap => write!(f, "TPAP"),
        }
    }
}

/// Configuration for connecting to a device.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    /// The device hostname or IP address.
    pub host: String,
    /// Optional port override (auto-detected if None).
    pub port: Option<u16>,
    /// Credentials for KLAP/AES authentication.
    pub credentials: Option<Credentials>,
    /// Connection and I/O timeout.
    pub timeout: Duration,
    /// Use HTTPS instead of HTTP for KLAP.
    pub https: bool,
    /// Hint about which encryption protocol to try first.
    /// When set (e.g., from discovery), `connect()` will try this protocol first
    /// before falling back to auto-detection.
    pub encryption_hint: Option<EncryptionType>,
}

impl DeviceConfig {
    /// Creates a new device configuration.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
            credentials: None,
            timeout: DEFAULT_TIMEOUT,
            https: false,
            encryption_hint: None,
        }
    }

    /// Sets the port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the credentials.
    pub fn with_credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Sets the timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enables HTTPS for KLAP connections.
    pub fn with_https(mut self, https: bool) -> Self {
        self.https = https;
        self
    }

    /// Sets a hint about which encryption protocol to try first.
    ///
    /// When set, `connect()` will attempt the hinted protocol first before
    /// falling back to auto-detection. This improves connection speed when
    /// the protocol is already known (e.g., from discovery).
    pub fn with_encryption_hint(mut self, hint: EncryptionType) -> Self {
        self.encryption_hint = Some(hint);
        self
    }

    /// Creates a device configuration from a discovered device.
    ///
    /// This sets the host and port based on discovery results, allowing
    /// `connect()` to use the appropriate protocol without probing.
    ///
    /// Credentials must still be added separately if required:
    ///
    /// ```no_run
    /// use kasa_core::{Credentials, DiscoveredDevice, transport::DeviceConfig};
    ///
    /// fn connect_to_discovered(device: &DiscoveredDevice) -> DeviceConfig {
    ///     DeviceConfig::from_discovered(device)
    ///         .with_credentials(Credentials::new("user@example.com", "password"))
    /// }
    /// ```
    pub fn from_discovered(device: &DiscoveredDevice) -> Self {
        Self::new(device.ip.to_string())
            .with_port(device.port)
            .with_encryption_hint(device.encryption_type)
    }
}

/// Attempts to connect to a device, auto-detecting the protocol.
///
/// This function tries different protocols in order:
/// 1. KLAP on port 80 (if credentials provided)
/// 2. Legacy XOR on port 9999
///
/// # Arguments
///
/// * `config` - Device configuration including host and optional credentials
///
/// # Returns
///
/// A boxed transport on success, or an error if no protocol works.
///
/// # Example
///
/// ```no_run
/// use kasa_core::{Credentials, transport::{DeviceConfig, connect, Transport}};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Try connecting with credentials (for KLAP devices)
///     let config = DeviceConfig::new("192.168.1.100")
///         .with_credentials(Credentials::new("user@example.com", "password"));
///     
///     let mut transport = connect(config).await?;
///     let response = transport.send(r#"{"system":{"get_sysinfo":{}}}"#).await?;
///     println!("{}", response);
///     Ok(())
/// }
/// ```
pub async fn connect(config: DeviceConfig) -> Result<Box<dyn Transport>, Error> {
    // If we have an encryption hint from discovery, try that protocol first
    if let Some(hint) = config.encryption_hint {
        tracing::debug!("Using encryption hint: {}", hint);
        match hint {
            EncryptionType::Xor => {
                if let Ok(transport) = try_legacy(&config).await {
                    return Ok(Box::new(transport));
                }
                tracing::debug!("Hinted XOR protocol failed, trying other protocols");
            }
            EncryptionType::Klap => {
                if let Ok(transport) = try_klap(&config).await {
                    return Ok(Box::new(transport));
                }
                tracing::debug!("Hinted KLAP protocol failed, trying other protocols");
            }
            EncryptionType::Tpap => {
                if let Ok(transport) = try_tpap(&config).await {
                    return Ok(Box::new(transport));
                }
                tracing::debug!("Hinted TPAP protocol failed, trying other protocols");
            }
            EncryptionType::Aes => {
                // AES (Tapo) not yet implemented, fall through to auto-detection
                tracing::debug!("AES protocol not yet supported, trying other protocols");
            }
        }
    }

    // Auto-detect protocol: try authenticated protocols first if credentials provided
    if config.credentials.is_some() {
        // Try TPAP first (newer firmware on port 4433)
        match try_tpap(&config).await {
            Ok(transport) => return Ok(Box::new(transport)),
            Err(e) => {
                tracing::debug!("TPAP connection failed: {}, trying KLAP", e);
            }
        }

        // Try KLAP (port 80)
        match try_klap(&config).await {
            Ok(transport) => return Ok(Box::new(transport)),
            Err(e) => {
                tracing::debug!("KLAP connection failed: {}, trying legacy", e);
            }
        }
    }

    // Try legacy XOR protocol
    match try_legacy(&config).await {
        Ok(transport) => return Ok(Box::new(transport)),
        Err(e) => {
            tracing::debug!("Legacy connection failed: {}", e);
        }
    }

    // If we have credentials and both failed, try KLAP with default credentials
    if config.credentials.is_none() {
        // No credentials provided, try KLAP with blank credentials
        let mut klap_config = config.clone();
        klap_config.credentials = Some(Credentials::blank());
        if let Ok(transport) = try_klap(&klap_config).await {
            return Ok(Box::new(transport));
        }
    }

    Err(Error::ConnectionFailed(format!(
        "Could not connect to {} using any protocol",
        config.host
    )))
}

async fn try_tpap(config: &DeviceConfig) -> Result<TpapTransport, Error> {
    let port = config.port.unwrap_or(tpap::DEFAULT_PORT);
    let credentials = config.credentials.clone().unwrap_or_default();

    TpapTransport::connect(&config.host, port, credentials, config.timeout).await
}

async fn try_klap(config: &DeviceConfig) -> Result<KlapTransport, Error> {
    let port = config.port.unwrap_or(if config.https { 4433 } else { 80 });
    let credentials = config.credentials.clone().unwrap_or_default();

    KlapTransport::connect(
        &config.host,
        port,
        credentials,
        config.timeout,
        config.https,
    )
    .await
}

async fn try_legacy(config: &DeviceConfig) -> Result<LegacyTransport, Error> {
    let port = config.port.unwrap_or(9999);

    let transport = LegacyTransport::new(&config.host, port, config.timeout);
    // Test the connection by sending a simple command
    let mut transport_clone = transport.clone();
    transport_clone
        .send(r#"{"system":{"get_sysinfo":{}}}"#)
        .await?;

    Ok(transport)
}

/// Trait for device transport protocols.
///
/// This trait abstracts over different transport protocols (legacy XOR, KLAP)
/// to provide a unified interface for sending commands to devices.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends a JSON command to the device and returns the response.
    ///
    /// # Arguments
    ///
    /// * `command` - JSON command string to send
    ///
    /// # Returns
    ///
    /// The JSON response from the device, or an error.
    async fn send(&mut self, command: &str) -> Result<String, Error>;

    /// Returns the encryption type used by this transport.
    fn encryption_type(&self) -> EncryptionType;

    /// Returns the device host.
    fn host(&self) -> &str;

    /// Returns the device port.
    fn port(&self) -> u16;
}

/// Extension trait providing typed convenience methods for device communication.
///
/// This trait provides high-level methods that handle JSON serialization/deserialization
/// automatically, making it easier to interact with devices without dealing with raw JSON.
///
/// # Example
///
/// ```no_run
/// use kasa_core::transport::{DeviceConfig, connect, TransportExt};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut transport = connect(DeviceConfig::new("192.168.1.100")).await?;
///     
///     // Get device info with typed response
///     let sysinfo = transport.get_sysinfo().await?;
///     println!("Device: {} ({})", sysinfo.alias, sysinfo.model);
///     
///     // Get energy reading (if supported)
///     if let Ok(energy) = transport.get_energy().await {
///         if let Some(power) = energy.power_w() {
///             println!("Power: {:.1}W", power);
///         }
///     }
///     
///     // Control the relay
///     transport.set_relay_state(true).await?;
///     
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait TransportExt: Transport {
    /// Gets device system information.
    ///
    /// Returns detailed information about the device including model, firmware version,
    /// current relay state, and for power strips, information about each child plug.
    async fn get_sysinfo(&mut self) -> Result<crate::response::SysInfo, Error>;

    /// Gets real-time energy meter readings.
    ///
    /// Returns voltage, current, power, and total energy consumption.
    /// Only available on devices with energy monitoring (e.g., HS110, KP115, HS300).
    ///
    /// The returned [`EnergyReading`](crate::response::EnergyReading) normalizes values
    /// to standard units (volts, amps, watts) regardless of device-specific formats.
    async fn get_energy(&mut self) -> Result<crate::response::EnergyReading, Error>;

    /// Gets cloud connection information.
    ///
    /// Returns whether the device is connected to TP-Link cloud services.
    async fn get_cloud_info(&mut self) -> Result<crate::response::CloudInfo, Error>;

    /// Sets the relay state (on/off).
    ///
    /// # Arguments
    ///
    /// * `on` - `true` to turn on, `false` to turn off
    async fn set_relay_state(&mut self, on: bool) -> Result<(), Error>;

    /// Sets the LED indicator state.
    ///
    /// # Arguments
    ///
    /// * `off` - `true` to turn LED off, `false` to turn LED on
    async fn set_led_off(&mut self, off: bool) -> Result<(), Error>;

    /// Gets energy meter readings for a specific child plug on a power strip.
    ///
    /// # Arguments
    ///
    /// * `child_id` - The child plug ID (from [`SysInfo::children`](crate::response::SysInfo::children))
    async fn get_energy_for_child(
        &mut self,
        child_id: &str,
    ) -> Result<crate::response::EnergyReading, Error>;

    /// Sets the relay state for a specific child plug on a power strip.
    ///
    /// # Arguments
    ///
    /// * `child_id` - The child plug ID (from [`SysInfo::children`](crate::response::SysInfo::children))
    /// * `on` - `true` to turn on, `false` to turn off
    async fn set_relay_state_for_child(&mut self, child_id: &str, on: bool) -> Result<(), Error>;

    /// Reboots the device.
    ///
    /// The device will restart after a 1-second delay.
    async fn reboot(&mut self) -> Result<(), Error>;
}

#[async_trait]
impl<T: Transport + ?Sized + Send> TransportExt for T {
    async fn get_sysinfo(&mut self) -> Result<crate::response::SysInfo, Error> {
        let response = self.send(crate::commands::INFO).await?;
        let parsed: crate::response::SysInfoResponse =
            serde_json::from_str(&response).map_err(|e| Error::ParseError(e.to_string()))?;
        Ok(parsed.system.get_sysinfo)
    }

    async fn get_energy(&mut self) -> Result<crate::response::EnergyReading, Error> {
        let response = self.send(crate::commands::ENERGY).await?;
        let parsed: crate::response::EmeterResponse =
            serde_json::from_str(&response).map_err(|e| Error::ParseError(e.to_string()))?;

        if parsed.emeter.get_realtime.err_code != 0 {
            return Err(Error::DeviceError(format!(
                "Energy monitoring not supported (err_code: {})",
                parsed.emeter.get_realtime.err_code
            )));
        }

        Ok(parsed.emeter.get_realtime)
    }

    async fn get_cloud_info(&mut self) -> Result<crate::response::CloudInfo, Error> {
        let response = self.send(crate::commands::CLOUDINFO).await?;
        let parsed: crate::response::CloudInfoResponse =
            serde_json::from_str(&response).map_err(|e| Error::ParseError(e.to_string()))?;
        Ok(parsed.cn_cloud.get_info)
    }

    async fn set_relay_state(&mut self, on: bool) -> Result<(), Error> {
        let command = if on {
            crate::commands::RELAY_ON
        } else {
            crate::commands::RELAY_OFF
        };
        self.send(command).await?;
        Ok(())
    }

    async fn set_led_off(&mut self, off: bool) -> Result<(), Error> {
        let command = if off {
            crate::commands::LED_OFF
        } else {
            crate::commands::LED_ON
        };
        self.send(command).await?;
        Ok(())
    }

    async fn get_energy_for_child(
        &mut self,
        child_id: &str,
    ) -> Result<crate::response::EnergyReading, Error> {
        let command = crate::commands::energy_for_child(child_id);
        let response = self.send(&command).await?;
        let parsed: crate::response::EmeterResponse =
            serde_json::from_str(&response).map_err(|e| Error::ParseError(e.to_string()))?;

        if parsed.emeter.get_realtime.err_code != 0 {
            return Err(Error::DeviceError(format!(
                "Energy monitoring not supported for child {} (err_code: {})",
                child_id, parsed.emeter.get_realtime.err_code
            )));
        }

        Ok(parsed.emeter.get_realtime)
    }

    async fn set_relay_state_for_child(&mut self, child_id: &str, on: bool) -> Result<(), Error> {
        let command = if on {
            crate::commands::relay_on_for_child(child_id)
        } else {
            crate::commands::relay_off_for_child(child_id)
        };
        self.send(&command).await?;
        Ok(())
    }

    async fn reboot(&mut self) -> Result<(), Error> {
        self.send(crate::commands::REBOOT).await?;
        Ok(())
    }
}
