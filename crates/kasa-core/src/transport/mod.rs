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

use crate::{Credentials, error::Error};

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
    // If credentials are provided, try authenticated protocols
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
