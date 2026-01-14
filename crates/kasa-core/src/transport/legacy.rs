//! Legacy XOR transport for older TP-Link Kasa devices.
//!
//! This transport uses the original TP-Link Smart Home Protocol:
//! - TCP connection on port 9999
//! - XOR autokey cipher with initial key 171
//! - No authentication required
//!
//! This is used by older firmware versions and devices that haven't been
//! updated to use KLAP.

use std::time::Duration;

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tracing::debug;

use crate::{
    crypto::xor::{decrypt, encrypt},
    error::Error,
    transport::{EncryptionType, Transport},
};

/// Default port for legacy TP-Link Smart Home Protocol.
pub const DEFAULT_PORT: u16 = 9999;

/// Transport using the legacy XOR protocol over TCP.
///
/// This transport connects to devices on port 9999 and uses an XOR autokey
/// cipher for encryption. No authentication is required.
///
/// # Example
///
/// ```no_run
/// use kasa_core::transport::{LegacyTransport, Transport};
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut transport = LegacyTransport::new("192.168.1.100", 9999, Duration::from_secs(10));
///     let response = transport.send(r#"{"system":{"get_sysinfo":{}}}"#).await?;
///     println!("{}", response);
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LegacyTransport {
    host: String,
    port: u16,
    timeout: Duration,
}

impl LegacyTransport {
    /// Creates a new legacy transport.
    ///
    /// # Arguments
    ///
    /// * `host` - Device hostname or IP address
    /// * `port` - TCP port (typically 9999)
    /// * `timeout` - Connection and I/O timeout
    pub fn new(host: impl Into<String>, port: u16, timeout: Duration) -> Self {
        Self {
            host: host.into(),
            port,
            timeout,
        }
    }

    /// Sends a command using the legacy protocol.
    async fn send_command(&self, command: &str) -> Result<String, Error> {
        let addr = format!("{}:{}", self.host, self.port);
        debug!(addr = %addr, "connecting");

        // Connect with timeout
        let mut stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Timeout("Connection timed out".into()))?
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        debug!(addr = %addr, "connected");

        let encrypted = encrypt(command);
        debug!(bytes = encrypted.len(), "sending request");

        // Write with timeout
        timeout(self.timeout, stream.write_all(&encrypted))
            .await
            .map_err(|_| Error::Timeout("Write timed out".into()))?
            .map_err(|e| Error::IoError(e.to_string()))?;

        // Read the 4-byte length header first
        let mut len_buf = [0u8; 4];
        timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| Error::Timeout("Read timed out".into()))?
            .map_err(|e| Error::IoError(e.to_string()))?;

        let payload_len = u32::from_be_bytes(len_buf) as usize;
        debug!(payload_bytes = payload_len, "response payload length");

        // Sanity check on payload length
        if payload_len > 1024 * 1024 {
            return Err(Error::Protocol(format!(
                "Response too large: {} bytes",
                payload_len
            )));
        }

        // Read the full payload
        let mut payload = vec![0u8; payload_len];
        timeout(self.timeout, stream.read_exact(&mut payload))
            .await
            .map_err(|_| Error::Timeout("Read timed out".into()))?
            .map_err(|e| Error::IoError(e.to_string()))?;

        debug!(bytes = payload_len, "received response");

        let decrypted = decrypt(&payload);
        Ok(decrypted)
    }
}

#[async_trait]
impl Transport for LegacyTransport {
    async fn send(&self, command: &str) -> Result<String, Error> {
        self.send_command(command).await
    }

    fn encryption_type(&self) -> EncryptionType {
        EncryptionType::Xor
    }

    fn host(&self) -> &str {
        &self.host
    }

    fn port(&self) -> u16 {
        self.port
    }
}
