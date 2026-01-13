//! Error types for kasa-core.
//!
//! This module defines the error types returned by the library.

use thiserror::Error;

/// Error type for kasa-core operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Connection to the device failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Authentication failed (KLAP protocol).
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Protocol error (unexpected response format, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// I/O error during communication.
    #[error("I/O error: {0}")]
    IoError(String),

    /// Device returned an error response.
    #[error("device error: {0}")]
    DeviceError(String),

    /// Failed to parse device response.
    #[error("parse error: {0}")]
    ParseError(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}
