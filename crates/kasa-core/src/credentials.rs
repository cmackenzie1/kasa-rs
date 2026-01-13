//! Credentials management for TP-Link Kasa devices.
//!
//! This module provides the [`Credentials`] struct for authentication with
//! devices that use the KLAP protocol (newer firmware versions).
//!
//! # Default Credentials
//!
//! Some devices may accept default credentials instead of user-specific ones:
//! - **Kasa default**: Used by devices that have been connected to the Kasa cloud
//! - **Tapo default**: Used by Tapo-branded devices
//! - **Blank**: Used by devices that have never been connected to any cloud
//!
//! The KLAP handshake will try the user's credentials first, then fall back to
//! these defaults if authentication fails.

use std::fmt;

/// Credentials for authenticating with TP-Link devices.
///
/// Used by the KLAP protocol for devices with newer firmware.
/// Legacy devices (using the XOR protocol on port 9999) do not require credentials.
///
/// # Example
///
/// ```
/// use kasa_core::Credentials;
///
/// // Create credentials from username and password
/// let creds = Credentials::new("user@example.com", "password123");
///
/// // Create blank credentials (for devices never connected to cloud)
/// let blank = Credentials::blank();
/// ```
#[derive(Clone, Default)]
pub struct Credentials {
    /// The username (typically an email address for TP-Link cloud accounts).
    pub username: String,
    /// The password for the account.
    pub password: String,
}

impl Credentials {
    /// Creates new credentials with the given username and password.
    ///
    /// # Arguments
    ///
    /// * `username` - The TP-Link account email address
    /// * `password` - The account password
    ///
    /// # Example
    ///
    /// ```
    /// use kasa_core::Credentials;
    ///
    /// let creds = Credentials::new("user@example.com", "mypassword");
    /// assert_eq!(creds.username, "user@example.com");
    /// ```
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Creates blank credentials (empty username and password).
    ///
    /// Blank credentials work for devices that have never been connected
    /// to the TP-Link cloud.
    ///
    /// # Example
    ///
    /// ```
    /// use kasa_core::Credentials;
    ///
    /// let blank = Credentials::blank();
    /// assert!(blank.is_blank());
    /// ```
    pub fn blank() -> Self {
        Self::default()
    }

    /// Returns `true` if both username and password are empty.
    ///
    /// # Example
    ///
    /// ```
    /// use kasa_core::Credentials;
    ///
    /// assert!(Credentials::blank().is_blank());
    /// assert!(!Credentials::new("user", "pass").is_blank());
    /// ```
    pub fn is_blank(&self) -> bool {
        self.username.is_empty() && self.password.is_empty()
    }
}

impl PartialEq for Credentials {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username && self.password == other.password
    }
}

impl Eq for Credentials {}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Default credential set used by TP-Link devices.
///
/// These are hardcoded credentials that devices may accept when they've been
/// connected to the TP-Link cloud. The KLAP protocol implementation will try
/// these if user-provided credentials fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultCredentials {
    /// Default Kasa credentials (for Kasa-branded devices).
    Kasa,
    /// Default Tapo credentials (for Tapo-branded devices).
    Tapo,
}

impl DefaultCredentials {
    /// Returns the default credentials for the given type.
    ///
    /// These credentials are documented in the python-kasa library and are
    /// used by devices that have been connected to the TP-Link cloud.
    pub fn credentials(self) -> Credentials {
        match self {
            // These are the hardcoded default credentials used by python-kasa
            // https://github.com/python-kasa/python-kasa/blob/master/kasa/credentials.py
            DefaultCredentials::Kasa => Credentials::new("kasa@tp-link.net", "kasaSetup"),
            DefaultCredentials::Tapo => Credentials::new("test@tp-link.net", "test"),
        }
    }

    /// Returns all default credential types.
    pub fn all() -> &'static [DefaultCredentials] {
        &[DefaultCredentials::Kasa, DefaultCredentials::Tapo]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_new() {
        let creds = Credentials::new("user@example.com", "password123");
        assert_eq!(creds.username, "user@example.com");
        assert_eq!(creds.password, "password123");
    }

    #[test]
    fn test_credentials_blank() {
        let blank = Credentials::blank();
        assert!(blank.is_blank());
        assert_eq!(blank.username, "");
        assert_eq!(blank.password, "");
    }

    #[test]
    fn test_credentials_is_blank() {
        assert!(Credentials::blank().is_blank());
        assert!(Credentials::new("", "").is_blank());
        assert!(!Credentials::new("user", "").is_blank());
        assert!(!Credentials::new("", "pass").is_blank());
        assert!(!Credentials::new("user", "pass").is_blank());
    }

    #[test]
    fn test_credentials_equality() {
        let a = Credentials::new("user", "pass");
        let b = Credentials::new("user", "pass");
        let c = Credentials::new("user", "other");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_credentials_debug_redacts_password() {
        let creds = Credentials::new("user@example.com", "secret123");
        let debug = format!("{:?}", creds);
        assert!(debug.contains("user@example.com"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret123"));
    }

    #[test]
    fn test_default_credentials() {
        let kasa = DefaultCredentials::Kasa.credentials();
        assert_eq!(kasa.username, "kasa@tp-link.net");
        assert_eq!(kasa.password, "kasaSetup");

        let tapo = DefaultCredentials::Tapo.credentials();
        assert_eq!(tapo.username, "test@tp-link.net");
        assert_eq!(tapo.password, "test");
    }

    #[test]
    fn test_default_credentials_all() {
        let all = DefaultCredentials::all();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&DefaultCredentials::Kasa));
        assert!(all.contains(&DefaultCredentials::Tapo));
    }
}
