//! KLAP transport for newer TP-Link Kasa devices.
//!
//! KLAP (Kasa Local Authentication Protocol) is used by newer firmware versions.
//! It operates over HTTP(S) on port 80 (or 4433 for HTTPS) and requires authentication.
//!
//! # Protocol Overview
//!
//! 1. **Handshake 1**: Client sends 16 random bytes, device responds with 16 bytes + hash
//! 2. **Handshake 2**: Client sends confirmation hash, device responds with session cookie
//! 3. **Request**: Client sends encrypted command, device responds with encrypted response
//!
//! # Authentication
//!
//! Authentication uses credentials (username/password) that are hashed:
//! `auth_hash = md5(md5(username) + md5(password))`
//!
//! Devices may accept:
//! - User's TP-Link cloud credentials
//! - Default Kasa credentials (`kasa@tp-link.net` / `kasaSetup`)
//! - Default Tapo credentials (`tapo@tp-link.net` / `tapoSetup`)
//! - Blank credentials (for devices never connected to cloud)
//!
//! # Note on HTTP Implementation
//!
//! This implementation uses raw TCP sockets instead of HTTP client libraries because
//! TP-Link devices have a non-compliant HTTP server that rejects requests with lowercase
//! headers. Modern HTTP libraries (reqwest, hyper, ureq) forcibly lowercase all headers
//! following HTTP/2 conventions, but TP-Link devices only support HTTP/1.1 with
//! title-case headers (e.g., "Content-Type" not "content-type").

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::{
    Credentials,
    credentials::DefaultCredentials,
    crypto::klap::{
        KlapEncryptionSession, generate_auth_hash, generate_auth_hash_v2,
        handshake1_seed_auth_hash, handshake1_seed_auth_hash_v2, handshake2_seed_auth_hash,
        handshake2_seed_auth_hash_v2,
    },
    error::Error,
    transport::{EncryptionType, Transport},
};

/// Default HTTP port for KLAP protocol.
pub const DEFAULT_PORT: u16 = 80;

/// Default HTTPS port for KLAP protocol.
pub const DEFAULT_HTTPS_PORT: u16 = 4433;

/// Session cookie name used by KLAP.
const SESSION_COOKIE_NAME: &str = "TP_SESSIONID";

/// Authentication hash for KLAP protocol.
///
/// KLAP v1 uses MD5-based hashing, while v2 uses SHA256-based hashing.
#[derive(Clone)]
enum AuthHash {
    /// KLAP v1: `md5(md5(username) + md5(password))` - 16 bytes
    V1([u8; 16]),
    /// KLAP v2: `sha256(sha1(username) + sha1(password))` - 32 bytes
    V2([u8; 32]),
}

impl AuthHash {
    /// Returns the auth hash as a hex string for logging.
    fn hex(&self) -> String {
        match self {
            AuthHash::V1(h) => hex::encode(h),
            AuthHash::V2(h) => hex::encode(h),
        }
    }

    /// Returns the auth hash as a byte slice.
    fn as_bytes(&self) -> &[u8] {
        match self {
            AuthHash::V1(h) => h.as_slice(),
            AuthHash::V2(h) => h.as_slice(),
        }
    }

    /// Returns true if this is a v2 auth hash.
    fn is_v2(&self) -> bool {
        matches!(self, AuthHash::V2(_))
    }
}

/// Transport using the KLAP protocol over HTTP(S).
///
/// This transport connects to devices on port 80 (HTTP) or 4433 (HTTPS) and uses
/// AES encryption with a session established via a two-phase handshake.
///
/// # Example
///
/// ```no_run
/// use kasa_core::{Credentials, transport::{KlapTransport, Transport}};
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let credentials = Credentials::new("user@example.com", "password");
///     let mut transport = KlapTransport::connect(
///         "192.168.1.100",
///         80,
///         credentials,
///         Duration::from_secs(10),
///         false,
///     ).await?;
///     
///     let response = transport.send(r#"{"system":{"get_sysinfo":{}}}"#).await?;
///     println!("{}", response);
///     Ok(())
/// }
/// ```
pub struct KlapTransport {
    host: String,
    port: u16,
    session: Arc<Mutex<KlapEncryptionSession>>,
    session_cookie: String,
    timeout: Duration,
}

impl KlapTransport {
    /// Connects to a device using the KLAP protocol.
    ///
    /// This performs the two-phase handshake and establishes an encrypted session.
    ///
    /// # Arguments
    ///
    /// * `host` - Device hostname or IP address
    /// * `port` - HTTP port (typically 80 or 4433 for HTTPS)
    /// * `credentials` - User credentials for authentication
    /// * `timeout` - Connection and I/O timeout
    /// * `https` - Use HTTPS instead of HTTP (not currently supported)
    ///
    /// # Returns
    ///
    /// A connected transport ready for sending commands, or an error.
    pub async fn connect(
        host: &str,
        port: u16,
        credentials: Credentials,
        timeout: Duration,
        https: bool,
    ) -> Result<Self, Error> {
        if https {
            return Err(Error::ConnectionFailed(
                "HTTPS not supported for KLAP transport (use HTTP on port 80)".into(),
            ));
        }

        debug!(host, port, "Attempting KLAP connection");

        // Build list of auth hashes to try
        // For each credential set, we try both KLAP v1 (MD5-based) and v2 (SHA256-based)
        let mut auth_attempts: Vec<(&str, AuthHash)> = Vec::new();

        // User credentials - try v2 first (newer devices), then v1
        let user_hash_v2 = generate_auth_hash_v2(&credentials);
        let user_hash_v1 = generate_auth_hash(&credentials);
        auth_attempts.push(("user (v2)", AuthHash::V2(user_hash_v2)));
        auth_attempts.push(("user (v1)", AuthHash::V1(user_hash_v1)));

        // Default credentials
        for default_creds in DefaultCredentials::all() {
            let creds = default_creds.credentials();
            let hash_v2 = generate_auth_hash_v2(&creds);
            let hash_v1 = generate_auth_hash(&creds);
            let name_v2 = match default_creds {
                DefaultCredentials::Kasa => "kasa default (v2)",
                DefaultCredentials::Tapo => "tapo default (v2)",
            };
            let name_v1 = match default_creds {
                DefaultCredentials::Kasa => "kasa default (v1)",
                DefaultCredentials::Tapo => "tapo default (v1)",
            };
            auth_attempts.push((name_v2, AuthHash::V2(hash_v2)));
            auth_attempts.push((name_v1, AuthHash::V1(hash_v1)));
        }

        // Blank credentials
        if !credentials.is_blank() {
            let blank_creds = Credentials::blank();
            let blank_hash_v2 = generate_auth_hash_v2(&blank_creds);
            let blank_hash_v1 = generate_auth_hash(&blank_creds);
            auth_attempts.push(("blank (v2)", AuthHash::V2(blank_hash_v2)));
            auth_attempts.push(("blank (v1)", AuthHash::V1(blank_hash_v1)));
        }

        // Try each auth hash
        for (name, auth_hash) in auth_attempts {
            debug!(
                credential_type = name,
                auth_hash = %auth_hash.hex(),
                "Trying credentials"
            );

            match Self::try_handshake_with_auth(host, port, &auth_hash, timeout).await {
                Ok((session, session_cookie)) => {
                    debug!(credential_type = name, "KLAP handshake succeeded");
                    return Ok(Self {
                        host: host.to_string(),
                        port,
                        session: Arc::new(Mutex::new(session)),
                        session_cookie,
                        timeout,
                    });
                }
                Err(e) => {
                    debug!(credential_type = name, error = %e, "Credentials failed");
                }
            }
        }

        Err(Error::AuthenticationFailed(
            "KLAP authentication failed with all credential sets (tried v1 and v2)".into(),
        ))
    }

    /// Attempts a full handshake with the given auth hash (v1 or v2).
    async fn try_handshake_with_auth(
        host: &str,
        port: u16,
        auth_hash: &AuthHash,
        io_timeout: Duration,
    ) -> Result<(KlapEncryptionSession, String), Error> {
        // Generate random local seed
        let mut local_seed = [0u8; 16];
        rand::rng().fill_bytes(&mut local_seed);

        // Handshake 1
        let (remote_seed, server_hash, session_cookie) =
            Self::perform_handshake1(host, port, &local_seed, io_timeout).await?;

        // Compute expected hash based on auth hash version
        let (expected_hash, use_v2_handshake) = match auth_hash {
            AuthHash::V1(h) => {
                // KLAP v1: sha256(local_seed + auth_hash)
                (handshake1_seed_auth_hash(&local_seed, h), false)
            }
            AuthHash::V2(h) => {
                // KLAP v2: sha256(local_seed + remote_seed + auth_hash)
                (
                    handshake1_seed_auth_hash_v2(&local_seed, &remote_seed, h),
                    true,
                )
            }
        };

        debug!(
            auth_hash = %auth_hash.hex(),
            is_v2 = auth_hash.is_v2(),
            local_seed = %hex::encode(local_seed),
            remote_seed = %hex::encode(remote_seed),
            server_hash = %hex::encode(server_hash),
            expected_hash = %hex::encode(expected_hash),
            "Verifying handshake1 hash"
        );

        if server_hash != expected_hash {
            debug!(
                server_hash = %hex::encode(server_hash),
                expected = %hex::encode(expected_hash),
                "Hash mismatch - credentials do not match device"
            );
            return Err(Error::AuthenticationFailed(
                "Server hash does not match expected hash".into(),
            ));
        }

        debug!(is_v2 = use_v2_handshake, "Handshake1 hash verified");

        // Handshake 2 - use appropriate version
        let handshake2_payload = if use_v2_handshake {
            // KLAP v2: sha256(remote_seed + local_seed + auth_hash)
            handshake2_seed_auth_hash_v2(&local_seed, &remote_seed, auth_hash.as_bytes())
        } else {
            // KLAP v1: sha256(remote_seed + auth_hash)
            match auth_hash {
                AuthHash::V1(h) => handshake2_seed_auth_hash(&remote_seed, h),
                AuthHash::V2(_) => unreachable!("v2 auth hash should use v2 handshake"),
            }
        };

        Self::perform_handshake2_with_payload(
            host,
            port,
            &handshake2_payload,
            &session_cookie,
            io_timeout,
        )
        .await?;

        // Create encryption session
        let session = KlapEncryptionSession::new(&local_seed, &remote_seed, auth_hash.as_bytes());

        Ok((session, session_cookie))
    }

    /// Sends a raw HTTP POST request and returns the response.
    async fn http_post(
        host: &str,
        port: u16,
        path: &str,
        body: &[u8],
        cookie: Option<&str>,
        io_timeout: Duration,
    ) -> Result<(u16, Vec<u8>, Option<String>), Error> {
        // Build the HTTP request with title-case headers
        let mut request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Accept: */*\r\n",
            path,
            host,
            port,
            body.len()
        );

        if let Some(cookie_value) = cookie {
            request.push_str(&format!(
                "Cookie: {}={}\r\n",
                SESSION_COOKIE_NAME, cookie_value
            ));
        }

        request.push_str("\r\n");

        // Connect to the device
        let addr = format!("{}:{}", host, port);
        let mut stream = timeout(io_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::ConnectionFailed("Connection timed out".into()))?
            .map_err(|e| Error::ConnectionFailed(format!("Connection failed: {}", e)))?;

        // Send the request
        let mut full_request = request.into_bytes();
        full_request.extend_from_slice(body);

        timeout(io_timeout, stream.write_all(&full_request))
            .await
            .map_err(|_| Error::ConnectionFailed("Write timed out".into()))?
            .map_err(|e| Error::ConnectionFailed(format!("Write failed: {}", e)))?;

        // Read the response
        let mut response = Vec::with_capacity(1024);
        let mut buf = [0u8; 4096];

        // Read headers first
        loop {
            let n = timeout(io_timeout, stream.read(&mut buf))
                .await
                .map_err(|_| Error::ConnectionFailed("Read timed out".into()))?
                .map_err(|e| Error::ConnectionFailed(format!("Read failed: {}", e)))?;

            if n == 0 {
                break;
            }

            response.extend_from_slice(&buf[..n]);

            // Check if we have the complete headers
            if let Some(header_end) = find_header_end(&response) {
                // Parse headers to find Content-Length
                let headers = String::from_utf8_lossy(&response[..header_end]);
                let content_length = parse_content_length(&headers);

                // Calculate how much body we still need
                let body_start = header_end + 4; // After \r\n\r\n
                let _body_received = response.len() - body_start;

                if let Some(expected_len) = content_length {
                    // Read remaining body if needed
                    while response.len() - body_start < expected_len {
                        let n = timeout(io_timeout, stream.read(&mut buf))
                            .await
                            .map_err(|_| Error::ConnectionFailed("Read timed out".into()))?
                            .map_err(|e| Error::ConnectionFailed(format!("Read failed: {}", e)))?;

                        if n == 0 {
                            break;
                        }

                        response.extend_from_slice(&buf[..n]);
                    }
                }

                break;
            }
        }

        // Parse the response
        let header_end = find_header_end(&response)
            .ok_or_else(|| Error::Protocol("Invalid HTTP response: no header end".into()))?;

        let headers = String::from_utf8_lossy(&response[..header_end]);
        let body_start = header_end + 4;
        let response_body = response[body_start..].to_vec();

        // Parse status code
        let status_code = parse_status_code(&headers)
            .ok_or_else(|| Error::Protocol("Invalid HTTP response: no status code".into()))?;

        // Parse Set-Cookie header
        let session_cookie = parse_session_cookie(&headers);

        Ok((status_code, response_body, session_cookie))
    }

    /// Performs handshake 1: send local seed, receive remote seed + hash.
    async fn perform_handshake1(
        host: &str,
        port: u16,
        local_seed: &[u8; 16],
        io_timeout: Duration,
    ) -> Result<([u8; 16], [u8; 32], String), Error> {
        debug!(
            host,
            port,
            local_seed = %hex::encode(local_seed),
            "Performing KLAP handshake1"
        );

        let (status, body, cookie) =
            Self::http_post(host, port, "/app/handshake1", local_seed, None, io_timeout).await?;

        if status != 200 {
            debug!(
                status,
                body = %String::from_utf8_lossy(&body),
                "Handshake1 failed"
            );
            return Err(Error::Protocol(format!(
                "Handshake1 returned status {}",
                status
            )));
        }

        if body.len() != 48 {
            return Err(Error::Protocol(format!(
                "Handshake1 response has unexpected length: {} (expected 48)",
                body.len()
            )));
        }

        let mut remote_seed = [0u8; 16];
        let mut server_hash = [0u8; 32];
        remote_seed.copy_from_slice(&body[..16]);
        server_hash.copy_from_slice(&body[16..48]);

        let session_cookie = cookie.unwrap_or_default();

        debug!(
            remote_seed = %hex::encode(remote_seed),
            cookie = %if session_cookie.is_empty() { "<none>" } else { &session_cookie },
            "Handshake1 received response"
        );

        Ok((remote_seed, server_hash, session_cookie))
    }

    /// Performs handshake 2 with a pre-computed payload.
    async fn perform_handshake2_with_payload(
        host: &str,
        port: u16,
        payload: &[u8; 32],
        session_cookie: &str,
        io_timeout: Duration,
    ) -> Result<(), Error> {
        debug!(host, port, "Performing KLAP handshake2");

        let cookie = if session_cookie.is_empty() {
            None
        } else {
            Some(session_cookie)
        };

        let (status, _body, _cookie) =
            Self::http_post(host, port, "/app/handshake2", payload, cookie, io_timeout).await?;

        if status != 200 {
            return Err(Error::AuthenticationFailed(format!(
                "Handshake2 returned status {}",
                status
            )));
        }

        debug!(host, port, "Handshake2 succeeded");
        Ok(())
    }

    /// Sends an encrypted request to the device.
    async fn send_request(&self, command: &str) -> Result<String, Error> {
        // Encrypt the command
        let (encrypted, seq) = {
            let mut session = self.session.lock().unwrap();
            let encrypted = session.encrypt(command.as_bytes());
            let seq = session.seq();
            (encrypted, seq)
        };

        let path = format!("/app/request?seq={}", seq);
        debug!(
            host = %self.host,
            port = self.port,
            seq,
            "Sending KLAP request"
        );

        let cookie = if self.session_cookie.is_empty() {
            None
        } else {
            Some(self.session_cookie.as_str())
        };

        let (status, body, _cookie) = Self::http_post(
            &self.host,
            self.port,
            &path,
            &encrypted,
            cookie,
            self.timeout,
        )
        .await?;

        if status != 200 {
            return Err(Error::Protocol(format!(
                "Request returned status {}",
                status
            )));
        }

        // Decrypt response
        let session = self.session.lock().unwrap();
        let decrypted = session
            .decrypt(&body, seq)
            .map_err(|e| Error::Protocol(format!("Failed to decrypt response: {}", e)))?;

        String::from_utf8(decrypted)
            .map_err(|e| Error::Protocol(format!("Response is not valid UTF-8: {}", e)))
    }
}

#[async_trait]
impl Transport for KlapTransport {
    async fn send(&mut self, command: &str) -> Result<String, Error> {
        self.send_request(command).await
    }

    fn encryption_type(&self) -> EncryptionType {
        EncryptionType::Klap
    }

    fn host(&self) -> &str {
        &self.host
    }

    fn port(&self) -> u16 {
        self.port
    }
}

// Implement Debug manually to avoid exposing sensitive session data
impl std::fmt::Debug for KlapTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KlapTransport")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("session_cookie", &"[REDACTED]")
            .finish()
    }
}

/// Find the position of "\r\n\r\n" in the response (end of headers).
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse the HTTP status code from the response headers.
fn parse_status_code(headers: &str) -> Option<u16> {
    // First line should be "HTTP/1.1 200 OK" or similar
    let first_line = headers.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// Parse the Content-Length header value.
fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            let value = line.split(':').nth(1)?.trim();
            return value.parse().ok();
        }
    }
    None
}

/// Parse the session cookie from Set-Cookie header.
fn parse_session_cookie(headers: &str) -> Option<String> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("set-cookie:") {
            let cookie_str = line.split(':').nth(1)?.trim();
            // Look for TP_SESSIONID=value
            if cookie_str.starts_with(SESSION_COOKIE_NAME) {
                // Parse "TP_SESSIONID=value;..." format
                return cookie_str
                    .split(';')
                    .next()
                    .and_then(|s| s.split('=').nth(1))
                    .map(|s| s.to_string());
            }
        }
    }
    None
}
