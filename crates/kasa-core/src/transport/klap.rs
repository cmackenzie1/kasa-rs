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
        KlapEncryptionSession, generate_auth_hash, handshake1_seed_auth_hash,
        handshake1_seed_auth_hash_v2, handshake2_seed_auth_hash, handshake2_seed_auth_hash_v2,
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

        // Try authentication with different credential sets
        let auth_hash = generate_auth_hash(&credentials);
        debug!(
            username = %credentials.username,
            auth_hash = %hex::encode(auth_hash),
            "Trying user credentials"
        );

        // First try user credentials
        match Self::try_handshake(host, port, &auth_hash, timeout).await {
            Ok((session, session_cookie)) => {
                debug!("KLAP handshake succeeded with user credentials");
                return Ok(Self {
                    host: host.to_string(),
                    port,
                    session: Arc::new(Mutex::new(session)),
                    session_cookie,
                    timeout,
                });
            }
            Err(e) => {
                debug!("User credentials failed: {}", e);
            }
        }

        // Try default credentials
        for default_creds in DefaultCredentials::all() {
            let creds = default_creds.credentials();
            let hash = generate_auth_hash(&creds);
            debug!(
                credential_type = ?default_creds,
                username = %creds.username,
                auth_hash = %hex::encode(hash),
                "Trying default credentials"
            );

            match Self::try_handshake(host, port, &hash, timeout).await {
                Ok((session, session_cookie)) => {
                    debug!(
                        credential_type = ?default_creds,
                        "KLAP handshake succeeded with default credentials"
                    );
                    return Ok(Self {
                        host: host.to_string(),
                        port,
                        session: Arc::new(Mutex::new(session)),
                        session_cookie,
                        timeout,
                    });
                }
                Err(e) => {
                    debug!("{:?} default credentials failed: {}", default_creds, e);
                }
            }
        }

        // Try blank credentials
        if !credentials.is_blank() {
            let blank_creds = Credentials::blank();
            let blank_hash = generate_auth_hash(&blank_creds);
            debug!(
                username = %blank_creds.username,
                auth_hash = %hex::encode(blank_hash),
                "Trying blank credentials"
            );

            match Self::try_handshake(host, port, &blank_hash, timeout).await {
                Ok((session, session_cookie)) => {
                    debug!("KLAP handshake succeeded with blank credentials");
                    return Ok(Self {
                        host: host.to_string(),
                        port,
                        session: Arc::new(Mutex::new(session)),
                        session_cookie,
                        timeout,
                    });
                }
                Err(e) => {
                    debug!("Blank credentials failed: {}", e);
                }
            }
        }

        Err(Error::AuthenticationFailed(
            "KLAP authentication failed with all credential sets".into(),
        ))
    }

    /// Attempts a full handshake with the given auth hash.
    async fn try_handshake(
        host: &str,
        port: u16,
        auth_hash: &[u8; 16],
        io_timeout: Duration,
    ) -> Result<(KlapEncryptionSession, String), Error> {
        // Generate random local seed
        let mut local_seed = [0u8; 16];
        rand::rng().fill_bytes(&mut local_seed);

        // Handshake 1
        let (remote_seed, server_hash, session_cookie) =
            Self::perform_handshake1(host, port, &local_seed, io_timeout).await?;

        // Try v1 hash first: sha256(local_seed + auth_hash)
        let expected_hash_v1 = handshake1_seed_auth_hash(&local_seed, auth_hash);
        // Try v2 hash: sha256(local_seed + remote_seed + auth_hash)
        let expected_hash_v2 = handshake1_seed_auth_hash_v2(&local_seed, &remote_seed, auth_hash);

        debug!(
            auth_hash = %hex::encode(auth_hash),
            local_seed = %hex::encode(local_seed),
            remote_seed = %hex::encode(remote_seed),
            server_hash = %hex::encode(server_hash),
            expected_hash_v1 = %hex::encode(expected_hash_v1),
            expected_hash_v2 = %hex::encode(expected_hash_v2),
            "Verifying handshake1 hash (trying v1 and v2)"
        );

        let use_v2 = if server_hash == expected_hash_v1 {
            debug!("Hash matches using KLAP v1");
            false
        } else if server_hash == expected_hash_v2 {
            debug!("Hash matches using KLAP v2");
            true
        } else {
            debug!(
                server_hash = %hex::encode(server_hash),
                expected_v1 = %hex::encode(expected_hash_v1),
                expected_v2 = %hex::encode(expected_hash_v2),
                "Hash mismatch - credentials do not match device (tried v1 and v2)"
            );
            return Err(Error::AuthenticationFailed(
                "Server hash does not match expected hash".into(),
            ));
        };

        // Handshake 2 - use appropriate version
        if use_v2 {
            let payload = handshake2_seed_auth_hash_v2(&local_seed, &remote_seed, auth_hash);
            Self::perform_handshake2_with_payload(
                host,
                port,
                &payload,
                &session_cookie,
                io_timeout,
            )
            .await?;
        } else {
            Self::perform_handshake2(
                host,
                port,
                &remote_seed,
                auth_hash,
                &session_cookie,
                io_timeout,
            )
            .await?;
        }

        // Create encryption session
        let session = KlapEncryptionSession::new(&local_seed, &remote_seed, auth_hash);

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

    /// Performs handshake 2: send confirmation hash (v1).
    async fn perform_handshake2(
        host: &str,
        port: u16,
        remote_seed: &[u8; 16],
        auth_hash: &[u8; 16],
        session_cookie: &str,
        io_timeout: Duration,
    ) -> Result<(), Error> {
        // Note: v1 protocol only uses remote_seed + auth_hash (not local_seed)
        let payload = handshake2_seed_auth_hash(remote_seed, auth_hash);
        Self::perform_handshake2_with_payload(host, port, &payload, session_cookie, io_timeout)
            .await
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
