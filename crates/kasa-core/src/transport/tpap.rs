//! TPAP transport for TP-Link devices with SPAKE2+ authentication.
//!
//! TPAP (TP-Link Adaptive Protocol) is used by newer firmware versions that
//! require stronger authentication. It operates over HTTP on port 80 or HTTPS
//! on port 4433 and
//! uses SPAKE2+ for password-authenticated key exchange.
//!
//! # Protocol Overview
//!
//! 1. **Discovery**: Client sends `{"method":"login","params":{"sub_method":"discover"}}`
//! 2. **PAKE Register**: Client initiates SPAKE2+ with random bytes, cipher preferences
//! 3. **PAKE Share**: Client sends SPAKE2+ share and confirmation
//! 4. **Data Session**: All subsequent requests are AEAD-encrypted with session key
//!
//! # TLS Requirements
//!
//! Devices advertising TLS use TLS 1.2. Devices advertising `tls: 0` use HTTP,
//! with application data protected by the authenticated TPAP session cipher.
//! The device may require mutual TLS (client certificate) for TLS mode 2.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rand::RngCore;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::debug;

use crate::{
    Credentials,
    crypto::{
        spake2plus::{Spake2PlusCipherSuite, Spake2PlusProver},
        tpap::{TpapCipherType, TpapSessionCipher},
    },
    error::Error,
    transport::{EncryptionType, Transport},
};

/// Default HTTPS port for TPAP protocol.
pub const DEFAULT_PORT: u16 = 4433;

/// Maximum size of an HTTP response we will buffer from a device. Bounds memory
/// use against a rogue/buggy device that streams an unbounded body.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// TPAP discovery information from device.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TpapInfo {
    /// TLS mode: 0=none, 1=server-only, 2=mutual
    #[serde(default)]
    pub tls: u8,
    /// Device Attestation Certificate support
    #[serde(default)]
    pub dac: u8,
    /// NOC (Network Operation Center) authentication support
    #[serde(default)]
    pub noc: u8,
    /// Supported PAKE types (0=default, 2=user credentials, 3=shared token)
    #[serde(default)]
    pub pake: Vec<u8>,
    /// TPAP port
    #[serde(default)]
    pub port: u16,
}

impl Default for TpapInfo {
    fn default() -> Self {
        Self {
            tls: 1,
            dac: 0,
            noc: 0,
            pake: vec![2],
            port: DEFAULT_PORT,
        }
    }
}

/// TPAP session state.
struct TpapSession {
    /// Session ID (stok) from device.
    session_id: String,
    /// Current sequence number (atomic for concurrent access).
    seq: AtomicU32,
    /// AEAD cipher for encryption/decryption.
    cipher: TpapSessionCipher,
}

/// Transport using the TPAP protocol over HTTP or HTTPS.
pub struct TpapTransport {
    host: String,
    port: u16,
    credentials: Credentials,
    timeout: Duration,
    tpap_info: Option<TpapInfo>,
    session: Option<TpapSession>,
    tls_config: Arc<rustls::ClientConfig>,
    https: bool,
}

impl TpapTransport {
    /// Connect to a device using the TPAP protocol.
    ///
    /// This performs discovery and SPAKE2+ authentication to establish
    /// an encrypted session.
    ///
    /// # Arguments
    ///
    /// * `host` - Device hostname or IP address
    /// * `port` - HTTPS port (typically 4433)
    /// * `credentials` - User credentials for SPAKE2+ authentication
    /// * `timeout` - Connection and I/O timeout
    pub async fn connect(
        host: &str,
        port: u16,
        credentials: Credentials,
        timeout: Duration,
    ) -> Result<Self, Error> {
        Self::connect_with_https(host, port, credentials, timeout, true).await
    }

    /// Connect using the HTTP or HTTPS mode advertised by TPAP discovery.
    ///
    /// # Arguments
    ///
    /// * `host` - Device IP address
    /// * `port` - Advertised TPAP port
    /// * `credentials` - TP-Link account credentials
    /// * `timeout` - Connection and I/O timeout
    /// * `https` - Whether the initial discovery request uses TLS
    ///
    /// # Errors
    ///
    /// Returns an error if discovery, authentication, or network I/O fails.
    pub async fn connect_with_https(
        host: &str,
        port: u16,
        credentials: Credentials,
        timeout: Duration,
        https: bool,
    ) -> Result<Self, Error> {
        debug!(host, port, https, "attempting TPAP connection");

        // Create TLS config (insecure for now - devices use self-signed certs)
        let tls_config = create_tls_config()?;

        let mut transport = Self {
            host: host.to_string(),
            port,
            credentials,
            timeout,
            tpap_info: None,
            session: None,
            tls_config: Arc::new(tls_config),
            https,
        };

        // Perform discovery
        transport.discover().await?;

        // Perform SPAKE2+ authentication
        transport.authenticate().await?;

        Ok(transport)
    }

    /// Perform TPAP discovery to get device capabilities.
    async fn discover(&mut self) -> Result<(), Error> {
        debug!(host = %self.host, "Performing TPAP discovery");

        let request = json!({
            "method": "login",
            "params": {
                "sub_method": "discover"
            }
        });

        let response = self.send_raw(&request.to_string()).await?;
        let response: Value = serde_json::from_str(&response)
            .map_err(|e| Error::Protocol(format!("Invalid discovery response: {}", e)))?;

        // Check for error
        if let Some(error_code) = response.get("error_code").and_then(|v| v.as_i64())
            && error_code != 0
        {
            return Err(Error::Protocol(format!(
                "Discovery failed with error code: {}",
                error_code
            )));
        }

        // Parse TPAP info from result
        if let Some(result) = response.get("result")
            && let Some(tpap) = result.get("tpap")
        {
            let info: TpapInfo = serde_json::from_value(tpap.clone())
                .map_err(|e| Error::Protocol(format!("Invalid TPAP settings: {e}")))?;
            self.https = info.tls != 0;
            if info.port != 0 {
                self.port = info.port;
            }
            self.tpap_info = Some(info);
        }

        debug!(tpap_info = ?self.tpap_info, "Discovery completed");
        Ok(())
    }

    /// Perform SPAKE2+ authentication.
    async fn authenticate(&mut self) -> Result<(), Error> {
        debug!(host = %self.host, "Starting SPAKE2+ authentication");

        // Generate user random
        let mut user_random = [0u8; 32];
        rand::rng().fill_bytes(&mut user_random);

        // Determine passcode type based on PAKE capabilities
        let passcode_type = if let Some(ref info) = self.tpap_info {
            if info.pake.contains(&0) {
                "default_userpw"
            } else {
                "userpw"
            }
        } else {
            "userpw"
        };

        // Phase 1: pake_register
        let register_request = json!({
            "method": "login",
            "params": {
                "sub_method": "pake_register",
                "username": md5_hex("admin"),
                "user_random": base64_encode(&user_random),
                "cipher_suites": [1],
                "encryption": ["aes_128_ccm", "chacha20_poly1305", "aes_256_ccm"],
                "passcode_type": passcode_type
            }
        });

        let register_response = self.send_raw(&register_request.to_string()).await?;
        let register: Value = serde_json::from_str(&register_response)
            .map_err(|e| Error::Protocol(format!("Invalid register response: {}", e)))?;

        // Check for error
        if let Some(error_code) = register.get("error_code").and_then(|v| v.as_i64())
            && error_code != 0
        {
            return Err(Error::AuthenticationFailed(format!(
                "PAKE register failed with error code: {}",
                error_code
            )));
        }

        let result = register
            .get("result")
            .ok_or_else(|| Error::Protocol("Missing result in register response".into()))?;

        // Extract register response fields
        let dev_random = base64_decode(
            result
                .get("dev_random")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Protocol("Missing dev_random".into()))?,
        )?;

        let dev_salt = base64_decode(
            result
                .get("dev_salt")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Protocol("Missing dev_salt".into()))?,
        )?;

        let dev_share = base64_decode(
            result
                .get("dev_share")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Protocol("Missing dev_share".into()))?,
        )?;

        // Reject iterations that would truncate when narrowed to u32 (2^32 would
        // wrap to 0, collapsing PBKDF2 stretching), and reject 0 explicitly.
        let iterations_u64 = result
            .get("iterations")
            .and_then(|v| v.as_u64())
            .unwrap_or(10000);
        if iterations_u64 == 0 || iterations_u64 > u32::MAX as u64 {
            return Err(Error::Protocol(format!(
                "Invalid PBKDF2 iterations from device: {iterations_u64}"
            )));
        }
        let iterations = iterations_u64 as u32;

        // Validate cipher suite fits in u8 before narrowing (avoids 257 -> 1 wrap).
        let cipher_suite_u64 = result
            .get("cipher_suites")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        if cipher_suite_u64 > u8::MAX as u64 {
            return Err(Error::Protocol(format!(
                "Invalid cipher suite from device: {cipher_suite_u64}"
            )));
        }
        let cipher_suite = cipher_suite_u64 as u8;

        let encryption = result
            .get("encryption")
            .and_then(|v| v.as_str())
            .unwrap_or("aes_128_ccm");

        debug!(
            iterations,
            cipher_suite, encryption, "Received PAKE register response"
        );

        // Parse cipher suite and encryption type
        let suite = Spake2PlusCipherSuite::from_u8(cipher_suite)
            .unwrap_or(Spake2PlusCipherSuite::P256Sha256HmacSha256);

        let cipher_type = TpapCipherType::parse(encryption).unwrap_or(TpapCipherType::Aes128Ccm);

        // Apply the password transformation negotiated by the device.
        let credential_str = resolve_credentials(&self.credentials, result)?;

        // dev_random must be exactly 32 bytes; truncating/zero-padding a
        // malformed value weakens transcript freshness, so reject it instead.
        let dev_random_arr: [u8; 32] = dev_random.as_slice().try_into().map_err(|_| {
            let len = dev_random.len();
            Error::Protocol(format!("Invalid dev_random length: {len} (expected 32)"))
        })?;

        let prover = Spake2PlusProver::new(
            credential_str.as_bytes(),
            &dev_salt,
            iterations,
            user_random,
            dev_random_arr,
            suite,
        );

        // Get our share
        let user_share = prover.share();

        // Process device share and get confirmations
        let (user_confirm, expected_dev_confirm, shared_key) = prover
            .process_share(&dev_share)
            .map_err(|e| Error::Protocol(format!("SPAKE2+ share processing failed: {}", e)))?;

        // Phase 2: pake_share
        let share_request = json!({
            "method": "login",
            "params": {
                "sub_method": "pake_share",
                "user_share": base64_encode(&user_share),
                "user_confirm": base64_encode(&user_confirm)
            }
        });

        let share_response = self.send_raw(&share_request.to_string()).await?;
        let share: Value = serde_json::from_str(&share_response)
            .map_err(|e| Error::Protocol(format!("Invalid share response: {}", e)))?;

        // Check for error
        if let Some(error_code) = share.get("error_code").and_then(|v| v.as_i64())
            && error_code != 0
        {
            return Err(Error::AuthenticationFailed(format!(
                "PAKE share failed with error code: {}",
                error_code
            )));
        }

        let share_result = share
            .get("result")
            .ok_or_else(|| Error::Protocol("Missing result in share response".into()))?;

        // Verify device confirmation
        let dev_confirm = share_result
            .get("dev_confirm")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Protocol("Missing dev_confirm".into()))?;

        let dev_confirm_bytes = base64_decode(dev_confirm)?;

        if dev_confirm_bytes != expected_dev_confirm {
            return Err(Error::AuthenticationFailed(
                "SPAKE2+ confirmation mismatch".into(),
            ));
        }

        // Extract session info
        let session_id = share_result
            .get("stok")
            .or_else(|| share_result.get("sessionId"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Protocol("Missing session ID".into()))?
            .to_string();

        let start_seq_u64 = share_result
            .get("start_seq")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        if start_seq_u64 > u32::MAX as u64 {
            return Err(Error::Protocol(format!(
                "Invalid start_seq from device: {start_seq_u64}"
            )));
        }
        let start_seq = start_seq_u64 as u32;

        // Create session cipher
        let use_sha512 = matches!(
            suite,
            Spake2PlusCipherSuite::P256Sha512HmacSha512 | Spake2PlusCipherSuite::P256Sha512CmacAes
        );
        let cipher = TpapSessionCipher::from_shared_key(cipher_type, &shared_key, use_sha512);

        self.session = Some(TpapSession {
            session_id,
            seq: AtomicU32::new(start_seq),
            cipher,
        });

        debug!(host = %self.host, "SPAKE2+ authentication successful");
        Ok(())
    }

    /// Send a raw (unencrypted) request to the device.
    ///
    /// Used during discovery and authentication phases.
    async fn send_raw(&self, body: &str) -> Result<String, Error> {
        // Use blocking I/O in a spawn_blocking context
        let host = self.host.clone();
        let port = self.port;
        let tls_config = self.tls_config.clone();
        let https = self.https;
        let timeout = self.timeout;
        let body = body.to_string();

        tokio::task::spawn_blocking(move || {
            send_http_request(
                &host,
                port,
                "/",
                &body,
                None,
                https.then_some(tls_config),
                timeout,
            )
        })
        .await
        .map_err(|e| Error::IoError(format!("Task join error: {}", e)))?
    }

    /// Send an encrypted request to the device.
    async fn send_encrypted(&self, command: &str) -> Result<String, Error> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| Error::Protocol("No active session".into()))?;

        // Atomically get and increment sequence number
        let seq = session.seq.fetch_add(1, Ordering::SeqCst);

        // Encrypt command
        let ciphertext = session
            .cipher
            .encrypt(command.as_bytes(), seq)
            .map_err(|e| Error::Protocol(format!("Encryption failed: {}", e)))?;
        let mut encrypted = seq.to_be_bytes().to_vec();
        encrypted.extend_from_slice(&ciphertext);

        // Build path with session ID and sequence
        let path = format!("/stok={}/ds", session.session_id);

        let host = self.host.clone();
        let port = self.port;
        let tls_config = self.tls_config.clone();
        let https = self.https;
        let timeout = self.timeout;

        // Send encrypted request
        let response = tokio::task::spawn_blocking(move || {
            send_http_request_binary(
                &host,
                port,
                &path,
                &encrypted,
                https.then_some(tls_config),
                timeout,
            )
        })
        .await
        .map_err(|e| Error::IoError(format!("Task join error: {}", e)))??;

        // Each encrypted frame carries its nonce sequence before the AEAD data.
        if response.len() < 4 + 16 {
            return Err(Error::Protocol("TPAP response is too short".into()));
        }
        let response_seq = u32::from_be_bytes(response[..4].try_into().unwrap());
        if response_seq != seq {
            debug!(
                request_seq = seq,
                response_seq, "device returned a different response sequence"
            );
        }
        let decrypted = session
            .cipher
            .decrypt(&response[4..], response_seq)
            .map_err(|e| Error::Protocol(format!("Decryption failed: {}", e)))?;

        String::from_utf8(decrypted)
            .map_err(|e| Error::Protocol(format!("Response is not valid UTF-8: {}", e)))
    }
}

#[async_trait]
impl Transport for TpapTransport {
    async fn send(&self, command: &str) -> Result<String, Error> {
        self.send_encrypted(command).await
    }

    fn encryption_type(&self) -> EncryptionType {
        EncryptionType::Tpap
    }

    fn host(&self) -> &str {
        &self.host
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Debug for TpapTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpapTransport")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tpap_info", &self.tpap_info)
            .field("has_session", &self.session.is_some())
            .finish()
    }
}

// =============================================================================
// TLS and HTTP helpers
// =============================================================================

/// Create a rustls client config for TPAP.
///
/// Note: TPAP devices use self-signed certificates, so we disable verification.
fn create_tls_config() -> Result<rustls::ClientConfig, Error> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    // Custom verifier that accepts any certificate
    #[derive(Debug)]
    struct InsecureVerifier;

    impl ServerCertVerifier for InsecureVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    // Pick crypto provider explicitly per feature — avoids relying on a
    // process-installed default.
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let provider = rustls::crypto::ring::default_provider();
    #[cfg(feature = "aws-lc-rs")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    // TLS 1.2 only — TPAP devices don't support 1.3.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|e| Error::Protocol(format!("TLS provider/version setup failed: {}", e)))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();

    Ok(config)
}

/// Send an HTTP or HTTPS POST request with JSON body.
fn send_http_request(
    host: &str,
    port: u16,
    path: &str,
    body: &str,
    _cookie: Option<&str>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    timeout: Duration,
) -> Result<String, Error> {
    let response =
        send_http_request_binary(host, port, path, body.as_bytes(), tls_config, timeout)?;
    String::from_utf8(response)
        .map_err(|e| Error::Protocol(format!("Response is not valid UTF-8: {}", e)))
}

/// Send an HTTP or HTTPS POST request with binary body.
fn send_http_request_binary(
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
    tls_config: Option<Arc<rustls::ClientConfig>>,
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    // Connect TCP
    let addr = format!("{}:{}", host, port);
    let mut tcp_stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| Error::ConnectionFailed(format!("Invalid address: {}", e)))?,
        timeout,
    )
    .map_err(|e| Error::ConnectionFailed(format!("TCP connect failed: {}", e)))?;

    tcp_stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| Error::IoError(format!("Set read timeout failed: {}", e)))?;
    tcp_stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| Error::IoError(format!("Set write timeout failed: {}", e)))?;

    if let Some(tls_config) = tls_config {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| Error::ConnectionFailed("Invalid server name".into()))?;
        let mut conn = rustls::ClientConnection::new(tls_config, server_name)
            .map_err(|e| Error::ConnectionFailed(format!("TLS connection failed: {}", e)))?;
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp_stream);
        exchange_http(&mut stream, host, port, path, body)
    } else {
        exchange_http(&mut tcp_stream, host, port, path, body)
    }
}

fn exchange_http(
    stream: &mut (impl Read + Write),
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    // Build HTTP request with title-case headers
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n",
        path,
        host,
        port,
        body.len()
    );

    // Send request
    stream
        .write_all(request.as_bytes())
        .map_err(|e| Error::IoError(format!("Write headers failed: {}", e)))?;
    stream
        .write_all(body)
        .map_err(|e| Error::IoError(format!("Write body failed: {}", e)))?;
    stream
        .flush()
        .map_err(|e| Error::IoError(format!("Flush failed: {}", e)))?;

    // Read response
    let mut response = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => return Err(Error::IoError(format!("Read failed: {}", e))),
        }

        // Bound memory against a rogue device that streams an unbounded body.
        if response.len() > MAX_RESPONSE_SIZE {
            return Err(Error::Protocol(format!(
                "Response too large: exceeded {MAX_RESPONSE_SIZE} bytes"
            )));
        }

        // Check if we have complete response (simple check for Content-Length)
        if let Some(header_end) = find_header_end(&response) {
            let headers = String::from_utf8_lossy(&response[..header_end]);
            if let Some(content_length) = parse_content_length(&headers) {
                if content_length > MAX_RESPONSE_SIZE {
                    return Err(Error::Protocol(format!(
                        "Response Content-Length {content_length} exceeds maximum {MAX_RESPONSE_SIZE}"
                    )));
                }
                let body_start = header_end + 4;
                if response.len() >= body_start + content_length {
                    break;
                }
            }
        }
    }

    // Parse HTTP response
    let header_end = find_header_end(&response)
        .ok_or_else(|| Error::Protocol("Invalid HTTP response: no header end".into()))?;

    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status = parse_status_code(&headers)
        .ok_or_else(|| Error::Protocol("Invalid HTTP response: no status".into()))?;

    if status != 200 {
        return Err(Error::Protocol(format!("HTTP error: {}", status)));
    }

    let body_start = header_end + 4;
    Ok(response[body_start..].to_vec())
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_code(headers: &str) -> Option<u16> {
    headers
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            return line.split(':').nth(1)?.trim().parse().ok();
        }
    }
    None
}

// =============================================================================
// Utility functions
// =============================================================================

fn resolve_credentials(credentials: &Credentials, result: &Value) -> Result<String, Error> {
    if let Some(extra) = result.get("extra_crypt")
        && let Some(kind) = extra.get("type").and_then(Value::as_str)
        && !kind.is_empty()
    {
        if kind == "password_shadow" && extra["params"]["passwd_id"].as_u64() == Some(2) {
            use sha1::{Digest, Sha1};
            return Ok(hex::encode(Sha1::digest(
                credentials.expose_password().as_bytes(),
            )));
        }
        return Err(Error::Protocol(format!(
            "Unsupported TPAP credential transformation: {kind}"
        )));
    }
    Ok(if credentials.username.is_empty() {
        credentials.expose_password().to_string()
    } else {
        format!("{}/{}", credentials.username, credentials.expose_password())
    })
}

/// Compute MD5 hash and return as hex string.
fn md5_hex(data: &str) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Base64 encode bytes.
fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

/// Base64 decode string.
fn base64_decode(data: &str) -> Result<Vec<u8>, Error> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD
        .decode(data)
        .map_err(|e| Error::Protocol(format!("Base64 decode failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve_once(response: Vec<u8>) -> (u16, std::thread::JoinHandle<Vec<u8>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let body_start;
            loop {
                let mut buf = [0; 1024];
                let n = stream.read(&mut buf).unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = find_header_end(&request) {
                    let length =
                        parse_content_length(&String::from_utf8_lossy(&request[..end])).unwrap();
                    if request.len() >= end + 4 + length {
                        body_start = end + 4;
                        break;
                    }
                }
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
            request[body_start..].to_vec()
        });
        (port, handle)
    }

    #[test]
    fn test_tpap_password_shadow_sha1() {
        let credentials = Credentials::new("user@example.com", "password");
        let result = json!({"extra_crypt":{"type":"password_shadow","params":{"passwd_id":2}}});
        assert_eq!(
            resolve_credentials(&credentials, &result).unwrap(),
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        );
    }

    #[tokio::test]
    async fn test_tpap_plain_http_request() {
        let (port, server) = serve_once(br#"{"error_code":0}"#.to_vec());
        let body = tokio::task::spawn_blocking(move || {
            send_http_request_binary(
                "127.0.0.1",
                port,
                "/",
                br#"{"method":"login"}"#,
                None,
                Duration::from_secs(3),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(body, br#"{"error_code":0}"#);
        assert_eq!(server.join().unwrap(), br#"{"method":"login"}"#);
    }

    #[tokio::test]
    async fn test_tpap_encrypted_frames_include_sequence() {
        for response_seq in [7u32, 8] {
            let cipher =
                TpapSessionCipher::from_shared_key(TpapCipherType::Aes128Ccm, &[0x42; 32], false);
            let seq = 7u32;
            let mut response = response_seq.to_be_bytes().to_vec();
            response.extend(
                cipher
                    .encrypt(br#"{"error_code":0}"#, response_seq)
                    .unwrap(),
            );
            let (port, server) = serve_once(response);
            let transport = TpapTransport {
                host: "127.0.0.1".into(),
                port,
                credentials: Credentials::blank(),
                timeout: Duration::from_secs(3),
                tpap_info: None,
                tls_config: Arc::new(create_tls_config().unwrap()),
                https: false,
                session: Some(TpapSession {
                    session_id: "test".into(),
                    seq: AtomicU32::new(seq),
                    cipher: cipher.clone(),
                }),
            };
            let result = transport.send(r#"{"method":"get_device_info"}"#).await;
            let request = server.join().unwrap();
            assert_eq!(&request[..4], &seq.to_be_bytes());
            assert_eq!(
                cipher.decrypt(&request[4..], seq).unwrap(),
                br#"{"method":"get_device_info"}"#
            );
            assert_eq!(result.unwrap(), r#"{"error_code":0}"#);
        }
    }
}
