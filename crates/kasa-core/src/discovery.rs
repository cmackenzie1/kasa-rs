//! Discovery protocols for TP-Link Kasa devices.
//!
//! Supports two discovery methods:
//! - **Port 9999 (Legacy)**: XOR-encrypted UDP broadcast for older devices
//! - **Port 20002 (TDP)**: RSA-based discovery for newer KLAP/SMART devices
//!
//! # Protocol Overview
//!
//! ## Legacy Discovery (Port 9999)
//!
//! Simple XOR encryption of `{"system":{"get_sysinfo":{}}}` query.
//!
//! ## TDP Discovery (Port 20002)
//!
//! TP-Link Discovery Protocol uses:
//! 1. RSA key pair generation (2048-bit)
//! 2. Custom TDP packet header with RSA public key
//! 3. Device responds with JSON containing encryption scheme info

use std::net::IpAddr;
use std::time::Duration;

use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey, rand_core::OsRng};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::debug;

use crate::transport::EncryptionType;

/// Port for legacy XOR discovery.
pub const LEGACY_DISCOVERY_PORT: u16 = 9999;

/// Port for TDP (newer KLAP/SMART) discovery.
pub const TDP_DISCOVERY_PORT: u16 = 20002;

/// Broadcast address for discovery.
pub const BROADCAST_ADDR: &str = "255.255.255.255";

/// A device discovered on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    /// IP address of the device.
    pub ip: IpAddr,
    /// Port for communication.
    pub port: u16,
    /// Device alias/name.
    pub alias: String,
    /// Device model (e.g., "HS300(US)").
    pub model: String,
    /// MAC address.
    pub mac: String,
    /// Device ID.
    pub device_id: String,
    /// Hardware version.
    pub hw_ver: String,
    /// Software/firmware version.
    pub sw_ver: String,
    /// Current relay state.
    pub relay_state: bool,
    /// LED off state.
    pub led_off: bool,
    /// WiFi signal strength.
    pub rssi: i32,
    /// Time device has been on.
    pub on_time: u64,
    /// Whether device is updating.
    pub updating: bool,
    /// Encryption type used by the device.
    pub encryption_type: EncryptionType,
    /// HTTP port for KLAP devices.
    pub http_port: Option<u16>,
    /// Whether device uses new KLAP (v2).
    pub new_klap: Option<bool>,
    /// Login version for KLAP.
    pub login_version: Option<u32>,
}

/// Discovery result from TDP (port 20002) response.
#[derive(Debug, Clone, Deserialize)]
pub struct TdpDiscoveryResult {
    pub error_code: i32,
    pub result: TdpDeviceInfo,
}

/// Device info from TDP discovery.
#[derive(Debug, Clone, Deserialize)]
pub struct TdpDeviceInfo {
    pub device_id: String,
    pub device_type: String,
    pub device_model: String,
    pub ip: String,
    pub mac: String,
    pub hw_ver: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub factory_default: bool,
    pub mgt_encrypt_schm: Option<TdpEncryptionScheme>,
}

/// Encryption scheme info from TDP discovery.
#[derive(Debug, Clone, Deserialize)]
pub struct TdpEncryptionScheme {
    pub encrypt_type: String,
    #[serde(default)]
    pub is_support_https: bool,
    #[serde(default)]
    pub http_port: u16,
    #[serde(default)]
    pub lv: u32,
    #[serde(default)]
    pub new_klap: u8,
}

/// TDP packet header structure.
///
/// Format (16 bytes):
/// - version: u8 (2)
/// - msg_type: u8 (0)
/// - op_code: u16 BE (1 = probe)
/// - msg_size: u16 BE (payload length)
/// - flags: u8 (17)
/// - padding: u8 (0)
/// - device_serial: u32 BE (random)
/// - crc32: u32 BE (computed over entire packet)
#[derive(Debug)]
struct TdpHeader {
    version: u8,
    msg_type: u8,
    op_code: u16,
    msg_size: u16,
    flags: u8,
    padding: u8,
    device_serial: u32,
    crc32: u32,
}

impl TdpHeader {
    fn new(payload_len: u16, serial: u32) -> Self {
        Self {
            version: 2,
            msg_type: 0,
            op_code: 1, // probe
            msg_size: payload_len,
            flags: 17,
            padding: 0,
            device_serial: serial,
            crc32: 0x5A6B7C8D, // Initial CRC, will be updated
        }
    }

    fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0] = self.version;
        bytes[1] = self.msg_type;
        bytes[2..4].copy_from_slice(&self.op_code.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.msg_size.to_be_bytes());
        bytes[6] = self.flags;
        bytes[7] = self.padding;
        bytes[8..12].copy_from_slice(&self.device_serial.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.crc32.to_be_bytes());
        bytes
    }
}

/// Generates a TDP discovery query packet.
///
/// The packet contains:
/// 1. TDP header (16 bytes)
/// 2. JSON payload with RSA public key
///
/// Returns the packet bytes and the private key for decrypting responses.
pub fn generate_tdp_discovery_query() -> std::io::Result<(Vec<u8>, RsaPrivateKey)> {
    // Generate RSA key pair (using OsRng from rsa's rand_core to avoid version conflicts)
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| std::io::Error::other(format!("RSA key generation failed: {}", e)))?;
    let public_key = RsaPublicKey::from(&private_key);

    // Get PEM-encoded public key
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| std::io::Error::other(format!("PEM encoding failed: {}", e)))?;

    // Create JSON payload
    let payload = serde_json::json!({
        "params": {
            "rsa_key": public_pem
        }
    });
    let payload_bytes = serde_json::to_vec(&payload)?;

    // Generate random serial
    let serial: u32 = rand::random();

    // Create header
    let header = TdpHeader::new(payload_bytes.len() as u16, serial);
    let header_bytes = header.to_bytes();

    // Combine header and payload
    let mut packet = Vec::with_capacity(16 + payload_bytes.len());
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(&payload_bytes);

    // Calculate CRC32 over entire packet and update bytes 12-16
    let crc = crc32fast::hash(&packet);
    packet[12..16].copy_from_slice(&crc.to_be_bytes());

    Ok((packet, private_key))
}

/// Parse a TDP discovery response.
///
/// The response format is:
/// - 16 bytes header
/// - JSON payload
pub fn parse_tdp_response(data: &[u8]) -> std::io::Result<TdpDiscoveryResult> {
    if data.len() < 16 {
        return Err(std::io::Error::other("TDP response too short"));
    }

    // Skip header, parse JSON
    let json_data = &data[16..];
    serde_json::from_slice(json_data)
        .map_err(|e| std::io::Error::other(format!("Failed to parse TDP response: {}", e)))
}

/// Discovers devices using both legacy (9999) and TDP (20002) protocols.
///
/// # Arguments
///
/// * `discovery_timeout` - How long to wait for responses
///
/// # Returns
///
/// A vector of discovered devices from both protocols.
pub async fn discover_all(discovery_timeout: Duration) -> std::io::Result<Vec<DiscoveredDevice>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    // Send legacy discovery (port 9999)
    let legacy_query = crate::crypto::xor::encrypt_udp(crate::commands::INFO);
    let legacy_addr = format!("{}:{}", BROADCAST_ADDR, LEGACY_DISCOVERY_PORT);
    debug!("Sending legacy discovery to {}", legacy_addr);
    socket.send_to(&legacy_query, &legacy_addr).await?;

    // Send TDP discovery (port 20002)
    let (tdp_query, _private_key) = generate_tdp_discovery_query()?;
    let tdp_addr = format!("{}:{}", BROADCAST_ADDR, TDP_DISCOVERY_PORT);
    debug!("Sending TDP discovery to {}", tdp_addr);
    socket.send_to(&tdp_query, &tdp_addr).await?;

    let mut devices = Vec::new();
    let mut seen_ips = std::collections::HashSet::new();
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
                let ip = addr.ip();
                let port = addr.port();

                // Skip duplicates
                if seen_ips.contains(&ip) {
                    continue;
                }

                debug!("Received {} bytes from {}:{}", n, ip, port);

                if port == LEGACY_DISCOVERY_PORT {
                    // Legacy XOR response
                    if let Some(device) = parse_legacy_response(&buf[..n], ip) {
                        seen_ips.insert(ip);
                        devices.push(device);
                    }
                } else if port == TDP_DISCOVERY_PORT {
                    // TDP response
                    if let Some(device) = parse_tdp_discovery(&buf[..n], ip) {
                        seen_ips.insert(ip);
                        devices.push(device);
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("Error receiving discovery response: {}", e);
                break;
            }
            Err(_) => {
                // Timeout on this recv, continue to check deadline
                continue;
            }
        }
    }

    debug!("Discovered {} devices", devices.len());
    Ok(devices)
}

/// Parse a legacy (port 9999) discovery response.
fn parse_legacy_response(data: &[u8], ip: IpAddr) -> Option<DiscoveredDevice> {
    let decrypted = crate::crypto::xor::decrypt(data);
    debug!("Legacy response from {}: {}", ip, decrypted);

    #[derive(Deserialize)]
    struct SysInfoResponse {
        system: SystemInfo,
    }

    #[derive(Deserialize)]
    struct SystemInfo {
        get_sysinfo: SysInfo,
    }

    #[derive(Deserialize)]
    struct SysInfo {
        #[serde(default)]
        alias: String,
        #[serde(default)]
        model: String,
        #[serde(default)]
        mac: String,
        #[serde(default)]
        mic_mac: String,
        #[serde(default, rename = "deviceId")]
        device_id: String,
        #[serde(default)]
        hw_ver: String,
        #[serde(default)]
        sw_ver: String,
        #[serde(default)]
        relay_state: u8,
        #[serde(default)]
        led_off: u8,
        #[serde(default)]
        rssi: i32,
        #[serde(default)]
        on_time: u64,
        #[serde(default)]
        updating: u8,
    }

    let response: SysInfoResponse = serde_json::from_str(&decrypted).ok()?;
    let info = response.system.get_sysinfo;

    let mac = if info.mac.is_empty() {
        info.mic_mac
    } else {
        info.mac
    };

    Some(DiscoveredDevice {
        ip,
        port: crate::DEFAULT_PORT,
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
        encryption_type: EncryptionType::Xor,
        http_port: None,
        new_klap: None,
        login_version: None,
    })
}

/// Parse a TDP (port 20002) discovery response.
fn parse_tdp_discovery(data: &[u8], ip: IpAddr) -> Option<DiscoveredDevice> {
    let result = parse_tdp_response(data).ok()?;

    if result.error_code != 0 {
        debug!("TDP response error_code: {}", result.error_code);
        return None;
    }

    let info = result.result;
    let scheme = info.mgt_encrypt_schm.as_ref();

    let encryption_type = match scheme.map(|s| s.encrypt_type.as_str()) {
        Some("KLAP") => EncryptionType::Klap,
        Some("AES") => EncryptionType::Aes,
        _ => EncryptionType::Xor,
    };

    let http_port = scheme.map(|s| s.http_port).filter(|&p| p > 0);
    let new_klap = scheme.map(|s| s.new_klap == 1);
    let login_version = scheme.map(|s| s.lv).filter(|&v| v > 0);

    debug!(
        "TDP device {} model={} type={} encrypt={:?} new_klap={:?}",
        ip, info.device_model, info.device_type, encryption_type, new_klap
    );

    Some(DiscoveredDevice {
        ip,
        port: http_port.unwrap_or(80),
        alias: String::new(), // TDP doesn't include alias
        model: info.device_model,
        mac: info.mac,
        device_id: info.device_id,
        hw_ver: info.hw_ver,
        sw_ver: String::new(), // TDP doesn't include sw_ver
        relay_state: false,    // Unknown from TDP
        led_off: false,        // Unknown from TDP
        rssi: 0,               // Unknown from TDP
        on_time: 0,            // Unknown from TDP
        updating: false,       // Unknown from TDP
        encryption_type,
        http_port,
        new_klap,
        login_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdp_header_serialization() {
        let header = TdpHeader::new(100, 0x12345678);
        let bytes = header.to_bytes();

        assert_eq!(bytes[0], 2); // version
        assert_eq!(bytes[1], 0); // msg_type
        assert_eq!(&bytes[2..4], &[0, 1]); // op_code BE
        assert_eq!(&bytes[4..6], &[0, 100]); // msg_size BE
        assert_eq!(bytes[6], 17); // flags
        assert_eq!(bytes[7], 0); // padding
        assert_eq!(&bytes[8..12], &[0x12, 0x34, 0x56, 0x78]); // serial BE
    }

    #[test]
    fn test_generate_tdp_query() {
        let (packet, _key) = generate_tdp_discovery_query().unwrap();

        // Check header
        assert_eq!(packet[0], 2); // version
        assert_eq!(packet[1], 0); // msg_type
        assert_eq!(packet[2], 0); // op_code high
        assert_eq!(packet[3], 1); // op_code low (probe)
        assert_eq!(packet[6], 17); // flags

        // Check payload contains rsa_key
        let payload_str = String::from_utf8_lossy(&packet[16..]);
        assert!(payload_str.contains("rsa_key"));
        assert!(payload_str.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_parse_tdp_response() {
        // Simulated response with header + JSON
        let json = r#"{"error_code":0,"result":{"device_id":"abc123","device_type":"IOT.SMARTPLUGSWITCH","device_model":"HS300(US)","ip":"192.168.1.100","mac":"AA:BB:CC:DD:EE:FF","hw_ver":"2.0","mgt_encrypt_schm":{"encrypt_type":"KLAP","http_port":80,"lv":2,"new_klap":1}}}"#;
        let mut packet = vec![0u8; 16]; // Dummy header
        packet.extend_from_slice(json.as_bytes());

        let result = parse_tdp_response(&packet).unwrap();
        assert_eq!(result.error_code, 0);
        assert_eq!(result.result.device_model, "HS300(US)");
        assert_eq!(
            result
                .result
                .mgt_encrypt_schm
                .as_ref()
                .unwrap()
                .encrypt_type,
            "KLAP"
        );
        assert_eq!(result.result.mgt_encrypt_schm.as_ref().unwrap().new_klap, 1);
    }
}
