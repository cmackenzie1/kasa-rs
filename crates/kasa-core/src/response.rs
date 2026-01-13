//! Typed response structures for Kasa device JSON responses.
//!
//! This module provides strongly-typed structures for parsing device responses,
//! eliminating the need for manual JSON field extraction.
//!
//! # Example
//!
//! ```no_run
//! use kasa_core::response::SysInfoResponse;
//!
//! let json = r#"{"system":{"get_sysinfo":{"alias":"Living Room","model":"HS103"}}}"#;
//! let response: SysInfoResponse = serde_json::from_str(json).unwrap();
//! println!("Device: {}", response.system.get_sysinfo.alias);
//! ```

use serde::{Deserialize, Deserializer, Serialize};

/// Response wrapper for system info queries.
///
/// This is the top-level response from `{"system":{"get_sysinfo":{}}}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SysInfoResponse {
    /// The system wrapper containing sysinfo.
    pub system: SystemWrapper,
}

/// Wrapper for the get_sysinfo response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemWrapper {
    /// The actual system information.
    pub get_sysinfo: SysInfo,
}

/// Device system information.
///
/// Contains all device metadata and current state.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SysInfo {
    /// Device alias/name set by the user.
    #[serde(default)]
    pub alias: String,

    /// Device model (e.g., "HS103", "KP115", "HS300(US)").
    #[serde(default)]
    pub model: String,

    /// MAC address of the device.
    /// Some devices use `mac`, others use `mic_mac`.
    #[serde(default, deserialize_with = "deserialize_mac")]
    pub mac: String,

    /// Unique device ID.
    #[serde(default, rename = "deviceId")]
    pub device_id: String,

    /// Hardware ID.
    #[serde(default, rename = "hwId")]
    pub hw_id: String,

    /// Hardware version.
    #[serde(default)]
    pub hw_ver: String,

    /// Software/firmware version.
    #[serde(default)]
    pub sw_ver: String,

    /// Current relay state (1 = on, 0 = off).
    /// For power strips, this is the overall state; check `children` for individual plugs.
    #[serde(default)]
    pub relay_state: u8,

    /// Whether the LED indicator is off (1 = off, 0 = on).
    #[serde(default)]
    pub led_off: u8,

    /// WiFi signal strength in dBm (negative, closer to 0 = stronger).
    #[serde(default)]
    pub rssi: i32,

    /// Seconds since the relay was turned on (0 if off).
    #[serde(default)]
    pub on_time: u64,

    /// Whether a firmware update is in progress.
    #[serde(default)]
    pub updating: u8,

    /// Child devices (plugs) for power strips like HS300.
    #[serde(default)]
    pub children: Vec<ChildPlug>,

    /// OEM ID for device identification.
    #[serde(default, rename = "oemId")]
    pub oem_id: String,

    /// Device type identifier.
    #[serde(default, rename = "type")]
    pub device_type: String,

    /// Alternative MAC address field used by some devices.
    #[serde(default)]
    pub mic_mac: String,

    /// Feature flags for the device.
    #[serde(default)]
    pub feature: String,

    /// Latitude for device location (if set).
    #[serde(default)]
    pub latitude_i: i32,

    /// Longitude for device location (if set).
    #[serde(default)]
    pub longitude_i: i32,

    /// Error code from the response (0 = success).
    #[serde(default)]
    pub err_code: i32,
}

/// Custom deserializer that handles both `mac` and `mic_mac` fields.
fn deserialize_mac<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    // Just deserialize normally - the mic_mac fallback is handled in SysInfo
    String::deserialize(deserializer)
}

impl SysInfo {
    /// Returns the MAC address, preferring `mac` over `mic_mac`.
    pub fn mac_address(&self) -> &str {
        if self.mac.is_empty() {
            &self.mic_mac
        } else {
            &self.mac
        }
    }

    /// Returns true if the relay is on.
    pub fn is_on(&self) -> bool {
        self.relay_state == 1
    }

    /// Returns true if the LED is off.
    pub fn is_led_off(&self) -> bool {
        self.led_off == 1
    }

    /// Returns true if a firmware update is in progress.
    pub fn is_updating(&self) -> bool {
        self.updating == 1
    }

    /// Returns true if this is a power strip with multiple plugs.
    pub fn is_power_strip(&self) -> bool {
        !self.children.is_empty()
    }
}

/// Information about a child plug on a power strip.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChildPlug {
    /// Unique ID for this plug (used in child context commands).
    #[serde(default)]
    pub id: String,

    /// User-assigned alias for this plug.
    #[serde(default)]
    pub alias: String,

    /// Current relay state (1 = on, 0 = off).
    #[serde(default)]
    pub state: u8,

    /// Seconds since this plug was turned on.
    #[serde(default)]
    pub on_time: u64,
}

impl ChildPlug {
    /// Returns true if this plug is on.
    pub fn is_on(&self) -> bool {
        self.state == 1
    }
}

/// Response wrapper for energy meter queries.
///
/// This is the top-level response from `{"emeter":{"get_realtime":{}}}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmeterResponse {
    /// The emeter wrapper containing realtime data.
    pub emeter: EmeterWrapper,
}

/// Wrapper for the get_realtime response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmeterWrapper {
    /// The actual energy reading.
    pub get_realtime: EnergyReading,
}

/// Energy meter reading with normalized values.
///
/// Different device models report values in different units:
/// - Some use `voltage_mv`, `current_ma`, `power_mw` (millivolts/milliamps/milliwatts)
/// - Others use `voltage`, `current`, `power` (volts/amps/watts)
///
/// This struct normalizes all values to standard units (V, A, W, Wh).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EnergyReading {
    /// Voltage in millivolts (some devices).
    #[serde(default)]
    pub voltage_mv: Option<f64>,

    /// Voltage in volts (some devices).
    #[serde(default)]
    pub voltage: Option<f64>,

    /// Current in milliamps (some devices).
    #[serde(default)]
    pub current_ma: Option<f64>,

    /// Current in amps (some devices).
    #[serde(default)]
    pub current: Option<f64>,

    /// Power in milliwatts (some devices).
    #[serde(default)]
    pub power_mw: Option<f64>,

    /// Power in watts (some devices).
    #[serde(default)]
    pub power: Option<f64>,

    /// Total energy in watt-hours (some devices).
    #[serde(default)]
    pub total_wh: Option<f64>,

    /// Total energy in watt-hours (some devices use this field name).
    #[serde(default)]
    pub total: Option<f64>,

    /// Error code from the response (0 = success).
    #[serde(default)]
    pub err_code: i32,
}

impl EnergyReading {
    /// Returns the voltage in volts, normalizing from millivolts if needed.
    pub fn voltage_v(&self) -> Option<f64> {
        self.voltage_mv.map(|mv| mv / 1000.0).or(self.voltage)
    }

    /// Returns the current in amps, normalizing from milliamps if needed.
    pub fn current_a(&self) -> Option<f64> {
        self.current_ma.map(|ma| ma / 1000.0).or(self.current)
    }

    /// Returns the power in watts, normalizing from milliwatts if needed.
    pub fn power_w(&self) -> Option<f64> {
        self.power_mw.map(|mw| mw / 1000.0).or(self.power)
    }

    /// Returns the total energy in watt-hours.
    pub fn total_wh(&self) -> Option<f64> {
        self.total_wh.or(self.total)
    }

    /// Returns true if the response indicates success.
    pub fn is_success(&self) -> bool {
        self.err_code == 0
    }
}

/// Response wrapper for cloud connection info.
///
/// This is the top-level response from `{"cnCloud":{"get_info":{}}}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudInfoResponse {
    /// The cloud wrapper containing connection info.
    #[serde(rename = "cnCloud")]
    pub cn_cloud: CloudWrapper,
}

/// Wrapper for the get_info response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudWrapper {
    /// The actual cloud connection info.
    pub get_info: CloudInfo,
}

/// Cloud connection status information.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CloudInfo {
    /// Whether the device is connected to the cloud (1 = connected).
    #[serde(default)]
    pub cld_connection: u8,

    /// Cloud username (email) if bound.
    #[serde(default)]
    pub username: String,

    /// Cloud server URL.
    #[serde(default)]
    pub server: String,

    /// Whether the device is bound to a cloud account.
    #[serde(default)]
    pub binded: u8,

    /// Error code from the response (0 = success).
    #[serde(default)]
    pub err_code: i32,
}

impl CloudInfo {
    /// Returns true if connected to the cloud.
    pub fn is_connected(&self) -> bool {
        self.cld_connection == 1
    }

    /// Returns true if bound to a cloud account.
    pub fn is_bound(&self) -> bool {
        self.binded == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sysinfo_basic() {
        let json = r#"{
            "system": {
                "get_sysinfo": {
                    "alias": "Living Room",
                    "model": "HS103(US)",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "deviceId": "abc123",
                    "hw_ver": "1.0",
                    "sw_ver": "1.2.3",
                    "relay_state": 1,
                    "led_off": 0,
                    "rssi": -50,
                    "on_time": 3600,
                    "updating": 0,
                    "err_code": 0
                }
            }
        }"#;

        let response: SysInfoResponse = serde_json::from_str(json).unwrap();
        let info = &response.system.get_sysinfo;

        assert_eq!(info.alias, "Living Room");
        assert_eq!(info.model, "HS103(US)");
        assert!(info.is_on());
        assert!(!info.is_led_off());
        assert_eq!(info.rssi, -50);
        assert_eq!(info.on_time, 3600);
    }

    #[test]
    fn test_parse_sysinfo_with_children() {
        let json = r#"{
            "system": {
                "get_sysinfo": {
                    "alias": "Power Strip",
                    "model": "HS300(US)",
                    "children": [
                        {"id": "plug0", "alias": "Lamp", "state": 1, "on_time": 100},
                        {"id": "plug1", "alias": "Fan", "state": 0, "on_time": 0}
                    ]
                }
            }
        }"#;

        let response: SysInfoResponse = serde_json::from_str(json).unwrap();
        let info = &response.system.get_sysinfo;

        assert!(info.is_power_strip());
        assert_eq!(info.children.len(), 2);
        assert!(info.children[0].is_on());
        assert!(!info.children[1].is_on());
        assert_eq!(info.children[0].alias, "Lamp");
    }

    #[test]
    fn test_parse_sysinfo_mic_mac() {
        let json = r#"{
            "system": {
                "get_sysinfo": {
                    "alias": "Test",
                    "model": "KP115",
                    "mac": "",
                    "mic_mac": "11:22:33:44:55:66"
                }
            }
        }"#;

        let response: SysInfoResponse = serde_json::from_str(json).unwrap();
        let info = &response.system.get_sysinfo;

        assert_eq!(info.mac_address(), "11:22:33:44:55:66");
    }

    #[test]
    fn test_parse_energy_milliwatts() {
        let json = r#"{
            "emeter": {
                "get_realtime": {
                    "voltage_mv": 121000,
                    "current_ma": 500,
                    "power_mw": 60000,
                    "total_wh": 1234,
                    "err_code": 0
                }
            }
        }"#;

        let response: EmeterResponse = serde_json::from_str(json).unwrap();
        let reading = &response.emeter.get_realtime;

        assert!((reading.voltage_v().unwrap() - 121.0).abs() < 0.001);
        assert!((reading.current_a().unwrap() - 0.5).abs() < 0.001);
        assert!((reading.power_w().unwrap() - 60.0).abs() < 0.001);
        assert_eq!(reading.total_wh(), Some(1234.0));
        assert!(reading.is_success());
    }

    #[test]
    fn test_parse_energy_standard_units() {
        let json = r#"{
            "emeter": {
                "get_realtime": {
                    "voltage": 121.5,
                    "current": 0.5,
                    "power": 60.75,
                    "total": 1234.5,
                    "err_code": 0
                }
            }
        }"#;

        let response: EmeterResponse = serde_json::from_str(json).unwrap();
        let reading = &response.emeter.get_realtime;

        assert_eq!(reading.voltage_v(), Some(121.5));
        assert_eq!(reading.current_a(), Some(0.5));
        assert_eq!(reading.power_w(), Some(60.75));
        assert_eq!(reading.total_wh(), Some(1234.5));
    }

    #[test]
    fn test_parse_cloud_info() {
        let json = r#"{
            "cnCloud": {
                "get_info": {
                    "cld_connection": 1,
                    "username": "user@example.com",
                    "server": "devs.tplinkcloud.com",
                    "binded": 1,
                    "err_code": 0
                }
            }
        }"#;

        let response: CloudInfoResponse = serde_json::from_str(json).unwrap();
        let info = &response.cn_cloud.get_info;

        assert!(info.is_connected());
        assert!(info.is_bound());
        assert_eq!(info.username, "user@example.com");
    }
}
