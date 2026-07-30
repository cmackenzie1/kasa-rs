//! SMART protocol adapter for newer TP-Link devices (e.g., KP125M, Tapo).
//!
//! Devices in the SMART family (discovery `device_type` like `SMART.KASAPLUG`)
//! use the same KLAP transport as newer IOT devices, but speak a different
//! command protocol: JSON-RPC style requests such as
//! `{"method":"get_device_info"}` with responses wrapped as
//! `{"error_code":0,"result":{...}}`.
//!
//! [`SmartTransport`] wraps an underlying [`Transport`] (typically
//! [`KlapTransport`](super::KlapTransport) with a v2 handshake) and:
//!
//! - Passes through commands that already use the SMART format
//!   (top-level `"method"` key), so raw SMART commands work directly.
//! - Translates the well-known legacy commands (`get_sysinfo`,
//!   `set_relay_state`, `emeter.get_realtime`, ...) into their SMART
//!   equivalents, and maps the responses back into the legacy JSON shapes
//!   that the rest of this crate (and its consumers) already understand.
//!
//! This means higher layers ([`TransportExt`](super::TransportExt), the CLI,
//! broadcast) work with SMART devices without modification.
//!
//! Legacy commands with no SMART equivalent (cloud bind/unbind, energy-meter
//! and runtime-stat resets, WiFi provisioning via `set_stainfo`) return a
//! [`DeviceError`](crate::error::Error::DeviceError) explaining that the
//! command is unsupported; the SMART firmware has no such methods (python-kasa
//! errors on these too).

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use serde_json::{Value, json};
use tracing::debug;

use crate::{
    error::Error,
    transport::{EncryptionType, Transport},
};

/// Transport adapter that speaks the SMART protocol over an inner transport.
///
/// See the [module documentation](self) for details.
pub struct SmartTransport {
    inner: Box<dyn Transport>,
    terminal_uuid: String,
}

impl SmartTransport {
    /// Wraps an existing transport with the SMART protocol adapter.
    pub fn new(inner: impl Transport + 'static) -> Self {
        let mut uuid = [0u8; 16];
        rand::rng().fill_bytes(&mut uuid);

        Self {
            inner: Box::new(inner),
            terminal_uuid: BASE64.encode(uuid),
        }
    }

    /// Builds a SMART request payload for a single method.
    fn build_request(&self, method: &str, params: Option<&Value>) -> String {
        let mut request = json!({
            "method": method,
            "request_time_milis": current_time_millis(),
            "terminal_uuid": self.terminal_uuid,
        });
        if let Some(params) = params {
            request["params"] = params.clone();
        }
        request.to_string()
    }

    /// Executes a single SMART method and returns the unwrapped `result`.
    async fn execute(&self, method: &str, params: Option<&Value>) -> Result<Value, Error> {
        let request = self.build_request(method, params);
        debug!(method, "sending SMART request");

        let response = self.inner.send(&request).await?;
        let response: Value = serde_json::from_str(&response)
            .map_err(|e| Error::ParseError(format!("invalid SMART response: {}", e)))?;

        let error_code = response
            .get("error_code")
            .and_then(|c| c.as_i64())
            .unwrap_or(0);
        if error_code != 0 {
            return Err(smart_error(method, error_code));
        }

        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Executes several SMART methods in a single `multipleRequest` round trip.
    ///
    /// Returns the per-method results in request order. Individual methods may
    /// fail without failing the whole call; failed methods yield `None`.
    async fn execute_multiple(&self, methods: &[&str]) -> Result<Vec<Option<Value>>, Error> {
        let requests: Vec<Value> = methods.iter().map(|m| json!({"method": m})).collect();
        let params = json!({"requests": requests});
        let result = self.execute("multipleRequest", Some(&params)).await?;

        let responses = result
            .get("responses")
            .and_then(|r| r.as_array())
            .ok_or_else(|| {
                Error::ParseError("multipleRequest response missing responses".into())
            })?;

        let results = methods
            .iter()
            .map(|method| {
                responses.iter().find_map(|r| {
                    let matches = r.get("method").and_then(|m| m.as_str()) == Some(*method);
                    let ok = r.get("error_code").and_then(|c| c.as_i64()) == Some(0);
                    if matches && ok {
                        r.get("result").cloned()
                    } else {
                        None
                    }
                })
            })
            .collect();

        Ok(results)
    }

    /// Handles the legacy `get_sysinfo` command by querying device and LED
    /// info in one batch and mapping the result to the legacy shape.
    async fn legacy_sysinfo(&self) -> Result<String, Error> {
        let results = self
            .execute_multiple(&["get_device_info", "get_led_info"])
            .await?;

        let device_info = results[0]
            .as_ref()
            .ok_or_else(|| Error::DeviceError("get_device_info failed".into()))?;

        Ok(map_sysinfo(device_info, results[1].as_ref()).to_string())
    }

    /// Handles the legacy `emeter.get_realtime` command.
    ///
    /// Prefers `get_emeter_data` (energy_monitoring v2, reports voltage and
    /// current) and falls back to `get_energy_usage` for devices that only
    /// report power.
    async fn legacy_energy(&self) -> Result<String, Error> {
        match self.execute("get_emeter_data", None).await {
            Ok(result) => Ok(map_emeter_data(&result).to_string()),
            Err(e) => {
                debug!(error = %e, "get_emeter_data failed, trying get_energy_usage");
                let result = self.execute("get_energy_usage", None).await?;
                Ok(map_energy_usage(&result).to_string())
            }
        }
    }

    /// Handles the legacy `set_relay_state` command via `set_device_info`.
    async fn legacy_set_relay(&self, params: &Value) -> Result<String, Error> {
        let on = params.get("state").and_then(|s| s.as_i64()).unwrap_or(0) == 1;
        self.execute("set_device_info", Some(&json!({"device_on": on})))
            .await?;
        Ok(json!({"system": {"set_relay_state": {"err_code": 0}}}).to_string())
    }

    /// Handles the legacy `set_led_off` command.
    ///
    /// SMART devices configure the LED through `set_led_info`, which expects
    /// the full LED configuration, so the current config is fetched first and
    /// only `led_rule` is changed (mirrors python-kasa).
    async fn legacy_set_led(&self, params: &Value) -> Result<String, Error> {
        let off = params.get("off").and_then(|o| o.as_i64()).unwrap_or(0) == 1;
        let rule = if off { "never" } else { "always" };

        let mut led_info = self.execute("get_led_info", None).await?;
        led_info["led_rule"] = json!(rule);
        self.execute("set_led_info", Some(&led_info)).await?;

        Ok(json!({"system": {"set_led_off": {"err_code": 0}}}).to_string())
    }

    /// Handles the legacy `netif.get_scaninfo` command.
    async fn legacy_wlanscan(&self) -> Result<String, Error> {
        let result = self.execute("get_wireless_scan_info", None).await?;
        Ok(map_scan_info(&result).to_string())
    }

    /// Executes a SMART method and wraps its raw result in a legacy
    /// `{module: {method: {..., "err_code": 0}}}` envelope.
    async fn legacy_wrapped(
        &self,
        smart_method: &str,
        params: Option<&Value>,
        module: &str,
        method: &str,
    ) -> Result<String, Error> {
        let result = self.execute(smart_method, params).await?;

        let mut inner = match result {
            Value::Object(map) => Value::Object(map),
            Value::Null => json!({}),
            other => json!({"result": other}),
        };
        inner["err_code"] = json!(0);

        Ok(json!({module: {method: inner}}).to_string())
    }

    /// Translates a legacy command to its SMART equivalent and executes it.
    async fn send_legacy(&self, command: &Value) -> Result<String, Error> {
        let (module, method, params) = parse_legacy_command(command)?;

        match (module.as_str(), method.as_str()) {
            ("system", "get_sysinfo") => self.legacy_sysinfo().await,
            ("system", "set_relay_state") => self.legacy_set_relay(&params).await,
            ("system", "set_led_off") => self.legacy_set_led(&params).await,
            ("system", "reboot") => {
                let delay = params.get("delay").and_then(|d| d.as_i64()).unwrap_or(1);
                self.legacy_wrapped(
                    "device_reboot",
                    Some(&json!({"delay": delay})),
                    "system",
                    "reboot",
                )
                .await
            }
            ("system", "reset") => {
                self.legacy_wrapped("device_reset", None, "system", "reset")
                    .await
            }
            ("emeter", "get_realtime") => self.legacy_energy().await,
            ("time", "get_time") => {
                self.legacy_wrapped("get_device_time", None, "time", "get_time")
                    .await
            }
            ("cnCloud", "get_info") => {
                let result = self.execute("get_connect_cloud_state", None).await?;
                Ok(map_cloud_state(&result).to_string())
            }
            ("anti_theft", "get_rules") => {
                self.legacy_wrapped("get_antitheft_rules", None, "anti_theft", "get_rules")
                    .await
            }
            ("count_down", "get_rules") => {
                self.legacy_wrapped("get_countdown_rules", None, "count_down", "get_rules")
                    .await
            }
            ("schedule", "get_rules") => {
                self.legacy_wrapped("get_schedule_rules", None, "schedule", "get_rules")
                    .await
            }
            ("netif", "get_scaninfo") => self.legacy_wlanscan().await,
            _ => Err(Error::DeviceError(format!(
                "command {}.{} is not supported for SMART protocol devices; \
                 send a raw SMART command instead (e.g. {{\"method\":\"get_device_info\"}})",
                module, method
            ))),
        }
    }
}

#[async_trait]
impl Transport for SmartTransport {
    async fn send(&self, command: &str) -> Result<String, Error> {
        let parsed: Value = serde_json::from_str(command)
            .map_err(|e| Error::ParseError(format!("invalid command JSON: {}", e)))?;

        // Commands already in SMART format pass through unchanged.
        if parsed.get("method").is_some() {
            return self.inner.send(command).await;
        }

        self.send_legacy(&parsed).await
    }

    fn encryption_type(&self) -> EncryptionType {
        self.inner.encryption_type()
    }

    fn host(&self) -> &str {
        self.inner.host()
    }

    fn port(&self) -> u16 {
        self.inner.port()
    }
}

impl std::fmt::Debug for SmartTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartTransport")
            .field("host", &self.inner.host())
            .field("port", &self.inner.port())
            .finish()
    }
}

/// Current UNIX time in milliseconds.
fn current_time_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Splits a legacy command like `{"system":{"set_relay_state":{"state":1}}}`
/// into (module, method, params).
fn parse_legacy_command(command: &Value) -> Result<(String, String, Value), Error> {
    let obj = command
        .as_object()
        .filter(|o| !o.is_empty())
        .ok_or_else(|| Error::ParseError("command must be a JSON object".into()))?;

    // Ignore a leading child context (power-strip addressing); SMART plugs
    // handled here have no children.
    let (module, body) = obj
        .iter()
        .find(|(k, _)| *k != "context")
        .ok_or_else(|| Error::ParseError("command has no module".into()))?;

    let body = body
        .as_object()
        .filter(|o| !o.is_empty())
        .ok_or_else(|| Error::ParseError(format!("module {} has no method", module)))?;

    let (method, params) = body.iter().next().unwrap();
    Ok((module.clone(), method.clone(), params.clone()))
}

/// Maps a SMART error code to a crate error with a readable description.
fn smart_error(method: &str, code: i64) -> Error {
    let description = match code {
        -1001 => "unspecified error",
        -1002 => "unknown method",
        -1003 => "JSON decoding failed",
        -1008 => "invalid parameters",
        -1301 => "device busy",
        -2101 => "component not supported",
        9999 => "session timeout",
        _ => "device error",
    };

    Error::DeviceError(format!(
        "SMART method {} failed: {} (error_code: {})",
        method, description, code
    ))
}

/// Decodes a base64-encoded device nickname, returning it verbatim on failure.
fn decode_nickname(nickname: &str) -> String {
    BASE64
        .decode(nickname)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| nickname.to_string())
}

/// Normalizes a MAC address like `DC-62-79-DB-9E-6E` to colon-separated form.
fn normalize_mac(mac: &str) -> String {
    mac.replace('-', ":")
}

/// Maps `get_device_info` (and optionally `get_led_info`) results into the
/// legacy `get_sysinfo` response shape.
fn map_sysinfo(device_info: &Value, led_info: Option<&Value>) -> Value {
    let get_str = |key: &str| device_info.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let get_i64 = |key: &str| device_info.get(key).and_then(|v| v.as_i64()).unwrap_or(0);

    let relay_state = device_info
        .get("device_on")
        .and_then(|v| v.as_bool())
        .unwrap_or(false) as u8;

    let led_off = led_info
        .map(|info| {
            let rule = info.get("led_rule").and_then(|r| r.as_str());
            let status = info.get("led_status").and_then(|s| s.as_bool());
            (rule == Some("never") || status == Some(false)) as u8
        })
        .unwrap_or(0);

    json!({
        "system": {
            "get_sysinfo": {
                "alias": decode_nickname(get_str("nickname")),
                "model": get_str("model"),
                "mac": normalize_mac(get_str("mac")),
                "deviceId": get_str("device_id"),
                "hwId": get_str("hw_id"),
                "oemId": get_str("oem_id"),
                "hw_ver": get_str("hw_ver"),
                "sw_ver": get_str("fw_ver"),
                "type": get_str("type"),
                "relay_state": relay_state,
                "led_off": led_off,
                "rssi": get_i64("rssi"),
                "on_time": get_i64("on_time"),
                "updating": 0,
                "err_code": 0
            }
        }
    })
}

/// Maps a `get_emeter_data` result into the legacy `emeter.get_realtime` shape.
///
/// The SMART field names conveniently match the legacy milli-unit names.
fn map_emeter_data(result: &Value) -> Value {
    let get = |key: &str| result.get(key).cloned().unwrap_or(Value::Null);

    json!({
        "emeter": {
            "get_realtime": {
                "voltage_mv": get("voltage_mv"),
                "current_ma": get("current_ma"),
                "power_mw": get("power_mw"),
                "total_wh": get("energy_wh"),
                "err_code": 0
            }
        }
    })
}

/// Maps a `get_energy_usage` result into the legacy `emeter.get_realtime`
/// shape. Only power is available; `current_power` is reported in milliwatts.
fn map_energy_usage(result: &Value) -> Value {
    let get = |key: &str| result.get(key).cloned().unwrap_or(Value::Null);

    json!({
        "emeter": {
            "get_realtime": {
                "power_mw": get("current_power"),
                "total_wh": get("month_energy"),
                "err_code": 0
            }
        }
    })
}

/// Maps a `get_connect_cloud_state` result into the legacy `cnCloud.get_info`
/// shape. A status of 0 means connected.
fn map_cloud_state(result: &Value) -> Value {
    let connected = result.get("status").and_then(|s| s.as_i64()) == Some(0);

    json!({
        "cnCloud": {
            "get_info": {
                "cld_connection": connected as u8,
                "err_code": 0
            }
        }
    })
}

/// Maps a `get_wireless_scan_info` result into the legacy
/// `netif.get_scaninfo` shape (base64 SSIDs decoded, key types numeric).
fn map_scan_info(result: &Value) -> Value {
    let ap_list: Vec<Value> = result
        .get("ap_list")
        .and_then(|l| l.as_array())
        .map(|aps| {
            aps.iter()
                .map(|ap| {
                    let ssid = ap.get("ssid").and_then(|s| s.as_str()).unwrap_or("");
                    let key_type = match ap.get("key_type").and_then(|k| k.as_str()) {
                        Some("none") | Some("open") => 0,
                        Some("wep") => 1,
                        Some(k) if k.starts_with("wpa2") => 3,
                        Some(k) if k.starts_with("wpa") => 2,
                        _ => 3,
                    };

                    json!({
                        "ssid": decode_nickname(ssid),
                        "key_type": key_type,
                        "rssi": ap.get("signal_level").cloned().unwrap_or(Value::Null)
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    json!({
        "netif": {
            "get_scaninfo": {
                "ap_list": ap_list,
                "err_code": 0
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock transport that returns canned SMART responses and records requests.
    struct MockTransport {
        requests: Mutex<Vec<String>>,
        responses: Mutex<Vec<String>>,
    }

    impl MockTransport {
        fn new(responses: Vec<&str>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into_iter().rev().map(String::from).collect()),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn send(&self, command: &str) -> Result<String, Error> {
            self.requests.lock().unwrap().push(command.to_string());
            self.responses
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| Error::DeviceError("no more mock responses".into()))
        }

        fn encryption_type(&self) -> EncryptionType {
            EncryptionType::Klap
        }

        fn host(&self) -> &str {
            "mock"
        }

        fn port(&self) -> u16 {
            80
        }
    }

    #[test]
    fn test_parse_legacy_command() {
        let cmd: Value =
            serde_json::from_str(r#"{"system":{"set_relay_state":{"state":1}}}"#).unwrap();
        let (module, method, params) = parse_legacy_command(&cmd).unwrap();
        assert_eq!(module, "system");
        assert_eq!(method, "set_relay_state");
        assert_eq!(params["state"], 1);
    }

    #[test]
    fn test_parse_legacy_command_skips_context() {
        let cmd: Value = serde_json::from_str(
            r#"{"context":{"child_ids":["abc"]},"emeter":{"get_realtime":{}}}"#,
        )
        .unwrap();
        let (module, method, _) = parse_legacy_command(&cmd).unwrap();
        assert_eq!(module, "emeter");
        assert_eq!(method, "get_realtime");
    }

    #[test]
    fn test_decode_nickname() {
        // "Lamp1" in base64
        assert_eq!(decode_nickname("TGFtcDE="), "Lamp1");
        // Invalid base64 falls back to the raw string
        assert_eq!(decode_nickname("not base64!"), "not base64!");
    }

    #[test]
    fn test_map_sysinfo_from_kp125m_fixture() {
        // Trimmed from python-kasa KP125M(US)_1.0_1.2.3.json fixture
        let device_info: Value = serde_json::from_str(
            r#"{
                "device_id": "0000000000000000000000000000000000000000",
                "device_on": true,
                "fw_ver": "1.2.3 Build 240624 Rel.154806",
                "hw_id": "00000000000000000000000000000000",
                "hw_ver": "1.0",
                "mac": "78-8C-B5-00-00-00",
                "model": "KP125M",
                "nickname": "TGFtcDE=",
                "oem_id": "00000000000000000000000000000000",
                "on_time": 936394,
                "rssi": -50,
                "type": "SMART.KASAPLUG"
            }"#,
        )
        .unwrap();
        let led_info: Value =
            serde_json::from_str(r#"{"led_rule": "always", "led_status": true}"#).unwrap();

        let mapped = map_sysinfo(&device_info, Some(&led_info));
        let sysinfo: crate::response::SysInfoResponse = serde_json::from_value(mapped).unwrap();
        let info = sysinfo.system.get_sysinfo;

        assert_eq!(info.alias, "Lamp1");
        assert_eq!(info.model, "KP125M");
        assert_eq!(info.mac_address(), "78:8C:B5:00:00:00");
        assert_eq!(info.sw_ver, "1.2.3 Build 240624 Rel.154806");
        assert!(info.is_on());
        assert!(!info.is_led_off());
        assert_eq!(info.rssi, -50);
        assert_eq!(info.on_time, 936394);
        assert!(!info.is_power_strip());
    }

    #[test]
    fn test_map_sysinfo_led_never() {
        let device_info = json!({"device_on": false});
        let led_info = json!({"led_rule": "never", "led_status": false});

        let mapped = map_sysinfo(&device_info, Some(&led_info));
        let info = &mapped["system"]["get_sysinfo"];
        assert_eq!(info["relay_state"], 0);
        assert_eq!(info["led_off"], 1);
    }

    #[test]
    fn test_map_emeter_data_from_kp125m_fixture() {
        let result: Value = serde_json::from_str(
            r#"{"current_ma": 33, "energy_wh": 971, "power_mw": 1003, "voltage_mv": 121215}"#,
        )
        .unwrap();

        let mapped = map_emeter_data(&result);
        let parsed: crate::response::EmeterResponse = serde_json::from_value(mapped).unwrap();
        let reading = parsed.emeter.get_realtime;

        assert!(reading.is_success());
        assert!((reading.voltage_v().unwrap() - 121.215).abs() < 0.001);
        assert!((reading.current_a().unwrap() - 0.033).abs() < 0.001);
        assert!((reading.power_w().unwrap() - 1.003).abs() < 0.001);
        assert_eq!(reading.total_wh(), Some(971.0));
    }

    #[test]
    fn test_map_energy_usage_fallback() {
        let result: Value = serde_json::from_str(
            r#"{"current_power": 1003, "today_energy": 20, "month_energy": 971}"#,
        )
        .unwrap();

        let mapped = map_energy_usage(&result);
        let parsed: crate::response::EmeterResponse = serde_json::from_value(mapped).unwrap();
        let reading = parsed.emeter.get_realtime;

        assert!((reading.power_w().unwrap() - 1.003).abs() < 0.001);
        assert_eq!(reading.total_wh(), Some(971.0));
    }

    #[test]
    fn test_map_cloud_state() {
        let connected = map_cloud_state(&json!({"status": 0}));
        assert_eq!(connected["cnCloud"]["get_info"]["cld_connection"], 1);

        let disconnected = map_cloud_state(&json!({"status": 1}));
        assert_eq!(disconnected["cnCloud"]["get_info"]["cld_connection"], 0);
    }

    #[test]
    fn test_map_scan_info() {
        let result = json!({
            "ap_list": [
                {"ssid": "TGFtcDE=", "key_type": "wpa2_psk", "signal_level": 3},
                {"ssid": "b3Blbg==", "key_type": "none", "signal_level": 1}
            ],
            "wep_supported": false
        });

        let mapped = map_scan_info(&result);
        let aps = mapped["netif"]["get_scaninfo"]["ap_list"]
            .as_array()
            .unwrap();
        assert_eq!(aps[0]["ssid"], "Lamp1");
        assert_eq!(aps[0]["key_type"], 3);
        assert_eq!(aps[1]["ssid"], "open");
        assert_eq!(aps[1]["key_type"], 0);
    }

    #[tokio::test]
    async fn test_send_raw_smart_passthrough() {
        let mock = MockTransport::new(vec![r#"{"error_code":0,"result":{"device_on":true}}"#]);
        let transport = SmartTransport::new(mock);

        let response = transport
            .send(r#"{"method":"get_device_info"}"#)
            .await
            .unwrap();
        assert!(response.contains("device_on"));
    }

    #[tokio::test]
    async fn test_send_legacy_relay_on_translates() {
        let mock = MockTransport::new(vec![r#"{"error_code":0,"result":{}}"#]);
        let transport = SmartTransport::new(mock);

        let response = transport
            .send(r#"{"system":{"set_relay_state":{"state":1}}}"#)
            .await
            .unwrap();

        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["system"]["set_relay_state"]["err_code"], 0);
    }

    #[tokio::test]
    async fn test_send_legacy_sysinfo_uses_multiple_request() {
        let mock = MockTransport::new(vec![
            r#"{"error_code":0,"result":{"responses":[
                {"method":"get_device_info","error_code":0,"result":{"nickname":"TGFtcDE=","device_on":true,"model":"KP125M","mac":"78-8C-B5-00-00-00"}},
                {"method":"get_led_info","error_code":0,"result":{"led_rule":"always","led_status":true}}
            ]}}"#,
        ]);
        let transport = SmartTransport::new(mock);

        let response = transport
            .send(r#"{"system":{"get_sysinfo":{}}}"#)
            .await
            .unwrap();

        let parsed: crate::response::SysInfoResponse = serde_json::from_str(&response).unwrap();
        let info = parsed.system.get_sysinfo;
        assert_eq!(info.alias, "Lamp1");
        assert_eq!(info.model, "KP125M");
        assert!(info.is_on());
    }

    #[tokio::test]
    async fn test_send_legacy_sysinfo_tolerates_led_failure() {
        let mock = MockTransport::new(vec![
            r#"{"error_code":0,"result":{"responses":[
                {"method":"get_device_info","error_code":0,"result":{"nickname":"TGFtcDE=","device_on":false,"model":"KP125M"}},
                {"method":"get_led_info","error_code":-1002}
            ]}}"#,
        ]);
        let transport = SmartTransport::new(mock);

        let response = transport
            .send(r#"{"system":{"get_sysinfo":{}}}"#)
            .await
            .unwrap();

        let parsed: crate::response::SysInfoResponse = serde_json::from_str(&response).unwrap();
        assert!(!parsed.system.get_sysinfo.is_on());
        assert!(!parsed.system.get_sysinfo.is_led_off());
    }

    #[tokio::test]
    async fn test_send_legacy_energy_falls_back_to_energy_usage() {
        let mock = MockTransport::new(vec![
            r#"{"error_code":-1002}"#,
            r#"{"error_code":0,"result":{"current_power":1003,"month_energy":971}}"#,
        ]);
        let transport = SmartTransport::new(mock);

        let response = transport
            .send(r#"{"emeter":{"get_realtime":{}}}"#)
            .await
            .unwrap();

        let parsed: crate::response::EmeterResponse = serde_json::from_str(&response).unwrap();
        assert!((parsed.emeter.get_realtime.power_w().unwrap() - 1.003).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_send_legacy_set_led_fetches_config_first() {
        let mock = MockTransport::new(vec![
            r#"{"error_code":0,"result":{"led_rule":"always","led_status":true,"night_mode":{}}}"#,
            r#"{"error_code":0,"result":{}}"#,
        ]);
        let transport = SmartTransport::new(mock);

        let response = transport
            .send(r#"{"system":{"set_led_off":{"off":1}}}"#)
            .await
            .unwrap();

        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["system"]["set_led_off"]["err_code"], 0);
    }

    #[tokio::test]
    async fn test_send_unsupported_legacy_command_errors() {
        let mock = MockTransport::new(vec![]);
        let transport = SmartTransport::new(mock);

        let err = transport
            .send(r#"{"netif":{"set_stainfo":{"ssid":"x","password":"y","key_type":3}}}"#)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn test_smart_error_code_is_reported() {
        let mock = MockTransport::new(vec![r#"{"error_code":9999}"#]);
        let transport = SmartTransport::new(mock);

        let err = transport
            .send(r#"{"system":{"set_relay_state":{"state":1}}}"#)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("session timeout"));
        assert!(err.to_string().contains("9999"));
    }
}
