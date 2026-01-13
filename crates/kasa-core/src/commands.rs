//! Predefined JSON command strings for common TP-Link Kasa device operations.
//!
//! These constants can be passed directly to transport methods to perform
//! common operations without constructing JSON manually.
//!
//! # Example
//!
//! ```no_run
//! use kasa_core::{commands, send_command, DEFAULT_PORT, DEFAULT_TIMEOUT};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     // Turn on a smart plug
//!     send_command("192.168.1.100", DEFAULT_PORT, DEFAULT_TIMEOUT, commands::RELAY_ON).await?;
//!     Ok(())
//! }
//! ```

/// Get anti-theft rules configuration.
pub const ANTITHEFT: &str = r#"{"anti_theft":{"get_rules":{}}}"#;

/// Get cloud connection information.
pub const CLOUDINFO: &str = r#"{"cnCloud":{"get_info":{}}}"#;

/// Unbind device from TP-Link cloud account.
///
/// This removes the device from cloud control but it continues to work locally.
pub const CLOUD_UNBIND: &str = r#"{"cnCloud":{"unbind":{}}}"#;

/// Bind device to TP-Link cloud account.
///
/// Requires username and password - use [`cloud_bind`] to generate
/// the command with credentials.
pub const CLOUD_BIND_TEMPLATE: &str =
    r#"{"cnCloud":{"bind":{"username":"{{USERNAME}}","password":"{{PASSWORD}}"}}}"#;

/// Get countdown timer rules.
pub const COUNTDOWN: &str = r#"{"count_down":{"get_rules":{}}}"#;

/// Erase all energy meter statistics.
///
/// **Warning:** This permanently deletes energy usage history.
pub const ENERGY_RESET: &str = r#"{"emeter":{"erase_emeter_stat":{}}}"#;

/// Get real-time energy meter readings.
///
/// Returns current voltage, current, power, and total energy consumption.
/// Only available on devices with energy monitoring (e.g., HS110, KP115).
pub const ENERGY: &str = r#"{"emeter":{"get_realtime":{}}}"#;

/// Get system information.
///
/// Returns device model, alias, MAC address, firmware version, relay state, and more.
pub const INFO: &str = r#"{"system":{"get_sysinfo":{}}}"#;

/// Turn off the LED indicator light.
pub const LED_OFF: &str = r#"{"system":{"set_led_off":{"off":1}}}"#;

/// Turn on the LED indicator light.
pub const LED_ON: &str = r#"{"system":{"set_led_off":{"off":0}}}"#;

/// Turn off the relay (power off the connected device).
pub const RELAY_OFF: &str = r#"{"system":{"set_relay_state":{"state":0}}}"#;

/// Turn on the relay (power on the connected device).
pub const RELAY_ON: &str = r#"{"system":{"set_relay_state":{"state":1}}}"#;

/// Reboot the device with a 1-second delay.
pub const REBOOT: &str = r#"{"system":{"reboot":{"delay":1}}}"#;

/// Factory reset the device with a 1-second delay.
///
/// **Warning:** This will erase all settings and require re-setup.
pub const RESET: &str = r#"{"system":{"reset":{"delay":1}}}"#;

/// Erase runtime statistics.
pub const RUNTIME_RESET: &str = r#"{"schedule":{"erase_runtime_stat":{}}}"#;

/// Get schedule rules.
pub const SCHEDULE: &str = r#"{"schedule":{"get_rules":{}}}"#;

/// Get the device's current time.
pub const TIME: &str = r#"{"time":{"get_time":{}}}"#;

/// Scan for available wireless networks.
pub const WLANSCAN: &str = r#"{"netif":{"get_scaninfo":{"refresh":0}}}"#;

/// Scan for available wireless networks (alternative endpoint for newer devices).
///
/// Some newer devices use the `smartlife.iot.common.softaponboarding` module
/// instead of `netif`. Try [`WLANSCAN`] first, then fall back to this.
pub const WLANSCAN_SOFTAP: &str =
    r#"{"smartlife.iot.common.softaponboarding":{"get_scaninfo":{"refresh":0}}}"#;

/// Generate a cloud bind command with the given credentials.
///
/// # Arguments
///
/// * `username` - TP-Link account email address
/// * `password` - TP-Link account password
///
/// # Example
///
/// ```
/// use kasa_core::commands;
///
/// let cmd = commands::cloud_bind("user@example.com", "secret123");
/// assert!(cmd.contains("user@example.com"));
/// ```
///
/// # Security Note
///
/// The password is sent in plaintext within the JSON command, though it is
/// encrypted using the TP-Link protocol before transmission over the network.
pub fn cloud_bind(username: &str, password: &str) -> String {
    format!(
        r#"{{"cnCloud":{{"bind":{{"username":"{}","password":"{}"}}}}}}"#,
        username, password
    )
}

/// Generate a command to connect the device to a WiFi network.
///
/// This command is used during device provisioning when the device is in AP mode.
///
/// # Arguments
///
/// * `ssid` - Network name (SSID) to connect to
/// * `password` - Network password
/// * `key_type` - Security type: 0=none, 1=WEP, 2=WPA, 3=WPA2
///
/// # Example
///
/// ```
/// use kasa_core::commands;
///
/// let cmd = commands::wifi_join("MyNetwork", "secret123", 3);
/// assert!(cmd.contains("MyNetwork"));
/// assert!(cmd.contains("key_type"));
/// ```
pub fn wifi_join(ssid: &str, password: &str, key_type: u8) -> String {
    format!(
        r#"{{"netif":{{"set_stainfo":{{"ssid":"{}","password":"{}","key_type":{}}}}}}}"#,
        ssid, password, key_type
    )
}

/// Generate a command to connect the device to a WiFi network (alternative endpoint).
///
/// Some newer devices use the `smartlife.iot.common.softaponboarding` module
/// instead of `netif`. Try [`wifi_join`] first, then fall back to this.
///
/// # Arguments
///
/// * `ssid` - Network name (SSID) to connect to
/// * `password` - Network password
/// * `key_type` - Security type: 0=none, 1=WEP, 2=WPA, 3=WPA2
pub fn wifi_join_softap(ssid: &str, password: &str, key_type: u8) -> String {
    format!(
        r#"{{"smartlife.iot.common.softaponboarding":{{"set_stainfo":{{"ssid":"{}","password":"{}","key_type":{}}}}}}}"#,
        ssid, password, key_type
    )
}

/// Wrap a command with context for a specific child plug.
///
/// Power strips like the HS300 have multiple outlets (children). To send
/// commands to a specific outlet, you need to wrap the command with a
/// context containing the child ID.
///
/// # Arguments
///
/// * `child_id` - The child plug ID (from sysinfo children array)
/// * `command_inner` - The JSON command to wrap (must be a valid JSON object without outer braces)
///
/// # Example
///
/// ```
/// use kasa_core::commands;
///
/// // Get energy for a specific plug
/// let cmd = commands::with_child_context(
///     "80064BBD5F529B1CE4DA888AF48CF58C24F0263501",
///     r#""emeter":{"get_realtime":{}}"#
/// );
/// assert!(cmd.contains("context"));
/// assert!(cmd.contains("child_ids"));
/// ```
pub fn with_child_context(child_id: &str, command_inner: &str) -> String {
    format!(
        r#"{{"context":{{"child_ids":["{}"]}},{}}}"#,
        child_id, command_inner
    )
}

/// Generate an energy reading command for a specific child plug.
///
/// # Arguments
///
/// * `child_id` - The child plug ID (from sysinfo children array)
///
/// # Example
///
/// ```
/// use kasa_core::commands;
///
/// let cmd = commands::energy_for_child("80064BBD5F529B1CE4DA888AF48CF58C24F0263501");
/// assert!(cmd.contains("emeter"));
/// assert!(cmd.contains("get_realtime"));
/// ```
pub fn energy_for_child(child_id: &str) -> String {
    with_child_context(child_id, r#""emeter":{"get_realtime":{}}"#)
}

/// Generate a relay on command for a specific child plug.
///
/// # Arguments
///
/// * `child_id` - The child plug ID (from sysinfo children array)
pub fn relay_on_for_child(child_id: &str) -> String {
    with_child_context(child_id, r#""system":{"set_relay_state":{"state":1}}"#)
}

/// Generate a relay off command for a specific child plug.
///
/// # Arguments
///
/// * `child_id` - The child plug ID (from sysinfo children array)
pub fn relay_off_for_child(child_id: &str) -> String {
    with_child_context(child_id, r#""system":{"set_relay_state":{"state":0}}"#)
}

/// Generate a batched energy reading command for multiple child plugs.
///
/// This sends a single request that retrieves energy data for all specified
/// children, significantly reducing network round trips for power strips.
///
/// # Arguments
///
/// * `child_ids` - Slice of child plug IDs (from sysinfo children array)
///
/// # Example
///
/// ```
/// use kasa_core::commands;
///
/// let ids = ["plug0", "plug1", "plug2"];
/// let cmd = commands::energy_for_children(&ids);
/// assert!(cmd.contains("emeter"));
/// assert!(cmd.contains("plug0"));
/// assert!(cmd.contains("plug1"));
/// assert!(cmd.contains("plug2"));
/// ```
///
/// # Response Format
///
/// The response contains an array of energy readings in the same order as the
/// child IDs provided. Use [`crate::response::BatchEmeterResponse`] to parse.
pub fn energy_for_children(child_ids: &[impl AsRef<str>]) -> String {
    let ids_json: Vec<String> = child_ids
        .iter()
        .map(|id| format!(r#""{}""#, id.as_ref()))
        .collect();

    format!(
        r#"{{"context":{{"child_ids":[{}]}},"emeter":{{"get_realtime":{{}}}}}}"#,
        ids_json.join(",")
    )
}
