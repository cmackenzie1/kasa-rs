//! Prometheus metrics definitions for Kasa devices.

use std::time::Duration;

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};

/// Labels for device identification (used on most metrics).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DeviceLabels {
    pub device_id: String,
    pub alias: String,
    pub model: String,
    pub ip: String,
}

/// Labels for plug-level metrics on power strips.
/// Includes a plug identifier for individual outlet tracking.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PlugLabels {
    pub device_id: String,
    pub alias: String,
    pub model: String,
    pub ip: String,
    pub plug_id: String,
    pub plug_alias: String,
    pub plug_slot: String,
}

/// Labels for device info metric (includes version information).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DeviceInfoLabels {
    pub device_id: String,
    pub alias: String,
    pub model: String,
    pub ip: String,
    pub hw_ver: String,
    pub sw_ver: String,
    pub mac: String,
}

/// Labels for scrape success metric (just device_id for simplicity).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ScrapeLabels {
    pub device_id: String,
}

impl From<&kasa_core::DiscoveredDevice> for DeviceLabels {
    fn from(device: &kasa_core::DiscoveredDevice) -> Self {
        Self {
            device_id: device.device_id.clone(),
            alias: device.alias.clone(),
            model: device.model.clone(),
            ip: device.ip.to_string(),
        }
    }
}

impl From<&kasa_core::DiscoveredDevice> for DeviceInfoLabels {
    fn from(device: &kasa_core::DiscoveredDevice) -> Self {
        Self {
            device_id: device.device_id.clone(),
            alias: device.alias.clone(),
            model: device.model.clone(),
            ip: device.ip.to_string(),
            hw_ver: device.hw_ver.clone(),
            sw_ver: device.sw_ver.clone(),
            mac: device.mac.clone(),
        }
    }
}

impl From<&kasa_core::DiscoveredDevice> for ScrapeLabels {
    fn from(device: &kasa_core::DiscoveredDevice) -> Self {
        Self {
            device_id: device.device_id.clone(),
        }
    }
}

/// Container for all Kasa device metrics.
pub struct DeviceMetrics {
    // Device info (always 1, carries metadata as labels)
    device_info: Family<DeviceInfoLabels, Gauge>,

    // Device state metrics
    relay_state: Family<DeviceLabels, Gauge>,
    led_off: Family<DeviceLabels, Gauge>,
    rssi_dbm: Family<DeviceLabels, Gauge<i64>>,
    on_time_seconds: Family<DeviceLabels, Gauge>,
    updating: Family<DeviceLabels, Gauge>,
    cloud_connected: Family<DeviceLabels, Gauge>,

    // Energy metrics (only populated for devices that support it)
    voltage_volts: Family<DeviceLabels, Gauge<f64, std::sync::atomic::AtomicU64>>,
    current_amps: Family<DeviceLabels, Gauge<f64, std::sync::atomic::AtomicU64>>,
    power_watts: Family<DeviceLabels, Gauge<f64, std::sync::atomic::AtomicU64>>,
    energy_watt_hours_total: Family<DeviceLabels, Gauge<f64, std::sync::atomic::AtomicU64>>,

    // Per-plug energy metrics for power strips
    plug_voltage_volts: Family<PlugLabels, Gauge<f64, std::sync::atomic::AtomicU64>>,
    plug_current_amps: Family<PlugLabels, Gauge<f64, std::sync::atomic::AtomicU64>>,
    plug_power_watts: Family<PlugLabels, Gauge<f64, std::sync::atomic::AtomicU64>>,
    plug_energy_watt_hours_total: Family<PlugLabels, Gauge<f64, std::sync::atomic::AtomicU64>>,
    plug_relay_state: Family<PlugLabels, Gauge>,
    plug_on_time_seconds: Family<PlugLabels, Gauge>,

    // Exporter metrics
    scrape_success: Family<ScrapeLabels, Gauge>,
    scrape_duration_seconds: Gauge<f64, std::sync::atomic::AtomicU64>,
    devices_discovered: Gauge,
}

impl DeviceMetrics {
    /// Create new metrics and register them with the provided registry.
    pub fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            device_info: Family::default(),
            relay_state: Family::default(),
            led_off: Family::default(),
            rssi_dbm: Family::default(),
            on_time_seconds: Family::default(),
            updating: Family::default(),
            cloud_connected: Family::default(),
            voltage_volts: Family::default(),
            current_amps: Family::default(),
            power_watts: Family::default(),
            energy_watt_hours_total: Family::default(),
            plug_voltage_volts: Family::default(),
            plug_current_amps: Family::default(),
            plug_power_watts: Family::default(),
            plug_energy_watt_hours_total: Family::default(),
            plug_relay_state: Family::default(),
            plug_on_time_seconds: Family::default(),
            scrape_success: Family::default(),
            scrape_duration_seconds: Gauge::default(),
            devices_discovered: Gauge::default(),
        };

        // Register all metrics
        registry.register(
            "kasa_device_info",
            "Device information and metadata (value is always 1)",
            metrics.device_info.clone(),
        );

        registry.register(
            "kasa_device_relay_state",
            "Relay state (1 = on, 0 = off)",
            metrics.relay_state.clone(),
        );

        registry.register(
            "kasa_device_led_off",
            "LED indicator state (1 = off, 0 = on)",
            metrics.led_off.clone(),
        );

        registry.register(
            "kasa_device_rssi_dbm",
            "WiFi signal strength in dBm",
            metrics.rssi_dbm.clone(),
        );

        registry.register(
            "kasa_device_on_time_seconds",
            "Seconds since relay was turned on",
            metrics.on_time_seconds.clone(),
        );

        registry.register(
            "kasa_device_updating",
            "Firmware update in progress (1 = updating, 0 = not updating)",
            metrics.updating.clone(),
        );

        registry.register(
            "kasa_device_cloud_connected",
            "Cloud connection status (1 = connected, 0 = disconnected)",
            metrics.cloud_connected.clone(),
        );

        registry.register(
            "kasa_device_voltage_volts",
            "Current voltage in volts",
            metrics.voltage_volts.clone(),
        );

        registry.register(
            "kasa_device_current_amps",
            "Current draw in amps",
            metrics.current_amps.clone(),
        );

        registry.register(
            "kasa_device_power_watts",
            "Current power consumption in watts",
            metrics.power_watts.clone(),
        );

        registry.register(
            "kasa_device_energy_watt_hours_total",
            "Total energy consumed in watt-hours",
            metrics.energy_watt_hours_total.clone(),
        );

        // Per-plug metrics for power strips
        registry.register(
            "kasa_plug_voltage_volts",
            "Current voltage in volts for individual plug",
            metrics.plug_voltage_volts.clone(),
        );

        registry.register(
            "kasa_plug_current_amps",
            "Current draw in amps for individual plug",
            metrics.plug_current_amps.clone(),
        );

        registry.register(
            "kasa_plug_power_watts",
            "Current power consumption in watts for individual plug",
            metrics.plug_power_watts.clone(),
        );

        registry.register(
            "kasa_plug_energy_watt_hours_total",
            "Total energy consumed in watt-hours for individual plug",
            metrics.plug_energy_watt_hours_total.clone(),
        );

        registry.register(
            "kasa_plug_relay_state",
            "Relay state for individual plug (1 = on, 0 = off)",
            metrics.plug_relay_state.clone(),
        );

        registry.register(
            "kasa_plug_on_time_seconds",
            "Seconds since relay was turned on for individual plug",
            metrics.plug_on_time_seconds.clone(),
        );

        registry.register(
            "kasa_scrape_success",
            "Whether the last scrape was successful (1 = success, 0 = failure)",
            metrics.scrape_success.clone(),
        );

        registry.register(
            "kasa_scrape_duration_seconds",
            "Duration of the last scrape cycle in seconds",
            metrics.scrape_duration_seconds.clone(),
        );

        registry.register(
            "kasa_devices_discovered",
            "Number of devices discovered in the last poll",
            metrics.devices_discovered.clone(),
        );

        metrics
    }

    /// Set device info metric
    pub fn set_device_info(&self, device: &kasa_core::DiscoveredDevice) {
        self.device_info
            .get_or_create(&DeviceInfoLabels::from(device))
            .set(1);
    }

    /// Set relay state
    pub fn set_relay_state(&self, device: &kasa_core::DiscoveredDevice, state: bool) {
        self.relay_state
            .get_or_create(&DeviceLabels::from(device))
            .set(if state { 1 } else { 0 });
    }

    /// Set LED off state
    pub fn set_led_off(&self, device: &kasa_core::DiscoveredDevice, off: bool) {
        self.led_off
            .get_or_create(&DeviceLabels::from(device))
            .set(if off { 1 } else { 0 });
    }

    /// Set RSSI in dBm
    pub fn set_rssi(&self, device: &kasa_core::DiscoveredDevice, rssi: i32) {
        self.rssi_dbm
            .get_or_create(&DeviceLabels::from(device))
            .set(rssi as i64);
    }

    /// Set on time in seconds
    pub fn set_on_time(&self, device: &kasa_core::DiscoveredDevice, seconds: u64) {
        self.on_time_seconds
            .get_or_create(&DeviceLabels::from(device))
            .set(seconds as i64);
    }

    /// Set updating state
    pub fn set_updating(&self, device: &kasa_core::DiscoveredDevice, updating: bool) {
        self.updating
            .get_or_create(&DeviceLabels::from(device))
            .set(if updating { 1 } else { 0 });
    }

    /// Set cloud connection state
    pub fn set_cloud_connected(&self, device: &kasa_core::DiscoveredDevice, connected: bool) {
        self.cloud_connected
            .get_or_create(&DeviceLabels::from(device))
            .set(if connected { 1 } else { 0 });
    }

    /// Set voltage in volts
    pub fn set_voltage(&self, device: &kasa_core::DiscoveredDevice, volts: f64) {
        self.voltage_volts
            .get_or_create(&DeviceLabels::from(device))
            .set(volts);
    }

    /// Set current in amps
    pub fn set_current(&self, device: &kasa_core::DiscoveredDevice, amps: f64) {
        self.current_amps
            .get_or_create(&DeviceLabels::from(device))
            .set(amps);
    }

    /// Set power in watts
    pub fn set_power(&self, device: &kasa_core::DiscoveredDevice, watts: f64) {
        self.power_watts
            .get_or_create(&DeviceLabels::from(device))
            .set(watts);
    }

    /// Set total energy in watt-hours
    pub fn set_energy_total(&self, device: &kasa_core::DiscoveredDevice, watt_hours: f64) {
        self.energy_watt_hours_total
            .get_or_create(&DeviceLabels::from(device))
            .set(watt_hours);
    }

    /// Set voltage in volts for a specific plug
    pub fn set_plug_voltage(&self, labels: &PlugLabels, volts: f64) {
        self.plug_voltage_volts.get_or_create(labels).set(volts);
    }

    /// Set current in amps for a specific plug
    pub fn set_plug_current(&self, labels: &PlugLabels, amps: f64) {
        self.plug_current_amps.get_or_create(labels).set(amps);
    }

    /// Set power in watts for a specific plug
    pub fn set_plug_power(&self, labels: &PlugLabels, watts: f64) {
        self.plug_power_watts.get_or_create(labels).set(watts);
    }

    /// Set total energy in watt-hours for a specific plug
    pub fn set_plug_energy_total(&self, labels: &PlugLabels, watt_hours: f64) {
        self.plug_energy_watt_hours_total
            .get_or_create(labels)
            .set(watt_hours);
    }

    /// Set relay state for a specific plug
    pub fn set_plug_relay_state(&self, labels: &PlugLabels, state: bool) {
        self.plug_relay_state
            .get_or_create(labels)
            .set(if state { 1 } else { 0 });
    }

    /// Set on time in seconds for a specific plug
    pub fn set_plug_on_time(&self, labels: &PlugLabels, seconds: u64) {
        self.plug_on_time_seconds
            .get_or_create(labels)
            .set(seconds as i64);
    }

    /// Set scrape success for a device
    pub fn set_scrape_success(&self, device: &kasa_core::DiscoveredDevice, success: bool) {
        self.scrape_success
            .get_or_create(&ScrapeLabels::from(device))
            .set(if success { 1 } else { 0 });
    }

    /// Set scrape duration
    pub fn set_scrape_duration(&self, duration: Duration) {
        self.scrape_duration_seconds.set(duration.as_secs_f64());
    }

    /// Set number of discovered devices
    pub fn set_devices_discovered(&self, count: usize) {
        self.devices_discovered.set(count as i64);
    }
}
