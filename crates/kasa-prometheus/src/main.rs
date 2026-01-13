//! Prometheus metrics exporter for TP-Link Kasa smart home devices.
//!
//! This exporter periodically discovers and polls Kasa devices on the local network,
//! collecting metrics about device state, energy usage, and connectivity.
//!
//! # Authentication
//!
//! Newer devices using KLAP v1/v2 or TPAP protocols require authentication.
//! Set credentials via environment variables:
//!
//! ```bash
//! export KASA_USERNAME=your-email@example.com
//! export KASA_PASSWORD=your-password
//! ```
//!
//! Or use CLI arguments:
//!
//! ```bash
//! kasa-prometheus --username your-email@example.com --password your-password
//! ```

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use clap::Parser;
use kasa_core::{
    Credentials,
    discovery::{self, DiscoveredDevice},
    transport::{DeviceConfig, EncryptionType, Transport, connect},
};
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

mod metrics;

use metrics::{DeviceMetrics, PlugLabels};

/// Prometheus metrics exporter for TP-Link Kasa smart home devices.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// HTTP listen address
    #[arg(long, default_value = "0.0.0.0:9101")]
    listen: SocketAddr,

    /// Device polling interval in seconds
    #[arg(long, default_value = "15")]
    scrape_interval: u64,

    /// Discovery timeout in seconds
    #[arg(long, default_value = "3")]
    discovery_timeout: u64,

    /// Per-device command timeout in seconds
    #[arg(long, default_value = "10")]
    command_timeout: u64,

    /// Target specific device IP addresses instead of using discovery.
    /// Can be specified multiple times.
    #[arg(long = "target", value_name = "IP")]
    targets: Vec<String>,

    /// TP-Link cloud account username (email).
    /// Required for devices with newer firmware (KLAP/TPAP protocols).
    /// Can also be set via KASA_USERNAME environment variable.
    #[arg(short, long, env = "KASA_USERNAME")]
    username: Option<String>,

    /// TP-Link cloud account password.
    /// Required for devices with newer firmware (KLAP/TPAP protocols).
    /// Can also be set via KASA_PASSWORD environment variable.
    #[arg(short, long, env = "KASA_PASSWORD")]
    password: Option<String>,
}

/// Shared application state
struct AppState {
    registry: RwLock<Registry>,
    metrics: DeviceMetrics,
    credentials: Option<Credentials>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    // Create credentials from CLI args or environment
    let credentials = match (&cli.username, &cli.password) {
        (Some(user), Some(pass)) => {
            info!("Using credentials for user: {}", user);
            Some(Credentials::new(user, pass))
        }
        (Some(user), None) => {
            warn!(
                "Username {} provided but no password. KLAP/TPAP devices may not be accessible.",
                user
            );
            None
        }
        (None, Some(_)) => {
            warn!("Password provided but no username. Credentials will not be used.");
            None
        }
        (None, None) => {
            info!("No credentials provided. Only legacy XOR devices will be fully accessible.");
            None
        }
    };

    // Create metrics registry
    let mut registry = Registry::default();
    let metrics = DeviceMetrics::new(&mut registry);

    let state = Arc::new(AppState {
        registry: RwLock::new(registry),
        metrics,
        credentials,
    });

    // Start background polling task
    let poll_state = Arc::clone(&state);
    let scrape_interval = Duration::from_secs(cli.scrape_interval);
    let discovery_timeout = Duration::from_secs(cli.discovery_timeout);
    let command_timeout = Duration::from_secs(cli.command_timeout);
    let targets = cli.targets.clone();

    tokio::spawn(async move {
        poll_devices(
            poll_state,
            scrape_interval,
            discovery_timeout,
            command_timeout,
            targets,
        )
        .await;
    });

    // Build HTTP router
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    info!("Starting kasa-exporter on {}", cli.listen);
    info!("Polling interval: {}s", cli.scrape_interval);

    if cli.targets.is_empty() {
        info!("Mode: discovery (will find devices automatically)");
    } else {
        info!("Mode: targeted ({} devices)", cli.targets.len());
        for target in &cli.targets {
            info!("  - {}", target);
        }
    }

    let listener = tokio::net::TcpListener::bind(cli.listen).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Background task that polls devices at regular intervals
async fn poll_devices(
    state: Arc<AppState>,
    interval: Duration,
    discovery_timeout: Duration,
    command_timeout: Duration,
    targets: Vec<String>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        debug!("Starting device poll cycle");

        let start = std::time::Instant::now();

        if targets.is_empty() {
            // Discovery mode - use discover_all to find both legacy and KLAP/TPAP devices
            match discovery::discover_all(discovery_timeout).await {
                Ok(devices) => {
                    info!("Discovered {} devices", devices.len());
                    state.metrics.set_devices_discovered(devices.len());

                    // Poll each device for additional data (energy, cloud status)
                    for device in devices {
                        poll_discovered_device(&state, &device, command_timeout).await;
                    }
                }
                Err(e) => {
                    error!("Discovery failed: {}", e);
                    state.metrics.set_devices_discovered(0);
                }
            }
        } else {
            // Targeted mode - poll specific IPs
            state.metrics.set_devices_discovered(targets.len());

            for target in &targets {
                match poll_targeted_device(&state, target, command_timeout).await {
                    Ok(()) => debug!("Successfully polled {}", target),
                    Err(e) => warn!("Failed to poll {}: {}", target, e),
                }
            }
        }

        let duration = start.elapsed();
        state.metrics.set_scrape_duration(duration);
        debug!("Poll cycle completed in {:?}", duration);
    }
}

/// Poll a discovered device, using the appropriate transport based on encryption type.
async fn poll_discovered_device(
    state: &AppState,
    device: &DiscoveredDevice,
    command_timeout: Duration,
) {
    let ip = device.ip.to_string();

    debug!(
        "Polling device {} ({}) at {} using {:?} protocol",
        device.alias, device.model, ip, device.encryption_type
    );

    // Build device config based on encryption type
    let mut config = DeviceConfig::new(&ip).with_timeout(command_timeout);

    // Set port based on device discovery info
    config = config.with_port(device.port);

    // Add credentials if available and device needs authentication
    if device.encryption_type != EncryptionType::Xor {
        if let Some(ref creds) = state.credentials {
            config = config.with_credentials(creds.clone());
        } else {
            debug!(
                "Device {} uses {:?} but no credentials provided, trying anyway",
                device.alias, device.encryption_type
            );
        }
    }

    // Try to connect and get sysinfo
    match connect(config).await {
        Ok(mut transport) => {
            debug!(
                "Connected to {} using {} on port {}",
                device.alias,
                transport.encryption_type(),
                transport.port()
            );

            // Get sysinfo
            match transport.send(kasa_core::commands::INFO).await {
                Ok(response) => {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response)
                        && let Some(sysinfo) = json.get("system").and_then(|s| s.get("get_sysinfo"))
                    {
                        let children = sysinfo.get("children").and_then(|c| c.as_array());
                        poll_device_with_transport(
                            state,
                            device,
                            &mut transport,
                            sysinfo,
                            children,
                        )
                        .await;
                    } else {
                        warn!(
                            "Invalid sysinfo response from {} ({}): {}",
                            device.alias, ip, response
                        );
                        set_basic_device_metrics(state, device);
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to get sysinfo from {} ({}): {}",
                        device.alias, ip, e
                    );
                    set_basic_device_metrics(state, device);
                }
            }
        }
        Err(e) => {
            warn!(
                "Failed to connect to {} ({}) using {:?}: {}",
                device.alias, ip, device.encryption_type, e
            );
            // Set basic metrics from discovery data even if we can't connect
            set_basic_device_metrics(state, device);
        }
    }
}

/// Set basic device metrics from discovery data when we can't get full info.
fn set_basic_device_metrics(state: &AppState, device: &DiscoveredDevice) {
    // Convert discovery::DiscoveredDevice to metrics-compatible format
    let metrics_device = device_to_metrics(device);
    state.metrics.set_device_info(&metrics_device);
    state
        .metrics
        .set_relay_state(&metrics_device, device.relay_state);
    state.metrics.set_led_off(&metrics_device, device.led_off);
    state.metrics.set_rssi(&metrics_device, device.rssi);
    state.metrics.set_on_time(&metrics_device, device.on_time);
    state.metrics.set_updating(&metrics_device, device.updating);
    state.metrics.set_scrape_success(&metrics_device, false);
}

/// Convert discovery::DiscoveredDevice to the metrics-compatible kasa_core::DiscoveredDevice
fn device_to_metrics(device: &DiscoveredDevice) -> kasa_core::DiscoveredDevice {
    kasa_core::DiscoveredDevice {
        ip: device.ip,
        port: device.port,
        alias: device.alias.clone(),
        model: device.model.clone(),
        mac: device.mac.clone(),
        device_id: device.device_id.clone(),
        hw_ver: device.hw_ver.clone(),
        sw_ver: device.sw_ver.clone(),
        relay_state: device.relay_state,
        led_off: device.led_off,
        rssi: device.rssi,
        on_time: device.on_time,
        updating: device.updating,
        encryption_type: device.encryption_type,
    }
}

/// Poll a device using an established transport connection.
async fn poll_device_with_transport(
    state: &AppState,
    device: &DiscoveredDevice,
    transport: &mut Box<dyn Transport>,
    sysinfo: &serde_json::Value,
    children: Option<&Vec<serde_json::Value>>,
) {
    let ip = device.ip.to_string();
    let metrics_device = device_to_metrics(device);

    // Update device metrics from sysinfo
    let relay_state = sysinfo
        .get("relay_state")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        == 1;
    let led_off = sysinfo.get("led_off").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
    let rssi = sysinfo.get("rssi").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let on_time = sysinfo.get("on_time").and_then(|v| v.as_u64()).unwrap_or(0);
    let updating = sysinfo
        .get("updating")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        == 1;

    // Build metrics device with updated info from sysinfo
    let updated_device = kasa_core::DiscoveredDevice {
        alias: sysinfo
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or(&device.alias)
            .to_string(),
        sw_ver: sysinfo
            .get("sw_ver")
            .and_then(|v| v.as_str())
            .unwrap_or(&device.sw_ver)
            .to_string(),
        hw_ver: sysinfo
            .get("hw_ver")
            .and_then(|v| v.as_str())
            .unwrap_or(&device.hw_ver)
            .to_string(),
        relay_state,
        led_off,
        rssi,
        on_time,
        updating,
        ..metrics_device.clone()
    };

    state.metrics.set_device_info(&updated_device);
    state.metrics.set_relay_state(&updated_device, relay_state);
    state.metrics.set_led_off(&updated_device, led_off);
    state.metrics.set_rssi(&updated_device, rssi);
    state.metrics.set_on_time(&updated_device, on_time);
    state.metrics.set_updating(&updated_device, updating);

    // Check if this is a power strip with children
    if let Some(children) = children {
        debug!(
            "{} ({}) is a power strip with {} plugs",
            updated_device.alias,
            updated_device.model,
            children.len()
        );

        // Set per-plug state from sysinfo
        for (slot, child) in children.iter().enumerate() {
            let plug_id = child
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let plug_alias = child
                .get("alias")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let plug_state = child.get("state").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
            let plug_on_time = child.get("on_time").and_then(|v| v.as_u64()).unwrap_or(0);

            let labels = PlugLabels {
                device_id: updated_device.device_id.clone(),
                alias: updated_device.alias.clone(),
                model: updated_device.model.clone(),
                ip: ip.clone(),
                plug_id: plug_id.clone(),
                plug_alias,
                plug_slot: slot.to_string(),
            };

            state.metrics.set_plug_relay_state(&labels, plug_state);
            state.metrics.set_plug_on_time(&labels, plug_on_time);

            // Get energy data for this plug
            let energy_cmd = kasa_core::commands::energy_for_child(&plug_id);
            match transport.send(&energy_cmd).await {
                Ok(response) => {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response)
                        && let Some(emeter) = json.get("emeter").and_then(|e| e.get("get_realtime"))
                        && emeter.get("err_code").and_then(|c| c.as_i64()) == Some(0)
                    {
                        parse_plug_energy_metrics(state, &labels, emeter);
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to get energy data from {} plug {}: {}",
                        updated_device.alias, slot, e
                    );
                }
            }
        }

        state.metrics.set_scrape_success(&updated_device, true);
    } else {
        // Single device - try to get energy data (may not be supported by all devices)
        match transport.send(kasa_core::commands::ENERGY).await {
            Ok(response) => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                    if let Some(emeter) = json.get("emeter").and_then(|e| e.get("get_realtime")) {
                        // Check for error
                        if emeter.get("err_code").and_then(|c| c.as_i64()) == Some(0) {
                            parse_energy_metrics(state, &updated_device, emeter);
                            state.metrics.set_scrape_success(&updated_device, true);
                        } else {
                            // Device doesn't support energy monitoring
                            debug!(
                                "{} ({}) does not support energy monitoring",
                                updated_device.alias, updated_device.model
                            );
                            state.metrics.set_scrape_success(&updated_device, true);
                        }
                    } else {
                        state.metrics.set_scrape_success(&updated_device, true);
                    }
                } else {
                    state.metrics.set_scrape_success(&updated_device, true);
                }
            }
            Err(e) => {
                warn!(
                    "Failed to get energy data from {}: {}",
                    updated_device.alias, e
                );
                state.metrics.set_scrape_success(&updated_device, false);
            }
        }
    }

    // Try to get cloud connection status
    match transport.send(kasa_core::commands::CLOUDINFO).await {
        Ok(response) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response)
                && let Some(cloud) = json.get("cnCloud").and_then(|c| c.get("get_info"))
            {
                let connected = cloud
                    .get("cld_connection")
                    .and_then(|c| c.as_i64())
                    .unwrap_or(0)
                    == 1;
                state
                    .metrics
                    .set_cloud_connected(&updated_device, connected);
            }
        }
        Err(e) => {
            debug!(
                "Failed to get cloud info from {}: {}",
                updated_device.alias, e
            );
        }
    }
}

/// Poll a targeted device by IP address using auto-detection.
async fn poll_targeted_device(
    state: &AppState,
    target: &str,
    command_timeout: Duration,
) -> std::io::Result<()> {
    // Build device config - try with credentials if available
    let mut config = DeviceConfig::new(target).with_timeout(command_timeout);

    if let Some(ref creds) = state.credentials {
        config = config.with_credentials(creds.clone());
    }

    // Try to connect using auto-detection
    let mut transport = connect(config).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("Failed to connect: {}", e),
        )
    })?;

    debug!(
        "Connected to {} using {} on port {}",
        target,
        transport.encryption_type(),
        transport.port()
    );

    // Get sysinfo
    let response = transport
        .send(kasa_core::commands::INFO)
        .await
        .map_err(|e| std::io::Error::other(format!("Command failed: {}", e)))?;

    let json: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let sysinfo = json
        .get("system")
        .and_then(|s| s.get("get_sysinfo"))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing sysinfo in response",
            )
        })?;

    // Build a DiscoveredDevice from the response
    let device = DiscoveredDevice {
        ip: target.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid IP: {}", e),
            )
        })?,
        port: transport.port(),
        alias: sysinfo
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        model: sysinfo
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        mac: sysinfo
            .get("mac")
            .or_else(|| sysinfo.get("mic_mac"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        device_id: sysinfo
            .get("deviceId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        hw_ver: sysinfo
            .get("hw_ver")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        sw_ver: sysinfo
            .get("sw_ver")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        relay_state: sysinfo
            .get("relay_state")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            == 1,
        led_off: sysinfo.get("led_off").and_then(|v| v.as_i64()).unwrap_or(0) == 1,
        rssi: sysinfo.get("rssi").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
        on_time: sysinfo.get("on_time").and_then(|v| v.as_u64()).unwrap_or(0),
        updating: sysinfo
            .get("updating")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            == 1,
        encryption_type: transport.encryption_type(),
        http_port: None,
        new_klap: None,
        login_version: None,
    };

    // Check if this is a power strip with children
    let children = sysinfo.get("children").and_then(|c| c.as_array());

    // Now poll for additional data using the established transport
    poll_device_with_transport(state, &device, &mut transport, sysinfo, children).await;

    Ok(())
}

/// Parse energy meter response and update metrics for a plug
fn parse_plug_energy_metrics(state: &AppState, labels: &PlugLabels, emeter: &serde_json::Value) {
    // Voltage (may be in voltage_mv or voltage)
    if let Some(voltage) = emeter
        .get("voltage_mv")
        .and_then(|v| v.as_f64())
        .map(|v| v / 1000.0)
        .or_else(|| emeter.get("voltage").and_then(|v| v.as_f64()))
    {
        state.metrics.set_plug_voltage(labels, voltage);
    }

    // Current (may be in current_ma or current)
    if let Some(current) = emeter
        .get("current_ma")
        .and_then(|v| v.as_f64())
        .map(|v| v / 1000.0)
        .or_else(|| emeter.get("current").and_then(|v| v.as_f64()))
    {
        state.metrics.set_plug_current(labels, current);
    }

    // Power (may be in power_mw or power)
    if let Some(power) = emeter
        .get("power_mw")
        .and_then(|v| v.as_f64())
        .map(|v| v / 1000.0)
        .or_else(|| emeter.get("power").and_then(|v| v.as_f64()))
    {
        state.metrics.set_plug_power(labels, power);
    }

    // Total energy (may be in total_wh or total)
    if let Some(total) = emeter
        .get("total_wh")
        .and_then(|v| v.as_f64())
        .or_else(|| emeter.get("total").and_then(|v| v.as_f64()))
    {
        state.metrics.set_plug_energy_total(labels, total);
    }
}

/// Parse energy meter response and update metrics
fn parse_energy_metrics(
    state: &AppState,
    device: &kasa_core::DiscoveredDevice,
    emeter: &serde_json::Value,
) {
    // Voltage (may be in voltage_mv or voltage)
    if let Some(voltage) = emeter
        .get("voltage_mv")
        .and_then(|v| v.as_f64())
        .map(|v| v / 1000.0)
        .or_else(|| emeter.get("voltage").and_then(|v| v.as_f64()))
    {
        state.metrics.set_voltage(device, voltage);
    }

    // Current (may be in current_ma or current)
    if let Some(current) = emeter
        .get("current_ma")
        .and_then(|v| v.as_f64())
        .map(|v| v / 1000.0)
        .or_else(|| emeter.get("current").and_then(|v| v.as_f64()))
    {
        state.metrics.set_current(device, current);
    }

    // Power (may be in power_mw or power)
    if let Some(power) = emeter
        .get("power_mw")
        .and_then(|v| v.as_f64())
        .map(|v| v / 1000.0)
        .or_else(|| emeter.get("power").and_then(|v| v.as_f64()))
    {
        state.metrics.set_power(device, power);
    }

    // Total energy (may be in total_wh or total)
    if let Some(total) = emeter
        .get("total_wh")
        .and_then(|v| v.as_f64())
        .or_else(|| emeter.get("total").and_then(|v| v.as_f64()))
    {
        state.metrics.set_energy_total(device, total);
    }
}

/// Index page handler
async fn index_handler() -> impl IntoResponse {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Kasa Exporter</title>
</head>
<body>
    <h1>Kasa Exporter</h1>
    <p>Prometheus metrics exporter for TP-Link Kasa smart home devices.</p>
    <ul>
        <li><a href="/metrics">Metrics</a></li>
        <li><a href="/health">Health</a></li>
    </ul>
</body>
</html>"#;

    (StatusCode::OK, [("content-type", "text/html")], html)
}

/// Health check handler
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Metrics handler - returns Prometheus exposition format
async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let registry = state.registry.read().await;
    let mut buffer = String::new();

    match encode(&mut buffer, &registry) {
        Ok(()) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            buffer,
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain; charset=utf-8")],
            format!("Error encoding metrics: {}", e),
        ),
    }
}
