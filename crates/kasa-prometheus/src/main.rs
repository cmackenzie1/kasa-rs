//! Prometheus metrics exporter for TP-Link Kasa smart home devices.
//!
//! This exporter periodically discovers and polls Kasa devices on the local network,
//! collecting metrics about device state, energy usage, and connectivity.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use clap::Parser;
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
}

/// Shared application state
struct AppState {
    registry: RwLock<Registry>,
    metrics: DeviceMetrics,
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

    // Create metrics registry
    let mut registry = Registry::default();
    let metrics = DeviceMetrics::new(&mut registry);

    let state = Arc::new(AppState {
        registry: RwLock::new(registry),
        metrics,
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
            // Discovery mode
            match kasa_core::discover(discovery_timeout).await {
                Ok(devices) => {
                    info!("Discovered {} devices", devices.len());
                    state.metrics.set_devices_discovered(devices.len());

                    // Poll each device for additional data (energy, cloud status)
                    for device in devices {
                        // For discovery mode, we need to fetch sysinfo to check for children
                        match kasa_core::send_command(
                            &device.ip.to_string(),
                            device.port,
                            command_timeout,
                            kasa_core::commands::INFO,
                        )
                        .await
                        {
                            Ok(response) => {
                                if let Ok(json) =
                                    serde_json::from_str::<serde_json::Value>(&response)
                                    && let Some(sysinfo) =
                                        json.get("system").and_then(|s| s.get("get_sysinfo"))
                                {
                                    let children =
                                        sysinfo.get("children").and_then(|c| c.as_array());
                                    poll_single_device(
                                        &state,
                                        &device,
                                        command_timeout,
                                        sysinfo,
                                        children,
                                    )
                                    .await;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to get sysinfo from {}: {}", device.alias, e);
                            }
                        }
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

/// Poll a discovered device for additional metrics
async fn poll_single_device(
    state: &AppState,
    device: &kasa_core::DiscoveredDevice,
    command_timeout: Duration,
    _sysinfo: &serde_json::Value,
    children: Option<&Vec<serde_json::Value>>,
) {
    let ip = device.ip.to_string();

    // Set device info and basic metrics from discovery data
    state.metrics.set_device_info(device);
    state.metrics.set_relay_state(device, device.relay_state);
    state.metrics.set_led_off(device, device.led_off);
    state.metrics.set_rssi(device, device.rssi);
    state.metrics.set_on_time(device, device.on_time);
    state.metrics.set_updating(device, device.updating);

    // Check if this is a power strip with children
    if let Some(children) = children {
        debug!(
            "{} ({}) is a power strip with {} plugs",
            device.alias,
            device.model,
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
                device_id: device.device_id.clone(),
                alias: device.alias.clone(),
                model: device.model.clone(),
                ip: ip.clone(),
                plug_id: plug_id.clone(),
                plug_alias,
                plug_slot: slot.to_string(),
            };

            state.metrics.set_plug_relay_state(&labels, plug_state);
            state.metrics.set_plug_on_time(&labels, plug_on_time);

            // Get energy data for this plug
            let energy_cmd = kasa_core::commands::energy_for_child(&plug_id);
            match kasa_core::send_command(&ip, device.port, command_timeout, &energy_cmd).await {
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
                        device.alias, slot, e
                    );
                }
            }
        }

        state.metrics.set_scrape_success(device, true);
    } else {
        // Single device - try to get energy data (may not be supported by all devices)
        match kasa_core::send_command(
            &ip,
            device.port,
            command_timeout,
            kasa_core::commands::ENERGY,
        )
        .await
        {
            Ok(response) => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                    if let Some(emeter) = json.get("emeter").and_then(|e| e.get("get_realtime")) {
                        // Check for error
                        if emeter.get("err_code").and_then(|c| c.as_i64()) == Some(0) {
                            parse_energy_metrics(state, device, emeter);
                            state.metrics.set_scrape_success(device, true);
                        } else {
                            // Device doesn't support energy monitoring
                            debug!(
                                "{} ({}) does not support energy monitoring",
                                device.alias, device.model
                            );
                            state.metrics.set_scrape_success(device, true);
                        }
                    } else {
                        state.metrics.set_scrape_success(device, true);
                    }
                } else {
                    state.metrics.set_scrape_success(device, true);
                }
            }
            Err(e) => {
                warn!("Failed to get energy data from {}: {}", device.alias, e);
                state.metrics.set_scrape_success(device, false);
            }
        }
    }

    // Try to get cloud connection status
    match kasa_core::send_command(
        &ip,
        device.port,
        command_timeout,
        kasa_core::commands::CLOUDINFO,
    )
    .await
    {
        Ok(response) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response)
                && let Some(cloud) = json.get("cnCloud").and_then(|c| c.get("get_info"))
            {
                let connected = cloud
                    .get("cld_connection")
                    .and_then(|c| c.as_i64())
                    .unwrap_or(0)
                    == 1;
                state.metrics.set_cloud_connected(device, connected);
            }
        }
        Err(e) => {
            debug!("Failed to get cloud info from {}: {}", device.alias, e);
        }
    }
}

/// Poll a targeted device by IP address
async fn poll_targeted_device(
    state: &AppState,
    target: &str,
    command_timeout: Duration,
) -> std::io::Result<()> {
    // Get device info first
    let response = kasa_core::send_command(
        target,
        kasa_core::DEFAULT_PORT,
        command_timeout,
        kasa_core::commands::INFO,
    )
    .await?;

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
    let device = kasa_core::DiscoveredDevice {
        ip: target.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid IP: {}", e),
            )
        })?,
        port: kasa_core::DEFAULT_PORT,
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
    };

    // Check if this is a power strip with children
    let children = sysinfo.get("children").and_then(|c| c.as_array());

    // Now poll for additional data using the constructed device
    poll_single_device(state, &device, command_timeout, sysinfo, children).await;

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
