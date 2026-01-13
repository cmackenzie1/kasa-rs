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
    Credentials, DiscoveredDevice, discovery,
    transport::{DeviceConfig, EncryptionType, Transport, TransportExt, connect},
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

                    // Poll all devices concurrently
                    let futures: Vec<_> = devices
                        .iter()
                        .map(|device| {
                            let state = Arc::clone(&state);
                            let device = device.clone();
                            async move {
                                poll_discovered_device(&state, &device, command_timeout).await;
                            }
                        })
                        .collect();
                    futures::future::join_all(futures).await;
                }
                Err(e) => {
                    error!("Discovery failed: {}", e);
                    state.metrics.set_devices_discovered(0);
                }
            }
        } else {
            // Targeted mode - poll specific IPs concurrently
            state.metrics.set_devices_discovered(targets.len());

            let futures: Vec<_> = targets
                .iter()
                .map(|target| {
                    let state = Arc::clone(&state);
                    let target = target.clone();
                    async move {
                        match poll_targeted_device(&state, &target, command_timeout).await {
                            Ok(()) => debug!("Successfully polled {}", target),
                            Err(e) => warn!("Failed to poll {}: {}", target, e),
                        }
                    }
                })
                .collect();
            futures::future::join_all(futures).await;
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

    // Build device config from discovery results
    let mut config = DeviceConfig::from_discovered(device).with_timeout(command_timeout);

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

            // Get sysinfo using TransportExt
            match transport.get_sysinfo().await {
                Ok(sysinfo) => {
                    poll_device_with_transport(state, device, &mut transport, &sysinfo).await;
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
    state.metrics.set_device_info(device);
    state.metrics.set_relay_state(device, device.relay_state);
    state.metrics.set_led_off(device, device.led_off);
    state.metrics.set_rssi(device, device.rssi);
    state.metrics.set_on_time(device, device.on_time);
    state.metrics.set_updating(device, device.updating);
    state.metrics.set_scrape_success(device, false);
}

/// Poll a device using an established transport connection.
async fn poll_device_with_transport(
    state: &AppState,
    device: &DiscoveredDevice,
    transport: &mut Box<dyn Transport>,
    sysinfo: &kasa_core::response::SysInfo,
) {
    let ip = device.ip.to_string();

    // Build updated device info from sysinfo response
    let updated_device = DiscoveredDevice {
        ip: device.ip,
        port: device.port,
        mac: if sysinfo.mac_address().is_empty() {
            device.mac.clone()
        } else {
            sysinfo.mac_address().to_string()
        },
        device_id: if sysinfo.device_id.is_empty() {
            device.device_id.clone()
        } else {
            sysinfo.device_id.clone()
        },
        alias: if sysinfo.alias.is_empty() {
            device.alias.clone()
        } else {
            sysinfo.alias.clone()
        },
        model: if sysinfo.model.is_empty() {
            device.model.clone()
        } else {
            sysinfo.model.clone()
        },
        hw_ver: if sysinfo.hw_ver.is_empty() {
            device.hw_ver.clone()
        } else {
            sysinfo.hw_ver.clone()
        },
        sw_ver: if sysinfo.sw_ver.is_empty() {
            device.sw_ver.clone()
        } else {
            sysinfo.sw_ver.clone()
        },
        relay_state: sysinfo.is_on(),
        led_off: sysinfo.is_led_off(),
        rssi: sysinfo.rssi,
        on_time: sysinfo.on_time,
        updating: sysinfo.is_updating(),
        encryption_type: device.encryption_type,
        http_port: device.http_port,
        new_klap: device.new_klap,
        login_version: device.login_version,
    };

    state.metrics.set_device_info(&updated_device);
    state
        .metrics
        .set_relay_state(&updated_device, updated_device.relay_state);
    state
        .metrics
        .set_led_off(&updated_device, updated_device.led_off);
    state.metrics.set_rssi(&updated_device, updated_device.rssi);
    state
        .metrics
        .set_on_time(&updated_device, updated_device.on_time);
    state
        .metrics
        .set_updating(&updated_device, updated_device.updating);

    // Check if this is a power strip with children
    if sysinfo.is_power_strip() {
        debug!(
            "{} ({}) is a power strip with {} plugs",
            updated_device.alias,
            updated_device.model,
            sysinfo.children.len()
        );

        // Set per-plug state from sysinfo
        for (slot, child) in sysinfo.children.iter().enumerate() {
            let labels = PlugLabels {
                device_id: updated_device.device_id.clone(),
                alias: updated_device.alias.clone(),
                model: updated_device.model.clone(),
                ip: ip.clone(),
                plug_id: child.id.clone(),
                plug_alias: child.alias.clone(),
                plug_slot: slot.to_string(),
            };

            state.metrics.set_plug_relay_state(&labels, child.is_on());
            state.metrics.set_plug_on_time(&labels, child.on_time);

            // Get energy data for this plug using TransportExt
            match transport.get_energy_for_child(&child.id).await {
                Ok(reading) => {
                    set_plug_energy_metrics(state, &labels, &reading);
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
        match transport.get_energy().await {
            Ok(reading) => {
                set_energy_metrics(state, &updated_device, &reading);
                state.metrics.set_scrape_success(&updated_device, true);
            }
            Err(e) => {
                // Energy monitoring not supported is not a failure
                debug!(
                    "{} ({}) energy query failed: {}",
                    updated_device.alias, updated_device.model, e
                );
                state.metrics.set_scrape_success(&updated_device, true);
            }
        }
    }

    // Try to get cloud connection status
    match transport.get_cloud_info().await {
        Ok(cloud_info) => {
            state
                .metrics
                .set_cloud_connected(&updated_device, cloud_info.is_connected());
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

    // Get sysinfo using TransportExt
    let sysinfo = transport
        .get_sysinfo()
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to get sysinfo: {}", e)))?;

    // Build a DiscoveredDevice from the response
    let device = DiscoveredDevice {
        ip: target.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid IP: {}", e),
            )
        })?,
        port: transport.port(),
        alias: sysinfo.alias.clone(),
        model: sysinfo.model.clone(),
        mac: sysinfo.mac_address().to_string(),
        device_id: sysinfo.device_id.clone(),
        hw_ver: sysinfo.hw_ver.clone(),
        sw_ver: sysinfo.sw_ver.clone(),
        relay_state: sysinfo.is_on(),
        led_off: sysinfo.is_led_off(),
        rssi: sysinfo.rssi,
        on_time: sysinfo.on_time,
        updating: sysinfo.is_updating(),
        encryption_type: transport.encryption_type(),
        http_port: None,
        new_klap: None,
        login_version: None,
    };

    // Now poll for additional data using the established transport
    poll_device_with_transport(state, &device, &mut transport, &sysinfo).await;

    Ok(())
}

/// Set energy metrics for a plug using typed EnergyReading.
fn set_plug_energy_metrics(
    state: &AppState,
    labels: &PlugLabels,
    reading: &kasa_core::response::EnergyReading,
) {
    if let Some(voltage) = reading.voltage_v() {
        state.metrics.set_plug_voltage(labels, voltage);
    }
    if let Some(current) = reading.current_a() {
        state.metrics.set_plug_current(labels, current);
    }
    if let Some(power) = reading.power_w() {
        state.metrics.set_plug_power(labels, power);
    }
    if let Some(total) = reading.total_wh() {
        state.metrics.set_plug_energy_total(labels, total);
    }
}

/// Set energy metrics for a device using typed EnergyReading.
fn set_energy_metrics(
    state: &AppState,
    device: &DiscoveredDevice,
    reading: &kasa_core::response::EnergyReading,
) {
    if let Some(voltage) = reading.voltage_v() {
        state.metrics.set_voltage(device, voltage);
    }
    if let Some(current) = reading.current_a() {
        state.metrics.set_current(device, current);
    }
    if let Some(power) = reading.power_w() {
        state.metrics.set_power(device, power);
    }
    if let Some(total) = reading.total_wh() {
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
