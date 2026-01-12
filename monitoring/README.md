# Kasa Monitoring Stack

A complete monitoring stack for TP-Link Kasa smart home devices using Prometheus and Grafana.

## Quick Start

**On macOS/Windows** (hybrid mode - exporter runs natively for network access):

```bash
# 1. Start Prometheus and Grafana in Docker
docker compose up -d

# 2. Build and run the exporter natively (for device discovery)
cargo build --release -p kasa-prometheus
./target/release/kasa-prometheus --listen 0.0.0.0:9101

# 3. Open Grafana at http://localhost:3000 (admin/admin)
```

**On Linux** (everything in Docker):

```bash
# Uncomment network_mode: host in docker-compose.yml for kasa-exporter
docker compose up -d
```

## Stop Services

```bash
# Stop Docker services
docker compose down

# Stop native exporter (if running)
pkill kasa-prometheus
```

## Services

| Service | URL | Description |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | Visualization dashboards (admin/admin) |
| Prometheus | http://localhost:9090 | Metrics storage and querying |
| Kasa Exporter | http://localhost:9101 | Kasa device metrics exporter (native) |

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Kasa Devices   │────▶│  Kasa Exporter  │────▶│   Prometheus    │
│  (Local Network)│     │   :9101         │     │   :9090         │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │    Grafana      │
                                                │   :3000         │
                                                └─────────────────┘
```

## Configuration

### Kasa Exporter

The exporter needs access to your local network to discover and poll Kasa devices.

**macOS/Windows (Hybrid Mode):**
Run the exporter natively on your host machine. Docker Desktop's VM cannot access the host's local network for UDP broadcast discovery.

```bash
# Build once
cargo build --release -p kasa-prometheus

# Run with discovery mode (finds devices automatically)
./target/release/kasa-prometheus --listen 0.0.0.0:9101

# Or run with specific device IPs
./target/release/kasa-prometheus --listen 0.0.0.0:9101 \
  --target 192.168.1.100 --target 192.168.1.101
```

**Linux (Full Docker Mode):**
On Linux, `network_mode: host` works properly. Add the kasa-exporter service back to docker-compose.yml:

```yaml
kasa-exporter:
  build: .
  network_mode: host
  command: ["--listen", "0.0.0.0:9101"]
```

### Prometheus

Configuration: `monitoring/prometheus/prometheus.yml`

Default scrape interval is 15 seconds. Metrics are retained for 30 days.

### Grafana

- **Default credentials:** admin / admin
- **Datasource:** Auto-provisioned Prometheus datasource
- **Dashboards:** Auto-provisioned from `monitoring/grafana/provisioning/dashboards/`

## Dashboard

The included "Kasa Smart Home Devices" dashboard provides:

### Overview Section
- Total devices discovered
- Devices currently on
- Total power consumption
- Total energy consumed
- Scrape status and duration

### Power Consumption
- Real-time power per device (Watts)
- Power strip individual plug power
- Stacked total power consumption

### Energy
- Total energy consumed per device (Watt-hours)
- Energy per plug on power strips

### Voltage & Current
- Voltage monitoring (Volts)
- Current draw (Amps)

### Device State
- Relay on/off state timeline
- Device on-time duration
- Plug state for power strips

### Connectivity
- WiFi signal strength (RSSI in dBm)
- Cloud connection status
- Scrape success/failure per device

### Device Information
- Table view of all device metadata (model, IP, MAC, firmware versions)

## Metrics Reference

### Device Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kasa_device_info` | Gauge | device_id, alias, model, ip, hw_ver, sw_ver, mac | Device metadata (always 1) |
| `kasa_device_relay_state` | Gauge | device_id, alias, model, ip | Relay state (1=on, 0=off) |
| `kasa_device_led_off` | Gauge | device_id, alias, model, ip | LED indicator (1=off, 0=on) |
| `kasa_device_rssi_dbm` | Gauge | device_id, alias, model, ip | WiFi signal strength |
| `kasa_device_on_time_seconds` | Gauge | device_id, alias, model, ip | Seconds since relay on |
| `kasa_device_updating` | Gauge | device_id, alias, model, ip | Firmware update status |
| `kasa_device_cloud_connected` | Gauge | device_id, alias, model, ip | Cloud connection status |

### Energy Metrics (devices with energy monitoring)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kasa_device_voltage_volts` | Gauge | device_id, alias, model, ip | Voltage in volts |
| `kasa_device_current_amps` | Gauge | device_id, alias, model, ip | Current in amps |
| `kasa_device_power_watts` | Gauge | device_id, alias, model, ip | Power in watts |
| `kasa_device_energy_watt_hours_total` | Gauge | device_id, alias, model, ip | Total energy in Wh |

### Per-Plug Metrics (power strips like HS300)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kasa_plug_voltage_volts` | Gauge | device_id, alias, model, ip, plug_id, plug_alias, plug_slot | Voltage per plug |
| `kasa_plug_current_amps` | Gauge | device_id, alias, model, ip, plug_id, plug_alias, plug_slot | Current per plug |
| `kasa_plug_power_watts` | Gauge | device_id, alias, model, ip, plug_id, plug_alias, plug_slot | Power per plug |
| `kasa_plug_energy_watt_hours_total` | Gauge | device_id, alias, model, ip, plug_id, plug_alias, plug_slot | Energy per plug |
| `kasa_plug_relay_state` | Gauge | device_id, alias, model, ip, plug_id, plug_alias, plug_slot | Relay state per plug |
| `kasa_plug_on_time_seconds` | Gauge | device_id, alias, model, ip, plug_id, plug_alias, plug_slot | On time per plug |

### Exporter Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kasa_scrape_success` | Gauge | device_id | Last scrape success (1=ok, 0=fail) |
| `kasa_scrape_duration_seconds` | Gauge | - | Duration of last scrape cycle |
| `kasa_devices_discovered` | Gauge | - | Number of devices discovered |

## Importing the Dashboard

The dashboard JSON can be found at:
`monitoring/grafana/provisioning/dashboards/kasa-devices.json`

To import into an existing Grafana instance:
1. Go to Dashboards → Import
2. Upload the JSON file or paste its contents
3. Select your Prometheus datasource
4. Click Import

## Troubleshooting

### No devices discovered

1. Ensure Kasa devices are on the same network as the Docker host
2. Try using targeted mode with explicit device IPs
3. Check firewall rules allow UDP port 9999 (Kasa protocol)
4. Verify devices respond: `cargo run -p kasa -- discover`

### Grafana shows "No data"

1. Check Prometheus is scraping successfully: http://localhost:9090/targets
2. Verify kasa-exporter is running: http://localhost:9101/metrics
3. Wait for at least one scrape interval (15s by default)

### Permission denied errors

On Linux, you may need to run Docker with appropriate permissions for host network mode.

## Volumes

Data is persisted in Docker volumes:
- `prometheus_data` - Prometheus time series data
- `grafana_data` - Grafana configuration and dashboards
