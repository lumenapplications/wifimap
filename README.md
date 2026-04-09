# WiFi/MAP v5.3 — Security Platform

On-premises WiFi network intelligence and security monitoring for the SMB and MSP market.
Runs on a Raspberry Pi. No cloud. No subscription.

![CI](https://github.com/YOUR_ORG/wifimap/actions/workflows/ci.yml/badge.svg)

## What's new in v5.3

**Multi-site MSP dashboard** — central aggregation server with real-time push.
Pi scanners at client sites connect outbound via Tailscale. MSP overview shows
all sites, alert counts, and device counts in one view. Click any site to drill in.

**Tailscale integration** — install.sh now installs Tailscale silently.
Three-command client site deployment: install, tailscale up, done.

**Docker deployment** — dashboard + notification server + aggregation server
all containerised. `docker-compose up` on any Linux machine.

**PDF security reports** — generate branded PDF reports from any JSON export.
Device inventory, event log, zone violations, anomaly scores, recommendations.

**Deauth detection** — tx_retries delta monitoring via `iw station dump`.
No monitor mode required.

**Structured exception types** — `ScannerError`, `NetworkError`, `PermissionError`,
`ParseError`, `ConfigError`. 11 bare excepts replaced with typed catches.

## Quick Start (single site)

```bash
scp wifimap-v5.3.tar.gz pi@192.168.1.x:~/
ssh pi@192.168.1.x
tar -xzf wifimap-v5.3.tar.gz && cd wifimap
sudo ./install.sh
# Then optionally:
sudo tailscale up
```

## MSP / Multi-site Setup

```bash
# 1. Deploy aggregation server (any Linux machine on Tailscale)
docker-compose up -d

# 2. Get aggregation server Tailscale IP
tailscale ip -4

# 3. At each client site Pi, edit config and restart
sudo nano /etc/wifimap/config.env
# Set: WIFIMAP_UPSTREAM=ws://100.64.0.2:8766
sudo systemctl restart wifimap-scanner

# 4. Open dashboard → ⊞ MSP View → all sites appear automatically
```

## Generate PDF Report

```bash
# From the dashboard: Export PDF Report → saves JSON
python3 bin/generate_report.py export.json \
  --site "Client Name" \
  --period "April 2026"
```

## File Layout

```
bin/
  wifi_scanner.py        Pi scanner (systemd, needs WiFi hardware)
  notification_server.py Ntfy push bridge
  aggregation_server.py  MSP central hub
  generate_report.py     PDF report generator
web/
  index.html             Dashboard (single-file)
tests/
  test_scanner.py        155 tests
.github/workflows/
  ci.yml                 GitHub Actions: test + lint + package
Dockerfile.dashboard
Dockerfile.notify
Dockerfile.aggregation
docker-compose.yml
install.sh
```

## Services

```bash
sudo systemctl status wifimap-scanner
sudo systemctl status wifimap-web
sudo systemctl status wifimap-notify
tail -f /var/log/wifimap/scanner.log
```

## Tests

```bash
pip3 install pytest pytest-cov --break-system-packages
cd /opt/wifimap && pytest tests/ -v -W error::DeprecationWarning
```
