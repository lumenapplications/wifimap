# WiFi/MAP

![CI](https://github.com/lumenapplications/wifimap/actions/workflows/ci.yml/badge.svg)

On-premises WiFi security monitoring for small businesses and the IT providers who look after them. A Raspberry Pi node sits on the client's network, watches every device and access point in real time, and draws it all on a live floor plan. No cloud, no per-device licensing.

<!-- Add a dashboard screenshot here: ![WiFi/MAP dashboard](docs/dashboard.png) -->

## The problem

Most small offices can't tell you what's on their own network. A rogue access point in a conference room, a spoofed MAC address on the guest WiFi, or a device that shows up at 2am all go unnoticed until something breaks. Enterprise tools that catch this are priced and built for enterprises. The managed service providers (MSPs) who support these offices need something they can drop into a site in minutes and watch from one screen.

## Who it's for

Small, owner-operated MSPs managing roughly 10 to 30 client sites. Each site gets a **WiFi/MAP Node**: a branded appliance with a Raspberry Pi, a UPS and an external antenna. Nodes are leased rather than sold, with pricing quoted per site after a free assessment. Returning the node on cancellation doubles as the off switch.

## What it does

- **Live floor plan.** Draw the building, place nodes, and see devices and signal coverage as a heatmap that updates in real time.
- **Security detection.** Flags rogue access points, deauthentication attacks, MAC spoofing and devices entering restricted zones, then scores each device for anomalous behavior.
- **Persistent history.** Devices, events, known access points and approvals are stored in SQLite, so nothing resets when the node reboots.
- **Multi-site view for MSPs.** An aggregation server collects every client site over Tailscale. One dashboard shows alert and device counts across all sites, and you can click into any one.
- **Push alerts.** Notifications go to the operator's phone through Ntfy.
- **Client-ready reports.** Generates a branded five-page PDF covering the device inventory, event log, zone violations, anomaly scores and recommendations.

## How it's built

| Piece | What it is |
|---|---|
| `bin/wifi_scanner.py` | Python scanner that runs on each Pi as a systemd service and streams over WebSockets |
| `bin/aggregation_server.py` | Central MSP hub with a SQLite site registry, real-time push, drill-in proxy and a watchdog |
| `bin/notification_server.py` | Bridge from the dashboard to Ntfy push notifications |
| `bin/generate_report.py` | PDF report generator (WeasyPrint) |
| `web/index.html` | Single-file dashboard with no build step |
| `install.sh` | Role-aware installer for a main server or a sensor node, with Tailscale setup |
| `docker-compose.yml` | Containerized dashboard, notification and aggregation services |

**Quality:** 174 automated tests (155 scanner, 19 aggregation integration), run on every push through GitHub Actions. Errors use typed exceptions (`ScannerError`, `NetworkError`, `ParseError` and others) instead of bare catches.

## Quick start (single site)

```bash
scp wifimap-v5.3.tar.gz pi@192.168.1.x:~/
ssh pi@192.168.1.x
tar -xzf wifimap-v5.3.tar.gz && cd wifimap
sudo ./install.sh
sudo tailscale up   # optional, for remote access
```

## Multi-site setup

```bash
# 1. Start the aggregation server on any Linux machine on your Tailscale network
docker-compose up -d
tailscale ip -4

# 2. On each client-site Pi, point the scanner at it and restart
sudo nano /etc/wifimap/config.env
#    WIFIMAP_UPSTREAM=ws://<aggregation-ip>:8766
sudo systemctl restart wifimap-scanner

# 3. Open the dashboard and switch to MSP View
```

## Generate a report

```bash
python3 bin/generate_report.py export.json --site "Client Name" --period "April 2026"
```

## Run the tests

```bash
pip3 install "websockets==12.0" "requests==2.31.0" pytest pytest-asyncio
cd tests
PYTHONPATH=../bin python3 -m pytest test_scanner.py test_aggregation.py -v --asyncio-mode=auto -W error::DeprecationWarning
```

## Roadmap

- Replace the Pi-hole dependency with a four-stage hostname resolution chain
- Passive DNS monitoring through packet capture
- Anomaly scores that decay over time instead of only accumulating
- A building setup wizard with a rescalable grid

---

Built by [Lumen Applications](https://github.com/lumenapplications).
