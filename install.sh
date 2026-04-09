#!/bin/bash
# ============================================================
# WiFi/MAP v5.3 — Install Script
# ============================================================
set -e

INSTALL_DIR="/opt/wifimap"
CONFIG_DIR="/etc/wifimap"
LOG_DIR="/var/log/wifimap"
DATA_DIR="/var/lib/wifimap"
WEB_PORT=8080
WS_PORT=8765
NOTIFY_PORT=8768
NTFY_PORT=7777
AGG_SCANNER_PORT=8766
AGG_DASHBOARD_PORT=8767

# ── Root check ────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root: sudo ./install.sh"
  exit 1
fi

# ── Role selection ────────────────────────────────────────────
echo ""
echo "=========================================="
echo " WiFi/MAP v5.3 — Security Platform"
echo "=========================================="
echo ""
echo "  Select install type:"
echo ""
echo "  1) Main Server"
echo "     Runs the dashboard, scanner, aggregation server,"
echo "     and notification server. Install this on your Pi 5."
echo ""
echo "  2) Sensor Node"
echo "     Lightweight scanner only. Connects to the main"
echo "     server and reports signal data. Install this on"
echo "     each Pi Zero 2 W."
echo ""
read -rp "  Enter 1 or 2: " ROLE_CHOICE
echo ""

case "$ROLE_CHOICE" in
  1) ROLE="main"   ; echo "  Installing as: Main Server" ;;
  2) ROLE="node"   ; echo "  Installing as: Sensor Node" ;;
  *)
    echo "ERROR: Invalid choice. Enter 1 or 2."
    exit 1
    ;;
esac

echo ""

# ── Step 1: System packages ───────────────────────────────────
echo "[1/8] Updating and upgrading system packages..."
echo "  This may take a few minutes on first install..."
apt-get update -qq
apt-get upgrade -y -qq

if [ "$ROLE" = "main" ]; then
  apt-get install -y -qq \
    arp-scan nmap wireless-tools iw curl \
    python3-pip python3-websockets sqlite3 \
    ufw net-tools weasyprint
else
  apt-get install -y -qq \
    arp-scan nmap wireless-tools iw curl \
    python3-pip python3-websockets sqlite3 \
    ufw net-tools
fi

# ── Step 2: Python dependencies ───────────────────────────────
echo "[2/8] Installing Python dependencies..."
pip3 install \
  "websockets==12.0" \
  "requests==2.31.0" \
  --break-system-packages --quiet

# ── Step 3: Ntfy (main server only) ──────────────────────────
if [ "$ROLE" = "main" ]; then
  echo "[3/8] Installing Ntfy..."
  ARCH=$(uname -m)
  NTFY_VER="2.11.0"
  case "$ARCH" in
    aarch64) NTFY_ARCH="arm64" ;;
    armv7l)  NTFY_ARCH="armv7" ;;
    x86_64)  NTFY_ARCH="amd64" ;;
    *)       echo "  Skipping Ntfy (unsupported arch: $ARCH)" ;;
  esac
  if [ -n "$NTFY_ARCH" ]; then
    NTFY_URL="https://github.com/binwiederhier/ntfy/releases/download/v${NTFY_VER}/ntfy_${NTFY_VER}_linux_${NTFY_ARCH}.tar.gz"
    if curl -fsSL "$NTFY_URL" -o /tmp/ntfy.tar.gz 2>/dev/null; then
      tar -xzf /tmp/ntfy.tar.gz -C /tmp/
      mv /tmp/ntfy_${NTFY_VER}_linux_${NTFY_ARCH}/ntfy /usr/local/bin/ntfy 2>/dev/null || true
      chmod +x /usr/local/bin/ntfy 2>/dev/null || true
      echo "  Ntfy installed"
    else
      echo "  Ntfy download failed — push notifications unavailable"
    fi
  fi
else
  echo "[3/8] Skipping Ntfy (sensor node)"
fi

# ── Step 4: Tailscale ─────────────────────────────────────────
echo "[4/8] Installing Tailscale..."
if ! command -v tailscale &>/dev/null; then
  if curl -fsSL https://tailscale.com/install.sh | sh 2>/dev/null; then
    echo "  Tailscale installed — run 'sudo tailscale up' after install"
  else
    echo "  Tailscale install failed — remote access requires manual setup"
  fi
else
  echo "  Tailscale already installed ($(tailscale version 2>/dev/null | head -1))"
fi

# ── Step 5: Directories and files ────────────────────────────
echo "[5/8] Creating directories and installing files..."
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"
chown -R root:root "$DATA_DIR"
chmod 755 "$DATA_DIR"

cp bin/wifi_scanner.py "$INSTALL_DIR/bin/"

if [ "$ROLE" = "main" ]; then
  mkdir -p "$INSTALL_DIR/web"
  cp bin/notification_server.py "$INSTALL_DIR/bin/" 2>/dev/null || true
  cp bin/aggregation_server.py  "$INSTALL_DIR/bin/" 2>/dev/null || true
  cp bin/generate_report.py     "$INSTALL_DIR/bin/" 2>/dev/null || true
  cp web/index.html             "$INSTALL_DIR/web/"
  cp requirements.txt           "$INSTALL_DIR/"
  cp -r tests/                  "$INSTALL_DIR/" 2>/dev/null || true
fi

# ── Step 6: Credentials and config ────────────────────────────
echo "[6/8] Generating credentials and writing config..."
RANDOM_PASS=$(tr -dc 'A-Za-z0-9!@#$%' < /dev/urandom | head -c 16)
AUTH_HASH=$(python3 -c "import hashlib; print(hashlib.sha256(b'admin:${RANDOM_PASS}').hexdigest())")
INTERFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}' || echo "wlan0")

echo ""
echo "  ┌─────────────────────────────────────┐"
echo "  │  Username: admin                    │"
echo "  │  Password: $RANDOM_PASS  │"
echo "  │                                     │"
echo "  │  SAVE THESE — not shown again       │"
echo "  └─────────────────────────────────────┘"
echo ""

if [ "$ROLE" = "main" ]; then
  cat > "$CONFIG_DIR/config.env" <<EOF
# WiFi/MAP v5.3 — Main Server Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

WIFIMAP_ROLE=main
WIFIMAP_LABEL=main-server
WIFIMAP_INTERFACE=$INTERFACE
WIFIMAP_WS_PORT=$WS_PORT
WIFIMAP_WEB_PORT=$WEB_PORT
WIFIMAP_NOTIFY_PORT=$NOTIFY_PORT
WIFIMAP_AGG_SCANNER_PORT=$AGG_SCANNER_PORT
WIFIMAP_AGG_DASHBOARD_PORT=$AGG_DASHBOARD_PORT

# Authentication — SHA-256 of "username:password"
# Regenerate: python3 -c "import hashlib; print(hashlib.sha256(b'admin:NEWPASS').hexdigest())"
WIFIMAP_AUTH_USER=admin
WIFIMAP_AUTH_HASH=$AUTH_HASH

# Pi-hole hostname resolution (optional — set host if Pi-hole is on another machine)
WIFIMAP_PIHOLE_HOST=
WIFIMAP_PIHOLE_TOKEN=

# Ntfy push notifications (optional)
WIFIMAP_NTFY_HOST=
WIFIMAP_NTFY_PORT=$NTFY_PORT
WIFIMAP_NTFY_TOPIC=wifimap-alerts

# Subnet for device scanning (auto-detected if blank)
WIFIMAP_SUBNET=

# Persistence paths
WIFIMAP_DB_PATH=$DATA_DIR/wifimap.db
WIFIMAP_ZONES_PATH=$DATA_DIR/zones.json
WIFIMAP_AGG_DB_PATH=$DATA_DIR/aggregation.db

# MSP upstream — leave blank on main server
WIFIMAP_UPSTREAM=
EOF

else
  # Sensor node — prompt for main server Tailscale IP
  echo ""
  echo "  Enter the main server Tailscale IP."
  echo "  (Run 'tailscale ip -4' on your Pi 5 to get this)"
  echo "  Example: 100.64.0.2"
  echo ""
  read -rp "  Main server Tailscale IP: " MAIN_IP

  # Determine node label
  echo ""
  read -rp "  Node label (e.g. node-2, node-3): " NODE_LABEL
  NODE_LABEL=${NODE_LABEL:-node-2}

  # Determine scanning interface
  echo ""
  echo "  Available WiFi interfaces:"
  iw dev 2>/dev/null | awk '/Interface/{print "    " $2}' || echo "    wlan0"
  echo ""
  echo "  Use wlan1 if you have a USB WiFi adapter plugged in (recommended)."
  echo "  Use wlan0 if you have no USB adapter."
  read -rp "  Scanning interface [wlan1]: " SCAN_IF
  SCAN_IF=${SCAN_IF:-wlan1}

  cat > "$CONFIG_DIR/config.env" <<EOF
# WiFi/MAP v5.3 — Sensor Node Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

WIFIMAP_ROLE=node
WIFIMAP_LABEL=$NODE_LABEL
WIFIMAP_INTERFACE=$SCAN_IF
WIFIMAP_WS_PORT=$WS_PORT

# Authentication
WIFIMAP_AUTH_USER=admin
WIFIMAP_AUTH_HASH=$AUTH_HASH

# Persistence paths
WIFIMAP_DB_PATH=$DATA_DIR/wifimap.db
WIFIMAP_ZONES_PATH=$DATA_DIR/zones.json

# Main server connection — scanner dials out to aggregation server
WIFIMAP_UPSTREAM=ws://${MAIN_IP}:${AGG_SCANNER_PORT}
EOF
fi

chmod 600 "$CONFIG_DIR/config.env"

# ── Step 7: Systemd services ──────────────────────────────────
echo "[7/8] Installing services..."

# Scanner service (both roles)
cat > /etc/systemd/system/wifimap-scanner.service <<SVCEOF
[Unit]
Description=WiFi/MAP Scanner v5.3
After=network.target tailscaled.service
Wants=network.target

[Service]
Type=simple
User=root
EnvironmentFile=$CONFIG_DIR/config.env
ExecStart=/usr/bin/python3 $INSTALL_DIR/bin/wifi_scanner.py \
  --label \${WIFIMAP_LABEL} \
  --interface \${WIFIMAP_INTERFACE} \
  --port \${WIFIMAP_WS_PORT} \
  --auth-hash \${WIFIMAP_AUTH_HASH} \
  --db-path \${WIFIMAP_DB_PATH} \
  --zones-path \${WIFIMAP_ZONES_PATH} \
  \${WIFIMAP_UPSTREAM:+--upstream \${WIFIMAP_UPSTREAM}}
Restart=on-failure
RestartSec=5
StandardOutput=append:$LOG_DIR/scanner.log
StandardError=append:$LOG_DIR/scanner.log

[Install]
WantedBy=multi-user.target
SVCEOF

if [ "$ROLE" = "main" ]; then

  # Aggregation server
  cat > /etc/systemd/system/wifimap-aggregation.service <<SVCEOF
[Unit]
Description=WiFi/MAP Aggregation Server v5.3
After=network.target tailscaled.service
Wants=network.target

[Service]
Type=simple
User=root
EnvironmentFile=$CONFIG_DIR/config.env
ExecStart=/usr/bin/python3 $INSTALL_DIR/bin/aggregation_server.py \
  --host 0.0.0.0 \
  --scanner-port \${WIFIMAP_AGG_SCANNER_PORT} \
  --dashboard-port \${WIFIMAP_AGG_DASHBOARD_PORT} \
  --db-path \${WIFIMAP_AGG_DB_PATH}
Restart=on-failure
RestartSec=5
StandardOutput=append:$LOG_DIR/aggregation.log
StandardError=append:$LOG_DIR/aggregation.log

[Install]
WantedBy=multi-user.target
SVCEOF

  # Notification bridge
  cat > /etc/systemd/system/wifimap-notify.service <<SVCEOF
[Unit]
Description=WiFi/MAP Notification Bridge v5.3
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=$CONFIG_DIR/config.env
ExecStart=/usr/bin/python3 $INSTALL_DIR/bin/notification_server.py \
  --port \${WIFIMAP_NOTIFY_PORT}
Restart=on-failure
RestartSec=5
StandardOutput=append:$LOG_DIR/notify.log
StandardError=append:$LOG_DIR/notify.log

[Install]
WantedBy=multi-user.target
SVCEOF

  # Web dashboard
  cat > /etc/systemd/system/wifimap-web.service <<SVCEOF
[Unit]
Description=WiFi/MAP Web Dashboard v5.3
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/web
ExecStart=/usr/bin/python3 -m http.server $WEB_PORT
Restart=on-failure
RestartSec=5
StandardOutput=append:$LOG_DIR/web.log
StandardError=append:$LOG_DIR/web.log

[Install]
WantedBy=multi-user.target
SVCEOF

  # Ntfy
  cat > /etc/systemd/system/ntfy.service <<SVCEOF
[Unit]
Description=Ntfy Push Notification Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ntfy serve --listen-http :$NTFY_PORT
Restart=on-failure
RestartSec=5
StandardOutput=append:$LOG_DIR/ntfy.log
StandardError=append:$LOG_DIR/ntfy.log

[Install]
WantedBy=multi-user.target
SVCEOF

fi

# Enable and start services
systemctl daemon-reload

if [ "$ROLE" = "main" ]; then
  systemctl enable wifimap-scanner wifimap-aggregation wifimap-web wifimap-notify 2>/dev/null || true
  systemctl start  wifimap-scanner wifimap-aggregation wifimap-web wifimap-notify 2>/dev/null || true
  systemctl enable ntfy 2>/dev/null || true
  systemctl start  ntfy 2>/dev/null || true
else
  systemctl enable wifimap-scanner 2>/dev/null || true
  systemctl start  wifimap-scanner 2>/dev/null || true
fi

# ── Step 8: Firewall ──────────────────────────────────────────
echo "[8/8] Configuring firewall..."

if [ "$ROLE" = "main" ]; then
  ufw allow "$WEB_PORT/tcp"             comment 'WiFi/MAP Dashboard'           2>/dev/null || true
  ufw allow "$WS_PORT/tcp"             comment 'WiFi/MAP Scanner WS'           2>/dev/null || true
  ufw allow "$AGG_SCANNER_PORT/tcp"    comment 'WiFi/MAP Aggregation Scanners' 2>/dev/null || true
  ufw allow "$AGG_DASHBOARD_PORT/tcp"  comment 'WiFi/MAP Aggregation Dashboard'2>/dev/null || true
  ufw allow "$NOTIFY_PORT/tcp"         comment 'WiFi/MAP Notifications'        2>/dev/null || true
  ufw allow "$NTFY_PORT/tcp"           comment 'Ntfy Push'                     2>/dev/null || true
else
  ufw allow "$WS_PORT/tcp"             comment 'WiFi/MAP Scanner WS'           2>/dev/null || true
fi

# ── Completion banner ─────────────────────────────────────────
LOCAL_IP=$(hostname -I | awk '{print $1}')
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "not connected")

echo ""
echo "=========================================="
if [ "$ROLE" = "main" ]; then
  echo " WiFi/MAP v5.3 — Main Server Ready"
else
  echo " WiFi/MAP v5.3 — Sensor Node Ready"
fi
echo "=========================================="
echo ""

if [ "$ROLE" = "main" ]; then
  echo "  DASHBOARD"
  echo "    Local:     http://${LOCAL_IP}:${WEB_PORT}"
  if [ "$TAILSCALE_IP" != "not connected" ]; then
    echo "    Remote:    http://${TAILSCALE_IP}:${WEB_PORT}"
  fi
  echo ""
  echo "  CREDENTIALS"
  echo "    Username:  admin"
  echo "    Password:  $RANDOM_PASS"
  echo ""
  echo "  TAILSCALE"
  if [ "$TAILSCALE_IP" = "not connected" ]; then
    echo "    Not connected. Run: sudo tailscale up"
    echo "    Then note the IP — sensor nodes need it."
  else
    echo "    IP: ${TAILSCALE_IP}  ← sensor nodes connect to this"
  fi
  echo ""
  echo "  SERVICES RUNNING"
  echo "    wifimap-scanner       (port $WS_PORT)"
  echo "    wifimap-aggregation   (ports $AGG_SCANNER_PORT, $AGG_DASHBOARD_PORT)"
  echo "    wifimap-web           (port $WEB_PORT)"
  echo "    wifimap-notify        (port $NOTIFY_PORT)"
  echo "    ntfy                  (port $NTFY_PORT)"
  echo ""
  echo "  NEXT STEP"
  echo "    Run 'sudo tailscale up' then install sensor nodes."
else
  echo "  NODE: $NODE_LABEL"
  echo "  Scanning interface: $SCAN_IF"
  echo "  Reporting to: ws://${MAIN_IP}:${AGG_SCANNER_PORT}"
  echo ""
  echo "  TAILSCALE"
  if [ "$TAILSCALE_IP" = "not connected" ]; then
    echo "    Not connected. Run: sudo tailscale up"
  else
    echo "    IP: ${TAILSCALE_IP}"
  fi
  echo ""
  echo "  SERVICES RUNNING"
  echo "    wifimap-scanner (upstream mode)"
  echo ""
  echo "  NEXT STEP"
  echo "    Run 'sudo tailscale up' then check the main"
  echo "    server dashboard — this node should appear."
fi

echo "  LOGS"
echo "    tail -f $LOG_DIR/scanner.log"
echo ""

# ── Reboot prompt ─────────────────────────────────────────────
echo "=========================================="
echo " Reboot Recommended"
echo "=========================================="
echo ""
echo "  A reboot ensures any kernel updates take"
echo "  effect before the device goes into service."
echo ""
read -rp "  Reboot now? [Y/n]: " REBOOT_CHOICE
REBOOT_CHOICE=${REBOOT_CHOICE:-Y}

if [[ "$REBOOT_CHOICE" =~ ^[Yy]$ ]]; then
  echo ""
  echo "  Rebooting in 3 seconds..."
  sleep 3
  reboot
else
  echo ""
  echo "  Skipped. When ready: sudo reboot"
  echo ""
fi
