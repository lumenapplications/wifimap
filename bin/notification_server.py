#!/usr/bin/env python3
"""
notification_server.py  —  WiFi/MAP Local Notification Server  v5.3
====================================================================
Runs alongside wifi_scanner.py on the Pi.
Receives security events via WebSocket from the scanner and
forwards them to the local Ntfy instance as push notifications.

Also acts as a bridge for the web app to send notifications
even when it can't reach Ntfy directly (e.g. CORS restrictions).

Architecture:
  EventReceiver   — receives events from scanner via WebSocket
  NtfyClient      — sends push notifications to local Ntfy
  HTTPBridge      — simple HTTP endpoint for web app to POST events
  Config          — all settings

Install Ntfy on Raspberry Pi:
  # ARM64 (Pi 4, Pi 5):
  curl -L https://github.com/binwiederhier/ntfy/releases/download/v2.11.0/ntfy_2.11.0_linux_arm64.tar.gz | tar xz
  sudo mv ntfy /usr/local/bin/
  ntfy serve --listen-http :7777

  # Or via apt (may be older version):
  sudo apt install ntfy

Subscribe on phone:
  1. Install Ntfy app (iOS / Android)
  2. Add server: http://<pi-ip>:7777
  3. Subscribe to topic: wifimap-alerts

Usage:
  python3 notification_server.py
  python3 notification_server.py --ntfy-host localhost --ntfy-port 7777 --topic wifimap-alerts

Run both scanner and notification server:
  python3 wifi_scanner.py --x 0.3 --y 0.4 --label pi-node-1 &
  python3 notification_server.py &

Systemd service (recommended):
  See README for full service configuration.
"""

import asyncio
import json
import logging
import argparse
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


# =============================================================
# LOGGER
# =============================================================

logging.basicConfig(
    level   = logging.INFO,
    format  = '%(asctime)s [%(levelname)-7s] %(name)s — %(message)s',
    datefmt = '%H:%M:%S',
)
log = logging.getLogger('wifimap.notify')


# =============================================================
# CONFIG
# =============================================================

class Config:
    # Ntfy server settings
    NTFY_HOST     = 'localhost'
    NTFY_PORT     = 7777
    NTFY_TOPIC    = 'wifimap-alerts'
    NTFY_TOKEN    = None     # Optional auth token for protected Ntfy instance

    # HTTP bridge — allows web app to POST events here
    BRIDGE_HOST   = '0.0.0.0'
    BRIDGE_PORT   = 8766

    # Scanner WebSocket (to receive security events from scanner)
    SCANNER_WS    = 'ws://localhost:8765'

    # Rate limiting — max notifications per minute per severity
    RATE_LIMIT    = { 'critical': 60, 'warning': 20, 'info': 5 }

    # Dashboard URL — used in Ntfy action buttons for critical alerts.
    # Leave blank to omit the action button.
    DASHBOARD_URL = ''

    # Maximum POST body size accepted by the HTTP bridge.
    # Protects against request bomb attacks on the notification endpoint.
    MAX_BODY_BYTES = 65_536  # 64 KB

    # Cooldown per event type (seconds) — prevents duplicate alerts
    EVENT_COOLDOWN = {
        'new_device':    30,
        'rogue_ap':      60,
        'mac_spoof':     30,
        'zone_violation':15,
        'deauth_attack': 10,
    }


# =============================================================
# ARGUMENT PARSER
# =============================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='WiFi/MAP Notification Server v5.3')
    p.add_argument('--ntfy-host',    default=Config.NTFY_HOST,   help='Ntfy server host')
    p.add_argument('--ntfy-port',    type=int, default=Config.NTFY_PORT, help='Ntfy server port')
    p.add_argument('--ntfy-topic',   default=Config.NTFY_TOPIC,  help='Ntfy topic')
    p.add_argument('--ntfy-token',   default=None,               help='Ntfy auth token (if protected)')
    p.add_argument('--bridge-host',  default=Config.BRIDGE_HOST, help='HTTP bridge bind address')
    p.add_argument('--bridge-port',  type=int, default=Config.BRIDGE_PORT, help='HTTP bridge port')
    p.add_argument('--scanner-ws',   default=Config.SCANNER_WS,  help='Scanner WebSocket URL')
    p.add_argument('--dashboard-url',  default=Config.DASHBOARD_URL, help='Dashboard URL for Ntfy action buttons (e.g. http://192.168.1.x:8080). Leave blank to omit.')
    p.add_argument('--debug',        action='store_true')
    return p


# =============================================================
# NTFY CLIENT
# =============================================================

class NtfyClient:
    """
    Sends push notifications to a local or remote Ntfy instance.

    Priority mapping (Ntfy levels):
      min    — lowest, often no sound
      low    — quiet notification
      default— normal
      high   — loud, bypasses DND on most phones
      urgent — max priority, always audible, may override DND

    We map our severity tiers to Ntfy priorities:
      critical → urgent
      warning  → high
      info     → default
    """

    PRIORITY_MAP = {
        'critical': 'urgent',
        'warning':  'high',
        'info':     'default',
    }

    EMOJI_MAP = {
        'critical':    '🚨',
        'warning':     '⚠️',
        'info':        'ℹ️',
        'new_device':  '📱',
        'rogue_ap':    '📡',
        'mac_spoof':   '🔒',
        'zone_violation': '📍',
        'deauth_attack': '⚡',
    }

    def __init__(self, host: str, port: int, topic: str,
                 token: Optional[str] = None, dashboard_url: str = ''):
        self.host          = host
        self.port          = port
        self.topic         = topic
        self.token         = token
        self.dashboard_url = dashboard_url.strip()
        self.url           = f'http://{host}:{port}/{topic}'

        # Rate limiting state — timestamps of recent sends per severity
        self.send_history: dict = { s: [] for s in ['critical', 'warning', 'info'] }

        # Cooldown state — last send timestamp per event type
        self.last_sent: dict = {}

    def _is_rate_limited(self, severity: str) -> bool:
        """Check if we've sent too many notifications at this severity level recently."""
        limit   = Config.RATE_LIMIT.get(severity, 10)
        history = self.send_history.get(severity, [])
        now     = time.time()

        # Prune history older than 60 seconds
        self.send_history[severity] = [t for t in history if now - t < 60]

        if len(self.send_history[severity]) >= limit:
            log.warning(f'NtfyClient: rate limit hit for severity={severity} ({limit}/min)')
            return True
        return False

    def _is_on_cooldown(self, event_type: str) -> bool:
        """Check if this event type was sent recently (cooldown period)."""
        cooldown  = Config.EVENT_COOLDOWN.get(event_type, 0)
        last_time = self.last_sent.get(event_type, 0)
        if time.time() - last_time < cooldown:
            log.debug(f'NtfyClient: cooldown active for {event_type}')
            return True
        return False

    def send(self, event: dict) -> bool:
        """
        Send a notification for a security event.

        Expected event fields:
          severity    — 'critical' | 'warning' | 'info'
          type        — event type string
          title       — short notification title
          description — longer body text
          location    — where the event occurred
          device      — optional device dict
          timestamp   — Unix milliseconds

        Returns True if sent successfully.
        """
        if not REQUESTS_AVAILABLE:
            log.error('NtfyClient: requests library not installed (pip3 install requests)')
            return False

        severity   = event.get('severity', 'info')
        event_type = event.get('type', 'unknown')

        # Validate severity and event_type — these flow into HTTP headers
        # Only allow known values to prevent header injection
        if severity not in ('critical', 'warning', 'info'):
            severity = 'info'
        if not re.match(r'^[a-z_]{1,40}$', str(event_type)):
            event_type = 'unknown'

        # Check rate limit and cooldown
        if self._is_rate_limited(severity):
            return False
        if self._is_on_cooldown(event_type):
            return False

        # Build notification content
        title     = event.get('title', 'WiFi/MAP Alert')
        emoji     = self.EMOJI_MAP.get(event_type, self.EMOJI_MAP.get(severity, ''))
        priority  = self.PRIORITY_MAP.get(severity, 'default')
        timestamp = datetime.fromtimestamp(event.get('timestamp', time.time()*1000) / 1000)
        time_str  = timestamp.strftime('%H:%M:%S')

        # Build body with all relevant info
        body_lines = [event.get('description', '')]
        if event.get('location'):
            body_lines.append(f'Location: {event["location"]}')
        if event.get('device'):
            dev = event['device']
            body_lines.append(f'Device: {dev.get("name", dev.get("mac", "unknown"))} ({dev.get("ip", "?")})')
        body_lines.append(f'Time: {time_str}')
        body = '\n'.join(filter(None, body_lines))

        # Build Ntfy headers
        headers = {
            'Title':    f'{emoji} {title}',
            'Priority': priority,
            'Tags':     f'wifi,security,{event_type}',
            'Content-Type': 'text/plain',
        }

        # Add auth token if configured
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'

        # Add action button for critical events — only if dashboard URL is configured
        if severity == 'critical' and event.get('device') and self.dashboard_url:
            headers['Actions'] = f'view, Open Dashboard, {self.dashboard_url}'

        try:
            res = requests.post(
                self.url,
                data    = body.encode('utf-8'),
                headers = headers,
                timeout = 5,
            )
            if res.status_code in (200, 201):
                log.info(f'NtfyClient: sent [{severity}] "{title}"')
                # Record send for rate limiting
                self.send_history[severity].append(time.time())
                self.last_sent[event_type] = time.time()
                return True
            else:
                log.warning(f'NtfyClient: Ntfy returned HTTP {res.status_code}: {res.text[:100]}')
                return False

        except requests.exceptions.ConnectionError:
            log.warning(f'NtfyClient: cannot reach Ntfy at {self.url} — is Ntfy running?')
            return False
        except requests.exceptions.Timeout:
            log.warning('NtfyClient: Ntfy request timed out')
            return False
        except Exception as e:
            log.error(f'NtfyClient: unexpected error — {e}')
            return False

    def test(self) -> bool:
        """Send a test notification to verify connectivity."""
        return self.send({
            'severity':    'info',
            'type':        'test',
            'title':       'WiFi/MAP notification test',
            'description': 'Notification system is active and connected.',
            'location':    'System',
            'timestamp':   time.time() * 1000,
        })


# =============================================================
# HTTP BRIDGE
# =============================================================

class NotificationBridgeHandler(BaseHTTPRequestHandler):
    """
    Simple HTTP server that accepts POST requests from the web app
    and forwards them to the Ntfy client.

    The web app POSTs JSON security events to this endpoint when
    it wants to trigger a notification. This decouples notification
    sending from the scanner process.

    Endpoints:
      POST /notify    — send a notification
      POST /test      — send a test notification
      GET  /status    — check server status
      OPTIONS /notify — CORS preflight
    """

    ntfy_client: NtfyClient = None   # set by server setup

    def log_message(self, format, *args):
        # Suppress default request logging, use our logger instead
        log.debug(f'HTTP: {self.address_string()} — {format % args}')

    def _cors_headers(self):
        """Add CORS headers so the web app (any origin) can POST here."""
        self.send_header('Access-Control-Allow-Origin',  '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._cors_headers()
            self.end_headers()
            status = {
                'status':    'running',
                'ntfy_url':  self.ntfy_client.url if self.ntfy_client else None,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            self.wfile.write(json.dumps(status).encode())
        else:
            self.send_error(404)

    def do_POST(self):
        """Handle notification POST from web app."""
        try:
            length = int(self.headers.get('Content-Length', 0))
        except (TypeError, ValueError):
            self.send_error(400, 'Invalid Content-Length')
            return

        if length == 0:
            self.send_error(400, 'Empty request body')
            return

        if length > Config.MAX_BODY_BYTES:
            self.send_error(413, f'Request body too large (max {Config.MAX_BODY_BYTES} bytes)')
            return

        try:
            body = self.rfile.read(length)
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.send_error(400, f'Invalid JSON: {e}')
            return

        # Route to appropriate handler
        if self.path == '/notify':
            if not self.ntfy_client:
                self.send_error(503, 'Ntfy client not configured')
                return

            ok = self.ntfy_client.send(data)
            self.send_response(200 if ok else 503)
            self.send_header('Content-Type', 'application/json')
            self._cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'sent': ok}).encode())

        elif self.path == '/test':
            ok = self.ntfy_client.test() if self.ntfy_client else False
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'sent': ok}).encode())

        else:
            self.send_error(404)


def start_http_bridge(host: str, port: int, ntfy_client: NtfyClient):
    """Start the HTTP bridge server in a background thread."""
    NotificationBridgeHandler.ntfy_client = ntfy_client
    server = HTTPServer((host, port), NotificationBridgeHandler)
    log.info(f'HTTP bridge listening on http://{host}:{port}')
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# =============================================================
# SCANNER EVENT RECEIVER
# =============================================================

async def receive_scanner_events(scanner_ws_url: str, ntfy_client: NtfyClient):
    """
    Connect to the scanner's WebSocket and listen for security events.
    The scanner emits security-relevant messages (rogue_ap, deauth_attack)
    that this service translates into push notifications.

    Reconnects automatically on disconnect.
    """
    if not WEBSOCKETS_AVAILABLE:
        log.error('websockets library not installed (pip3 install websockets)')
        return

    # Security event types that should trigger notifications
    SECURITY_TYPES = {
        'rogue_ap',
        'deauth_attack',
        'mac_spoof',
        'new_device',
        'device_offline_restricted',
    }

    while True:
        try:
            log.info(f'EventReceiver: connecting to scanner at {scanner_ws_url}')
            async with websockets.connect(scanner_ws_url) as ws:
                log.info('EventReceiver: connected to scanner')
                async for raw in ws:
                    try:
                        data = json.loads(raw)
                        msg_type = data.get('type', '')

                        if msg_type == 'rogue_ap':
                            ntfy_client.send({
                                'severity':    'critical',
                                'type':        'rogue_ap',
                                'title':       'Rogue access point detected',
                                'description': f'SSID: "{data.get("ssid","unknown")}" · BSSID: {data.get("bssid","?")} · {data.get("rssi","?")}dBm',
                                'location':    f'Seen by {data.get("pi_label","?")}',
                                'timestamp':   time.time() * 1000,
                            })

                        elif msg_type == 'deauth_attack':
                            ntfy_client.send({
                                'severity':    'critical',
                                'type':        'deauth_attack',
                                'title':       'WiFi deauthentication attack detected',
                                'description': f'{data.get("count","?")} deauth frames in {data.get("window","?")}s',
                                'location':    f'Interface: {data.get("interface","?")} · Pi: {data.get("pi_label","?")}',
                                'timestamp':   time.time() * 1000,
                            })

                        elif msg_type == 'security_event':
                            # Generic security event forwarded from scanner
                            ntfy_client.send(data.get('event', data))

                    except json.JSONDecodeError:
                        log.debug('EventReceiver: non-JSON message received')
                    except Exception as e:
                        log.warning(f'EventReceiver: error processing message — {e}')

        except Exception as e:
            log.warning(f'EventReceiver: disconnected ({e}), retrying in 5s...')
            await asyncio.sleep(5)


# =============================================================
# MAIN
# =============================================================

async def main():
    args = build_arg_parser().parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info('=' * 55)
    log.info('WiFi/MAP Notification Server v5.3')
    log.info(f'  Ntfy:         http://{args.ntfy_host}:{args.ntfy_port}/{args.ntfy_topic}')
    log.info(f'  HTTP bridge:  http://{args.bridge_host}:{args.bridge_port}')
    log.info(f'  Scanner WS:   {args.scanner_ws}')
    log.info('=' * 55)

    # Create Ntfy client
    ntfy = NtfyClient(
        host          = args.ntfy_host,
        port          = args.ntfy_port,
        topic         = args.ntfy_topic,
        token         = args.ntfy_token,
        dashboard_url = args.dashboard_url,
    )

    # Send startup notification
    log.info('Sending startup notification...')
    if ntfy.test():
        log.info('Ntfy connection verified ✓')
    else:
        log.warning('Ntfy test failed — check Ntfy is running and topic is correct')

    # Start HTTP bridge in background thread
    start_http_bridge(args.bridge_host, args.bridge_port, ntfy)

    # Connect to scanner and forward security events
    await receive_scanner_events(args.scanner_ws, ntfy)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info('Shutdown by user')
