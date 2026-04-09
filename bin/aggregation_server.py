#!/usr/bin/env python3
"""
aggregation_server.py  —  WiFi/MAP Aggregation Server  v5.3
=============================================================
Central hub for MSP multi-site deployments.

Architecture
------------
                    Tailscale network
                         │
  Site A Pi ─────────────┤
  Site B Pi ─────────────┼──► Aggregation Server ◄── MSP Dashboard browser
  Site C Pi ─────────────┤         │
                         │    SQLite registry
                         │    (site config,
                         │     status history)

Two WebSocket servers run concurrently:

  SCANNER PORT (default 8766)
    Pi scanners connect here on startup (outbound — no inbound firewall needed).
    Each scanner identifies itself with a 'scanner-<label>' subprotocol.
    The aggregation server reads their message stream, extracts summary
    data (device count, alert count, last event), and pushes site_status
    updates to all connected dashboards.

  DASHBOARD PORT (default 8767)
    MSP dashboard browser connects here.
    Receives site_status push messages for the overview panel.
    When operator drills into a site, sends a drill_in message.
    Server then proxies the full scanner WebSocket bidirectionally
    so the existing dashboard protocol works unchanged.

Message types
-------------
To dashboard:
  site_list     — all registered sites and their current status
  site_status   — pushed immediately when any site's status changes
  site_error    — site connection lost or error

From dashboard:
  drill_in      — { siteId } — proxy this site's scanner to this dashboard
  drill_out     — end proxied connection, return to overview

No changes to wifi_scanner.py are needed — it just connects outbound
to the scanner port with a 'scanner-<label>' subprotocol.
"""

import asyncio
import websockets
import json
import logging
import argparse
import sqlite3
import time
import re
from pathlib import Path
from typing import Optional
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-7s] %(name)s — %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('wifimap.aggregation')


# ── Config ────────────────────────────────────────────────────
class Config:
    DEFAULT_HOST           = '0.0.0.0'
    DEFAULT_SCANNER_PORT   = 8766
    DEFAULT_DASHBOARD_PORT = 8767
    DEFAULT_DB_PATH        = Path('/var/lib/wifimap/aggregation.db')
    SITE_TIMEOUT_SECS      = 30   # mark site offline after this many seconds
    STATUS_PUSH_DEBOUNCE   = 0.5  # seconds between status pushes per site
    MAX_EVENT_HISTORY      = 50   # events kept per site in memory


# ── Input validation ──────────────────────────────────────────
def validate_label(label) -> str:
    if not label or not isinstance(label, str): return 'unknown'
    return re.sub(r'[^a-zA-Z0-9\-_.]', '', str(label))[:32] or 'unknown'

def sanitise(s) -> str:
    if s is None: return ''
    return re.sub(r'[\x00-\x1f\x7f]', '', str(s))[:256]


# ── Site registry database ────────────────────────────────────
class SiteDatabase:
    """
    Persists the site registry so the aggregation server remembers
    all known sites across restarts. Schema is intentionally minimal —
    full event history lives in each scanner's own database.
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute('PRAGMA journal_mode=WAL')
        self._conn.executescript('''
            CREATE TABLE IF NOT EXISTS sites (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                label       TEXT NOT NULL,
                first_seen  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                last_seen   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                status      TEXT NOT NULL DEFAULT 'offline'
            );
        ''')
        self._conn.commit()
        log.info(f'SiteDatabase: connected to {self.db_path}')

    def upsert_site(self, site_id: str, label: str):
        self._conn.execute('''
            INSERT INTO sites (id, name, label, last_seen, status)
            VALUES (?, ?, ?, strftime('%s','now'), 'online')
            ON CONFLICT(id) DO UPDATE SET
                last_seen = excluded.last_seen,
                status    = 'online'
        ''', (site_id, label, label))
        self._conn.commit()

    def mark_offline(self, site_id: str):
        self._conn.execute('''
            UPDATE sites SET status='offline', last_seen=strftime('%s','now')
            WHERE id=?
        ''', (site_id,))
        self._conn.commit()

    def get_all_sites(self) -> list:
        rows = self._conn.execute('SELECT * FROM sites ORDER BY label').fetchall()
        return [dict(row) for row in rows]

    def close(self):
        if self._conn: self._conn.close()


# ── Shared aggregation state ──────────────────────────────────
class AggState:
    def __init__(self):
        # scanner_label → WebSocket connection
        self.scanner_connections: dict = {}

        # scanner_label → current site summary
        self.site_summaries: dict = {}

        # All connected dashboard WebSocket connections
        self.dashboard_connections: set = set()

        # dashboard ws → scanner_label they're currently drilling into (or None)
        self.drill_targets: dict = {}

        # scanner_label → set of dashboard ws connections being proxied
        self.proxy_targets: dict = defaultdict(set)

        # Debounce timers per site
        self.push_timers: dict = {}

agg = AggState()
db: Optional[SiteDatabase] = None


# ── Site summary helpers ──────────────────────────────────────
def make_summary(label: str) -> dict:
    """Create a blank site summary for a newly connected scanner."""
    return {
        'siteId':      label,
        'label':       label,
        'status':      'online',
        'deviceCount': 0,
        'alertCount':  0,
        'lastEvent':   None,
        'lastSeen':    int(time.time() * 1000),
    }

def extract_summary_update(label: str, msg: dict) -> Optional[dict]:
    """
    Extract any summary-relevant information from a scanner message.
    Returns a partial update dict if anything changed, else None.
    Only security events and device counts affect the MSP overview.
    """
    msg_type = msg.get('type', '')
    update = {}

    if msg_type == 'device':
        # Recount online devices from what we know
        # We don't maintain a full device list — just track the count delta
        current = agg.site_summaries.get(label, {})
        if msg.get('online') and not current.get('_was_online_' + sanitise(msg.get('mac',''))):
            update['deviceCount'] = current.get('deviceCount', 0) + 1
            current['_was_online_' + sanitise(msg.get('mac',''))] = True
        elif not msg.get('online') and current.get('_was_online_' + sanitise(msg.get('mac',''))):
            update['deviceCount'] = max(0, current.get('deviceCount', 1) - 1)
            current['_was_online_' + sanitise(msg.get('mac',''))] = False

    elif msg_type in ('rogue_ap', 'deauth_attack', 'mac_spoof', 'new_device'):
        current = agg.site_summaries.get(label, {})
        update['alertCount'] = current.get('alertCount', 0) + 1
        update['lastEvent'] = {
            'severity': sanitise(msg.get('severity', 'critical')),
            'type':     sanitise(msg_type),
            'title':    sanitise(msg.get('title') or msg_type.replace('_', ' ').title()),
            'ts':       int(time.time() * 1000),
        }

    elif msg_type == 'hello':
        # Scanner just connected — mark online
        update['status']  = 'online'
        update['lastSeen'] = int(time.time() * 1000)

    return update if update else None


# ── Push site status to all dashboards ───────────────────────
async def push_site_status(label: str):
    """Push current site summary to all connected dashboard clients."""
    summary = agg.site_summaries.get(label)
    if not summary: return
    # Strip internal tracking keys before sending
    clean = {k: v for k, v in summary.items() if not k.startswith('_')}
    msg = json.dumps({'type': 'site_status', **clean})
    dead = set()
    for ws in agg.dashboard_connections:
        if agg.drill_targets.get(ws) == label:
            continue  # this dashboard is drilling into this site — don't overlap
        try:
            await ws.send(msg)
        except Exception:
            dead.add(ws)
    agg.dashboard_connections.difference_update(dead)


async def push_site_status_debounced(label: str):
    """Debounced push — coalesces rapid updates into one push per site."""
    if label in agg.push_timers:
        agg.push_timers[label].cancel()
    loop = asyncio.get_event_loop()
    agg.push_timers[label] = loop.call_later(
        Config.STATUS_PUSH_DEBOUNCE,
        lambda: asyncio.ensure_future(push_site_status(label))
    )


async def push_site_list(ws):
    """Send full site list to a newly connected dashboard."""
    sites = db.get_all_sites() if db else []
    # Merge with in-memory summaries for live status
    site_map = {s['id']: s for s in sites}
    for label, summary in agg.site_summaries.items():
        if label not in site_map:
            site_map[label] = {'id': label, 'label': label, 'name': label}
        clean = {k: v for k, v in summary.items() if not k.startswith('_')}
        site_map[label].update(clean)
    msg = json.dumps({'type': 'site_list', 'sites': list(site_map.values())})
    try:
        await ws.send(msg)
    except Exception:
        pass


# ── Scanner connection handler ────────────────────────────────
async def handle_scanner(ws):
    """
    Handle a Pi scanner connecting to the aggregation server.

    Label identification: the scanner sends a 'hello' message as its
    first message after connecting, which contains the label field.
    This is more reliable than subprotocol negotiation across different
    WebSocket library versions and network configurations.

    The hello message format (from MessageBuilder.hello):
      { "type": "hello", "label": "<site-label>", "version": 1, ... }
    """
    addr = ws.remote_address

    # Wait for the hello message to identify this scanner
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
        msg = json.loads(raw)
    except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as e:
        log.warning(f'Scanner from {addr} did not send hello within 10s — rejecting ({e})')
        await ws.close(code=4400, reason='Expected hello message')
        return

    if msg.get('type') != 'hello' or not msg.get('label'):
        log.warning(f'Scanner from {addr} sent unexpected first message: {msg.get("type")} — rejecting')
        await ws.close(code=4400, reason='Expected hello message with label')
        return

    label = validate_label(msg['label'])
    if label == 'unknown':
        log.warning(f'Scanner from {addr} sent invalid label — rejecting')
        await ws.close(code=4400, reason='Invalid label')
        return

    log.info(f'Scanner connected: {label} from {addr}')

    # Register site
    agg.scanner_connections[label] = ws
    if label not in agg.site_summaries:
        agg.site_summaries[label] = make_summary(label)
    else:
        agg.site_summaries[label]['status']   = 'online'
        agg.site_summaries[label]['lastSeen'] = int(time.time() * 1000)

    if db:
        db.upsert_site(label, label)

    # Process the hello message for summary updates then push status
    update = extract_summary_update(label, msg)
    if update:
        agg.site_summaries[label].update(update)
    await push_site_status_debounced(label)

    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            # Update site summary from this message
            update = extract_summary_update(label, msg)
            if update:
                agg.site_summaries[label].update(update)
                await push_site_status_debounced(label)

            # Proxy message to any dashboards drilling into this site
            if agg.proxy_targets.get(label):
                dead = set()
                for dash_ws in agg.proxy_targets[label]:
                    try:
                        await dash_ws.send(raw)
                    except Exception:
                        dead.add(dash_ws)
                agg.proxy_targets[label].difference_update(dead)

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        log.debug(f'handle_scanner [{label}]: {e}')
    finally:
        agg.scanner_connections.pop(label, None)
        if label in agg.site_summaries:
            agg.site_summaries[label]['status'] = 'offline'
        if db:
            db.mark_offline(label)
        await push_site_status(label)
        # Notify any drilling dashboards that the site went offline
        for dash_ws in list(agg.proxy_targets.get(label, set())):
            try:
                await dash_ws.send(json.dumps({'type': 'site_error', 'siteId': label, 'reason': 'Scanner disconnected'}))
            except Exception:
                pass
        agg.proxy_targets.pop(label, None)
        log.info(f'Scanner disconnected: {label}')


# ── Dashboard connection handler ──────────────────────────────
async def handle_dashboard(ws):
    """
    Handle a browser dashboard connecting to the aggregation server.
    Sends site_list on connect, then pushes site_status on changes.
    Handles drill_in / drill_out messages to proxy scanner connections.
    """
    log.info(f'Dashboard connected: {ws.remote_address}')
    agg.dashboard_connections.add(ws)
    agg.drill_targets[ws] = None

    try:
        # Send current site list immediately on connect
        await push_site_list(ws)

        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get('type', '')

            if msg_type == 'drill_in':
                # Dashboard wants to drill into a specific site
                site_id = validate_label(msg.get('siteId', ''))
                prev    = agg.drill_targets.get(ws)

                # Stop proxying previous site
                if prev and prev in agg.proxy_targets:
                    agg.proxy_targets[prev].discard(ws)

                if site_id and site_id in agg.scanner_connections:
                    agg.drill_targets[ws] = site_id
                    agg.proxy_targets[site_id].add(ws)
                    log.info(f'Dashboard drilling into: {site_id}')
                    # Send confirmation so dashboard knows proxy is active
                    await ws.send(json.dumps({'type': 'drill_active', 'siteId': site_id}))
                else:
                    await ws.send(json.dumps({'type': 'site_error', 'siteId': site_id, 'reason': 'Site not connected'}))

            elif msg_type == 'drill_out':
                # Dashboard returning to overview
                prev = agg.drill_targets.get(ws)
                if prev and prev in agg.proxy_targets:
                    agg.proxy_targets[prev].discard(ws)
                agg.drill_targets[ws] = None
                log.info(f'Dashboard returned to overview')
                await push_site_list(ws)

            elif agg.drill_targets.get(ws):
                # Message from dashboard while drilling — forward to scanner
                target_label  = agg.drill_targets[ws]
                scanner_ws    = agg.scanner_connections.get(target_label)
                if scanner_ws:
                    try:
                        await scanner_ws.send(raw)
                    except Exception as e:
                        log.warning(f'Forward to scanner [{target_label}] failed: {e}')

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        log.debug(f'handle_dashboard: {e}')
    finally:
        agg.dashboard_connections.discard(ws)
        prev = agg.drill_targets.pop(ws, None)
        if prev and prev in agg.proxy_targets:
            agg.proxy_targets[prev].discard(ws)
        log.info(f'Dashboard disconnected: {ws.remote_address}')


# ── Site timeout watchdog ─────────────────────────────────────
async def watchdog_loop():
    """
    Periodically mark sites offline if their scanner hasn't sent
    a message recently. Handles cases where the TCP connection
    drops without a clean WebSocket close.
    """
    while True:
        await asyncio.sleep(10)
        now = int(time.time() * 1000)
        timeout_ms = Config.SITE_TIMEOUT_SECS * 1000
        for label, summary in agg.site_summaries.items():
            if summary.get('status') == 'online':
                last = summary.get('lastSeen', now)
                if now - last > timeout_ms and label not in agg.scanner_connections:
                    log.warning(f'Watchdog: marking {label} offline (timeout)')
                    summary['status'] = 'offline'
                    if db: db.mark_offline(label)
                    await push_site_status(label)


# ── Arg parser ────────────────────────────────────────────────
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='WiFi/MAP Aggregation Server v5.3')
    p.add_argument('--host',            default=Config.DEFAULT_HOST)
    p.add_argument('--scanner-port',    type=int, default=Config.DEFAULT_SCANNER_PORT,
                   help='Port Pi scanners connect to (default 8766)')
    p.add_argument('--dashboard-port',  type=int, default=Config.DEFAULT_DASHBOARD_PORT,
                   help='Port MSP dashboard connects to (default 8767)')
    p.add_argument('--db-path',         default=str(Config.DEFAULT_DB_PATH),
                   help='SQLite site registry path')
    p.add_argument('--debug',           action='store_true')
    return p


# ── Main ──────────────────────────────────────────────────────
async def main():
    global db
    args = build_arg_parser().parse_args()
    if args.debug: logging.getLogger().setLevel(logging.DEBUG)

    db = SiteDatabase(Path(args.db_path))
    db.connect()

    # Pre-load known sites from database — mark all offline until they reconnect
    known = db.get_all_sites()
    for site in known:
        label = site['label']
        agg.site_summaries[label] = make_summary(label)
        agg.site_summaries[label]['status'] = 'offline'

    log.info('=' * 55)
    log.info('WiFi/MAP Aggregation Server v5.3')
    log.info(f'  Scanner port:   {args.host}:{args.scanner_port}')
    log.info(f'  Dashboard port: {args.host}:{args.dashboard_port}')
    log.info(f'  Database:       {args.db_path}')
    log.info(f'  Known sites:    {len(known)}')
    log.info('=' * 55)

    scanner_server   = await websockets.serve(handle_scanner,  args.host, args.scanner_port)
    dashboard_server = await websockets.serve(handle_dashboard, args.host, args.dashboard_port)

    log.info(f'Scanner server ready at   ws://{args.host}:{args.scanner_port}')
    log.info(f'Dashboard server ready at ws://{args.host}:{args.dashboard_port}')

    await asyncio.gather(
        scanner_server.wait_closed(),
        dashboard_server.wait_closed(),
        watchdog_loop(),
    )

    db.close()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info('Shutdown')
    except Exception as e:
        log.error(f'Fatal: {e}', exc_info=True)
        exit(1)
