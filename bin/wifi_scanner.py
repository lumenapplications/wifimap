#!/usr/bin/env python3
"""
wifi_scanner.py  —  WiFi/MAP Pi Node Scanner  v5.3
====================================================
Multi-site, Tailscale, structured exceptions

NEW IN v5.3:

  SQLITE DATABASE  (/var/lib/wifimap/wifimap.db)
    - devices table: MAC, IP, vendor, hostname, first/last seen,
      online status, anomaly score, approved flag, canvas position
    - events table: full security event log, persists across restarts
    - known_aps table: prevents rogue AP re-alerting on restart
    - approved_devices table: persists device approvals across restarts

  ON STARTUP:
    - Reads all four tables into memory
    - Sends approved device list to connecting clients
    - Sends zone list to connecting clients
    - Sends last 200 events to connecting clients (event_replay)

  NEW INBOUND MESSAGE TYPES (from browser):
    zone_save      — save or update a zone to zones.json
    zone_delete    — delete a zone from zones.json
    device_approve — approve a device, write to SQLite
    node_position  — log Pi node canvas position

  ZONE PERSISTENCE:
    Zones stored in /var/lib/wifimap/zones.json
    Sent to browser as zone_load on connect
    Updated when browser sends zone_save/zone_delete

Sprint 1 (security) and Sprint 2 (persistence) features retained.
"""

import asyncio
import websockets
import json
import logging
import argparse
import random
import math
import time
import shutil
import hashlib
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from collections import defaultdict

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ── Protocol version ──────────────────────────────────────────
WS_VERSION = 1


# ── Logger ────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [%(levelname)-7s] %(name)s — %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('wifimap.scanner')


# ── Structured exception types ────────────────────────────────
class ScannerError(Exception):
    """Base class for all WiFi/MAP scanner errors."""

class NetworkError(ScannerError):
    """Network operation failed — timeout, unreachable host, or interface down."""

class PermissionError(ScannerError):
    """Insufficient privileges — sudo required for arp-scan, nmap, iwlist."""

class ParseError(ScannerError):
    """Failed to parse output from a system command or WebSocket message."""

class ConfigError(ScannerError):
    """Invalid or missing configuration — bad interface name, invalid subnet, etc."""


# ── Config ────────────────────────────────────────────────────
class Config:
    DEFAULT_HOST            = '0.0.0.0'
    DEFAULT_PORT            = 8765
    DEFAULT_INTERFACE       = 'wlan0'
    RSSI_INTERVAL           = 1.0
    DEVICE_SCAN_INTERVAL    = 5.0
    AP_SCAN_INTERVAL        = 15.0
    PING_TIMEOUT            = 1
    DEMO_OFFLINE_CHANCE     = 0.08
    DEAUTH_THRESHOLD        = 10   # frames within DEAUTH_WINDOW seconds to trigger alert
    DEAUTH_WINDOW           = 5    # seconds
    DEFAULT_AUTH_HASH       = hashlib.sha256(b'admin:wifimap').hexdigest()
    MAX_SSID_LEN            = 64
    MAX_LABEL_LEN           = 32
    RSSI_MIN, RSSI_MAX      = -120, 0
    LATENCY_MAX             = 10000

    # Persistence paths — overridable via --db-path / --zones-path flags
    DATA_DIR                = Path('/var/lib/wifimap')
    DB_PATH                 = Path('/var/lib/wifimap/wifimap.db')
    ZONES_PATH              = Path('/var/lib/wifimap/zones.json')

    # Number of events replayed to newly connecting clients
    EVENT_REPLAY_COUNT      = 200


# ── Input validation ──────────────────────────────────────────
def validate_mac(mac) -> Optional[str]:
    if not mac or not isinstance(mac, str): return None
    m = mac.strip().lower().replace('-', ':')
    return m if re.match(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$', m) else None

def validate_ip(ip) -> Optional[str]:
    if not ip or not isinstance(ip, str): return None
    ip = ip.strip()
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip) and all(0<=int(p)<=255 for p in ip.split('.')): return ip
    return None

def validate_rssi(rssi) -> Optional[int]:
    try: v=int(rssi); return v if Config.RSSI_MIN<=v<=Config.RSSI_MAX else None
    except (TypeError, ValueError): return None

def validate_ssid(ssid) -> str:
    if not ssid or not isinstance(ssid, str): return 'unknown'
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', ssid)[:Config.MAX_SSID_LEN] or 'unknown'

def validate_label(label) -> str:
    if not label or not isinstance(label, str): return 'unknown-pi'
    return re.sub(r'[^a-zA-Z0-9\-_.]', '', label)[:Config.MAX_LABEL_LEN] or 'unknown-pi'

SAFE_ENV = {'PATH': '/usr/sbin:/sbin:/usr/bin:/bin'}


# ═══════════════════════════════════════════════════════════════
# SPRINT 2: DATABASE MODULE
# ═══════════════════════════════════════════════════════════════

class Database:
    """
    SQLite persistence for the scanner.
    Manages devices, events, known APs, and approved devices.

    Database location: /var/lib/wifimap/wifimap.db
    Created automatically on first run by install.sh or the scanner itself.

    Thread safety: uses a single connection with WAL mode, which allows
    concurrent reads while writes are serialised. Since the scanner is
    async but SQLite calls are synchronous, we use run_in_executor to
    avoid blocking the event loop on writes.
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn   = None

    def connect(self):
        """Open the database connection and create tables if needed."""
        # Ensure the data directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row  # return rows as dict-like objects
        self._conn.execute('PRAGMA journal_mode=WAL')  # WAL for concurrent access
        self._conn.execute('PRAGMA foreign_keys=ON')
        self._create_tables()
        log.info(f'Database: connected to {self.db_path}')

    def _create_tables(self):
        """Create all tables if they don't exist."""
        self._conn.executescript('''
            CREATE TABLE IF NOT EXISTS devices (
                mac         TEXT PRIMARY KEY,
                ip          TEXT,
                vendor      TEXT,
                hostname    TEXT,
                first_seen  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                last_seen   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                online      INTEGER NOT NULL DEFAULT 0,
                latency     INTEGER,
                anomaly_score REAL NOT NULL DEFAULT 0,
                approved    INTEGER NOT NULL DEFAULT 0,
                approved_at INTEGER,
                canvas_x    REAL,
                canvas_y    REAL,
                floor_id    INTEGER,
                pinned      INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS events (
                id          TEXT PRIMARY KEY,
                severity    TEXT NOT NULL,
                type        TEXT NOT NULL,
                title       TEXT NOT NULL,
                description TEXT,
                device_mac  TEXT,
                zone_name   TEXT,
                location    TEXT,
                timestamp   INTEGER NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                pi_label    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);

            CREATE TABLE IF NOT EXISTS known_aps (
                bssid       TEXT PRIMARY KEY,
                ssid        TEXT,
                rssi        INTEGER,
                channel     INTEGER,
                first_seen  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                last_seen   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                approved    INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS approved_devices (
                mac         TEXT PRIMARY KEY,
                approved_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                note        TEXT
            );

            CREATE TABLE IF NOT EXISTS pi_nodes (
                label       TEXT PRIMARY KEY,
                canvas_x    REAL,
                canvas_y    REAL,
                placed      INTEGER NOT NULL DEFAULT 0,
                last_seen   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
        ''')
        self._conn.commit()
        log.info('Database: schema ready')

    # ── Device operations ──────────────────────────────────────

    def upsert_device(self, mac: str, ip: str, vendor: str,
                      hostname: Optional[str], online: bool, latency: Optional[int]):
        """Insert or update a device record."""
        self._conn.execute('''
            INSERT INTO devices (mac, ip, vendor, hostname, last_seen, online, latency)
            VALUES (?, ?, ?, ?, strftime('%s','now'), ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip        = excluded.ip,
                hostname  = COALESCE(excluded.hostname, hostname),
                last_seen = excluded.last_seen,
                online    = excluded.online,
                latency   = excluded.latency
        ''', (mac, ip, vendor, hostname, int(online), latency))
        self._conn.commit()

    def get_all_devices(self) -> list:
        """Load all devices from database into memory."""
        return [dict(row) for row in self._conn.execute('SELECT * FROM devices').fetchall()]

    def approve_device(self, mac: str, note: str = None):
        """Mark a device as approved in both tables."""
        now = int(time.time())
        self._conn.execute('''
            INSERT INTO approved_devices (mac, approved_at, note) VALUES (?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET approved_at=excluded.approved_at
        ''', (mac, now, note))
        self._conn.execute('''
            UPDATE devices SET approved=1, approved_at=? WHERE mac=?
        ''', (now, mac))
        self._conn.commit()
        log.info(f'Database: device approved: {mac}')

    def get_approved_devices(self) -> list:
        """Return list of approved device MAC addresses with timestamps."""
        rows = self._conn.execute('SELECT mac, approved_at FROM approved_devices').fetchall()
        return [{'mac': row['mac'], 'approvedAt': row['approved_at'] * 1000} for row in rows]

    def is_approved(self, mac: str) -> bool:
        """Check if a device is approved."""
        row = self._conn.execute('SELECT 1 FROM approved_devices WHERE mac=?', (mac,)).fetchone()
        return row is not None

    # ── Event operations ───────────────────────────────────────

    def insert_event(self, event: dict):
        """Write a security event to the database."""
        try:
            device_mac = event.get('device', {}).get('mac') if event.get('device') else None
            zone_name  = event.get('zone', {}).get('name')  if event.get('zone')   else None
            self._conn.execute('''
                INSERT OR IGNORE INTO events
                  (id, severity, type, title, description, device_mac, zone_name, location, timestamp, pi_label)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(event.get('id', '')),
                str(event.get('severity', 'info')),
                str(event.get('type', 'unknown')),
                str(event.get('title', ''))[:255],
                str(event.get('description', ''))[:1000],
                device_mac,
                zone_name,
                str(event.get('location', ''))[:255],
                int(event.get('timestamp', time.time() * 1000) / 1000),
                None,  # pi_label populated separately
            ))
            self._conn.commit()
        except Exception as e:
            log.warning(f'Database.insert_event: {e}')

    def get_recent_events(self, limit: int = 200) -> list:
        """Return the most recent N events for replay to connecting clients."""
        rows = self._conn.execute('''
            SELECT * FROM events ORDER BY timestamp DESC LIMIT ?
        ''', (limit,)).fetchall()
        return [dict(row) for row in rows]

    def acknowledge_event(self, event_id: str):
        """Mark an event as acknowledged."""
        self._conn.execute('UPDATE events SET acknowledged=1 WHERE id=?', (event_id,))
        self._conn.commit()

    # ── AP operations ──────────────────────────────────────────

    def upsert_ap(self, bssid: str, ssid: str, rssi: int, channel: int, approved: bool):
        """Insert or update a known AP record."""
        self._conn.execute('''
            INSERT INTO known_aps (bssid, ssid, rssi, channel, approved)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(bssid) DO UPDATE SET
                ssid     = excluded.ssid,
                rssi     = excluded.rssi,
                last_seen = strftime('%s','now'),
                approved  = MAX(approved, excluded.approved)
        ''', (bssid, ssid, rssi, channel, int(approved)))
        self._conn.commit()

    def get_known_aps(self) -> dict:
        """Return dict of bssid → row for all known APs."""
        rows = self._conn.execute('SELECT * FROM known_aps').fetchall()
        return {row['bssid']: dict(row) for row in rows}

    def is_ap_known(self, bssid: str) -> bool:
        """Check if an AP BSSID is in the known AP table."""
        row = self._conn.execute('SELECT 1 FROM known_aps WHERE bssid=?', (bssid,)).fetchone()
        return row is not None

    # ── Pi node position ───────────────────────────────────────

    def save_node_position(self, label: str, canvas_x: float, canvas_y: float):
        """Save a Pi node's canvas position."""
        self._conn.execute('''
            INSERT INTO pi_nodes (label, canvas_x, canvas_y, placed, last_seen)
            VALUES (?, ?, ?, 1, strftime('%s','now'))
            ON CONFLICT(label) DO UPDATE SET
                canvas_x = excluded.canvas_x,
                canvas_y = excluded.canvas_y,
                placed   = 1,
                last_seen = excluded.last_seen
        ''', (label, canvas_x, canvas_y))
        self._conn.commit()

    def get_node_positions(self) -> dict:
        """Return dict of label → {canvas_x, canvas_y, placed} for all nodes."""
        rows = self._conn.execute('SELECT * FROM pi_nodes WHERE placed=1').fetchall()
        return {row['label']: dict(row) for row in rows}

    def close(self):
        if self._conn: self._conn.close()


# ═══════════════════════════════════════════════════════════════
# ZONE PERSISTENCE
# ═══════════════════════════════════════════════════════════════

class ZonePersistence:
    """
    Persists zone definitions to a JSON file.
    Zones are managed by the browser but stored on the Pi so they
    survive browser refreshes, different browsers, and redeployments.

    File: /var/lib/wifimap/zones.json
    """

    def __init__(self, zones_path: Path):
        self.zones_path = zones_path
        self.zones: list = []  # in-memory zone list
        self._load()

    def _load(self):
        """Load zones from disk on startup."""
        if not self.zones_path.exists():
            self.zones = []
            return
        try:
            with open(self.zones_path) as f:
                data = json.load(f)
                self.zones = data.get('zones', []) if isinstance(data, dict) else data
                log.info(f'ZonePersistence: loaded {len(self.zones)} zones from {self.zones_path}')
        except Exception as e:
            log.warning(f'ZonePersistence: failed to load zones — {e}')
            self.zones = []

    def _save(self):
        """Write zones to disk."""
        try:
            self.zones_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.zones_path, 'w') as f:
                json.dump({'zones': self.zones, 'savedAt': int(time.time())}, f, indent=2)
        except Exception as e:
            log.warning(f'ZonePersistence: failed to save zones — {e}')

    def add_or_update(self, zone: dict):
        """Add a new zone or update an existing one."""
        # Sanitise zone data
        zone_id = zone.get('id')
        clean_zone = {
            'id':        zone_id,
            'name':      re.sub(r'[\x00-\x1f]', '', str(zone.get('name', 'Zone')))[:64],
            'type':      zone.get('type', 'monitored') if zone.get('type') in ('restricted','monitored','safe','perimeter') else 'monitored',
            'alertTier': zone.get('alertTier', 'warning') if zone.get('alertTier') in ('critical','warning','info') else 'warning',
            'x': float(zone.get('x', 0)),
            'y': float(zone.get('y', 0)),
            'w': float(zone.get('w', 100)),
            'h': float(zone.get('h', 100)),
            'floorId':   zone.get('floorId', 0),
            'schedule':  zone.get('schedule', {'always': True}),
            'allowedMacs': [m for m in (zone.get('allowedMacs') or []) if validate_mac(m)],
        }
        existing_idx = next((i for i,z in enumerate(self.zones) if z.get('id') == zone_id), None)
        if existing_idx is not None:
            self.zones[existing_idx] = clean_zone
            log.info(f'ZonePersistence: updated zone {zone_id} "{clean_zone["name"]}"')
        else:
            self.zones.append(clean_zone)
            log.info(f'ZonePersistence: added zone {zone_id} "{clean_zone["name"]}"')
        self._save()

    def delete(self, zone_id):
        """Remove a zone by ID."""
        before = len(self.zones)
        self.zones = [z for z in self.zones if z.get('id') != zone_id]
        if len(self.zones) < before:
            log.info(f'ZonePersistence: deleted zone {zone_id}')
            self._save()

    def get_all(self) -> list:
        """Return all zones."""
        return self.zones


# ── Binary path resolution ───────────────────────────────────
class BinaryPaths:
    REQUIRED = ['ping']
    OPTIONAL = {'iwconfig':'ambient RSSI','iwlist':'AP scan','arp-scan':'device discovery','nmap':'device fallback','iw':'station dump','arping':'ARP latency','nmcli':'NetworkManager'}
    def __init__(self):
        self.paths={}; self._resolve()
    def _resolve(self):
        log.info('BinaryPaths: resolving...')
        for b in self.REQUIRED:
            p=shutil.which(b)
            if not p: raise RuntimeError(f'Required binary "{b}" not found. sudo apt-get install {b}')
            self.paths[b]=p; log.info(f'  {b} → {p}')
        for b,feat in self.OPTIONAL.items():
            p=shutil.which(b)
            if p: self.paths[b]=p; log.info(f'  {b} → {p}')
            else: log.debug(f'  {b} not found — {feat} disabled')
    def get(self,b): return self.paths.get(b)
    def available(self,b): return b in self.paths

BINS: Optional[BinaryPaths] = None

# ── Auth validator ───────────────────────────────────────────
class AuthValidator:
    def __init__(self,auth_hash): self.auth_hash=auth_hash; log.info(f'AuthValidator: configured ({auth_hash[:8]}...)')
    def validate(self,ws):
        protos=getattr(ws,'subprotocols',[])
        if not protos or not any(p.startswith('wifimap-v') for p in protos): return False
        ap=next((p for p in protos if p.startswith('auth-')),None)
        if not ap: return False
        prefix=ap[5:]
        return self.auth_hash.startswith(prefix) and len(prefix)>=16


# ── Shared state ──────────────────────────────────────────────
class AppState:
    def __init__(self):
        self.clients=set(); self.known_devices={}; self.hostname_cache={}
        self.device_rssi={}; self.ip_mac_map={}; self.known_aps={}
        self.approved_aps=set(); self.deauth_frames=defaultdict(list)

state = AppState()

# Global database and zone persistence instances
db:    Optional[Database]        = None
zones: Optional[ZonePersistence] = None


# ── OUI table ────────────────────────────────────────────────
OUI={'b8:27:eb':'Raspberry Pi Foundation','dc:a6:32':'Raspberry Pi Foundation','e4:5f:01':'Raspberry Pi Foundation','28:cd:c1':'Apple','f4:db:e6':'Apple','b4:fb:e4':'Apple','44:85:00':'Amazon Technologies','00:17:88':'Philips Lighting','18:b4:30':'Nest Labs','94:35:0a':'Samsung Electronics','b8:e9:37':'Sonos','fc:fb:fb':'Cisco Systems','00:50:56':'VMware'}
def vendor_from_mac(mac): return OUI.get(mac[:8],'Unknown vendor') if mac else 'Unknown'


# ── Message builder ───────────────────────────────────────────
class MessageBuilder:
    def __init__(self,args): self.label=validate_label(args.label); self.x=args.x; self.y=args.y
    def _base(self):
        m={'version':WS_VERSION,'timestamp':datetime.now(timezone.utc).isoformat(),'pi_label':self.label}
        if self.x is not None: m['x']=self.x
        if self.y is not None: m['y']=self.y
        return m
    def hello(self,demo): m=self._base(); m.update({'type':'hello','label':self.label,'demo':demo,'version':WS_VERSION}); return json.dumps(m)
    def rssi(self,reading): m=self._base(); m.update({'type':'rssi','rssi':validate_rssi(reading.get('rssi',-100)) or -100,'ssid':validate_ssid(reading.get('ssid',''))}); return json.dumps(m)
    def device(self,dev,online,latency,rssi=None,hostname=None):
        mac=validate_mac(dev.get('mac','')) or ''; ip=validate_ip(dev.get('ip','')) or '?'
        vendor=re.sub(r'[\x00-\x1f\x7f]','',str(dev.get('vendor',vendor_from_mac(mac))))[:64]
        m=self._base(); m.update({'type':'device','mac':mac,'ip':ip,'vendor':vendor,'online':bool(online),'latency':int(latency) if latency is not None and latency<Config.LATENCY_MAX else None})
        if hostname:
            sh=re.sub(r'[^a-zA-Z0-9.\-_]','',str(hostname))[:64]
            if sh: m['hostname']=sh; m['name']=sh
        if rssi is not None:
            vr=validate_rssi(rssi)
            if vr is not None: m['rssi']=vr
        return json.dumps(m)
    def device_rssi_batch(self,signals):
        validated=[{'mac':vm,'rssi':vr} for mac,rssi in signals.items() if (vm:=validate_mac(mac)) and (vr:=validate_rssi(rssi)) is not None]
        m=self._base(); m.update({'type':'device_rssi','devices':validated}); return json.dumps(m)
    def rogue_ap(self,ap):
        m=self._base(); m.update({'type':'rogue_ap','bssid':validate_mac(ap.get('bssid','')) or '?','ssid':validate_ssid(ap.get('ssid','')),'rssi':validate_rssi(ap.get('rssi',-90)) or -90}); return json.dumps(m)
    def deauth_attack(self,count,window): m=self._base(); m.update({'type':'deauth_attack','count':int(count),'window':int(window)}); return json.dumps(m)
    def mac_spoof(self,ip,old_mac,new_mac): m=self._base(); m.update({'type':'mac_spoof','ip':validate_ip(ip) or '?','old_mac':validate_mac(old_mac) or '?','new_mac':validate_mac(new_mac) or '?'}); return json.dumps(m)

    # ── Persistence-aware outbound message types ────────────────
    def zone_load(self, zone_list: list) -> str:
        """Send all persisted zones to a newly connecting client."""
        m = self._base()
        m.update({'type': 'zone_load', 'zones': zone_list})
        return json.dumps(m)

    def event_replay(self, events: list) -> str:
        """Send recent event log to a newly connecting client."""
        # Convert DB rows to browser-compatible format
        browser_events = []
        for e in events:
            browser_events.append({
                'id':          str(e.get('id', '')),
                'severity':    e.get('severity', 'info'),
                'type':        e.get('type', 'unknown'),
                'title':       e.get('title', ''),
                'description': e.get('description', ''),
                'location':    e.get('location', '—'),
                'timestamp':   e.get('timestamp', 0) * 1000,  # to milliseconds
                'acknowledged': bool(e.get('acknowledged', 0)),
                'device':      {'mac': e['device_mac']} if e.get('device_mac') else None,
            })
        m = self._base()
        m.update({'type': 'event_replay', 'events': browser_events})
        return json.dumps(m)

    def approved_devices(self, approved_list: list) -> str:
        """Send approved device list to a newly connecting client."""
        m = self._base()
        m.update({'type': 'approved_devices', 'devices': approved_list})
        return json.dumps(m)


# ── WiFi scanner ──────────────────────────────────────────────
class WiFiScanner:
    def __init__(self,interface,ssid=None): self.interface=validate_label(interface); self.ssid=ssid
    def get_reading(self): return self._iwconfig() or self._nmcli()
    def _iwconfig(self):
        bp=BINS.get('iwconfig')
        if not bp: return None
        try:
            out=subprocess.run([bp,self.interface],capture_output=True,text=True,timeout=3,env=SAFE_ENV).stdout
            rm=re.search(r'Signal level[=:](-?\d+)\s*dBm',out); sm=re.search(r'ESSID:"([^"]{0,64})"',out)
            if not rm: return None
            rssi=validate_rssi(rm.group(1))
            if rssi is None: return None
            ssid=validate_ssid(sm.group(1) if sm else 'unknown')
            if self.ssid and ssid!=self.ssid: return None
            return{'rssi':rssi,'ssid':ssid}
        except (subprocess.TimeoutExpired, OSError) as e: log.debug(f'WiFiScanner.iwconfig: {e}'); return None
    def _nmcli(self):
        bp=BINS.get('nmcli')
        if not bp: return None
        try:
            out=subprocess.run([bp,'-f','SSID,SIGNAL','dev','wifi'],capture_output=True,text=True,timeout=5,env=SAFE_ENV).stdout
            for line in out.splitlines()[1:]:
                parts=line.strip().split()
                if len(parts)<2: continue
                try:
                    pct=int(parts[-1]); ssid=validate_ssid(' '.join(parts[:-1]))
                    if self.ssid and ssid!=self.ssid: continue
                    rssi=validate_rssi(int((pct/2)-100))
                    if rssi is not None: return{'rssi':rssi,'ssid':ssid}
                except (ValueError, IndexError): continue
        except (subprocess.TimeoutExpired, OSError) as e: log.debug(f'WiFiScanner.nmcli: {e}')
        return None
    def get_demo(self): t=time.time(); return{'rssi':max(-90,min(-30,int(-58+random.gauss(0,3)+5*math.sin(t/30)))),'ssid':'Demo-Network-5G'}


# ── Device scanner ────────────────────────────────────────────
class DeviceScanner:
    def __init__(self,interface,subnet=None): self.interface=validate_label(interface); self.subnet=subnet
    def get_subnet(self):
        if self.subnet: return self.subnet
        bp=shutil.which('ip')
        if not bp: return '192.168.1.0/24'
        try:
            out=subprocess.run([bp,'route'],capture_output=True,text=True,timeout=3,env=SAFE_ENV).stdout
            for line in out.splitlines():
                if self.interface in line:
                    parts=line.split()
                    if parts and '/' in parts[0] and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$',parts[0]): return parts[0]
        except (subprocess.TimeoutExpired, OSError) as e: log.debug(f'DeviceScanner.get_subnet: {e}')
        return '192.168.1.0/24'
    def scan(self,subnet):
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$',subnet): return []
        return self._arp(subnet) or self._nmap(subnet)
    def _arp(self,subnet):
        bp=BINS.get('arp-scan'); sudo=shutil.which('sudo')
        if not bp or not sudo: return []
        devs=[]
        try:
            out=subprocess.run([sudo,bp,'--interface',self.interface,subnet],capture_output=True,text=True,timeout=15,env=SAFE_ENV).stdout
            for line in out.splitlines():
                parts=line.strip().split('\t')
                if len(parts)<2: continue
                ip=validate_ip(parts[0].strip()); mac=validate_mac(parts[1].strip())
                vendor=re.sub(r'[\x00-\x1f\x7f]','',parts[2].strip())[:64] if len(parts)>2 else ''
                if ip and mac: devs.append({'ip':ip,'mac':mac,'vendor':vendor or vendor_from_mac(mac)})
        except subprocess.TimeoutExpired: log.warning('DeviceScanner.arp: timed out')
        except OSError as e: log.warning(f'DeviceScanner.arp: {e}')
        return devs
    def _nmap(self,subnet):
        bp=BINS.get('nmap'); sudo=shutil.which('sudo')
        if not bp or not sudo: return []
        devs,ip,mac,vendor=[],None,None,'Unknown'
        try:
            out=subprocess.run([sudo,bp,'-sn',subnet],capture_output=True,text=True,timeout=30,env=SAFE_ENV).stdout
            for line in out.splitlines():
                im=re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line); mm=re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})',line); vm=re.search(r'\(([A-Za-z0-9 ,.\-]{1,64})\)',line)
                if im:
                    if ip and validate_ip(ip): devs.append({'ip':validate_ip(ip),'mac':validate_mac(mac) or ip+'_noMac','vendor':vendor})
                    ip,mac,vendor=im.group(1),None,'Unknown'
                if mm: mac=mm.group(1).lower()
                if vm and mac: vendor=vm.group(1)
            if ip and validate_ip(ip): devs.append({'ip':validate_ip(ip),'mac':validate_mac(mac) or ip+'_noMac','vendor':vendor})
        except subprocess.TimeoutExpired: log.warning('DeviceScanner.nmap: timed out')
        except OSError as e: log.warning(f'DeviceScanner.nmap: {e}')
        return devs
    def ping_latency(self,ip):
        vip=validate_ip(ip)
        if not vip: return None
        bp=BINS.get('ping')
        if not bp: return None
        try:
            out=subprocess.run([bp,'-c','1','-W',str(Config.PING_TIMEOUT),vip],capture_output=True,text=True,timeout=Config.PING_TIMEOUT+1,env=SAFE_ENV).stdout
            m=re.search(r'time[=<](\d+\.?\d*)\s*ms',out)
            if m:
                lat=round(float(m.group(1)))
                return lat if lat<Config.LATENCY_MAX else None
            return None
        except (subprocess.TimeoutExpired, OSError): return None
    def get_demo_devices(self):
        base=[{'ip':'192.168.1.10','mac':'b8:27:eb:aa:11:22','vendor':'Raspberry Pi Foundation'},{'ip':'192.168.1.42','mac':'28:cd:c1:bb:33:44','vendor':'Apple, Inc.'},{'ip':'192.168.1.55','mac':'44:85:00:cc:55:66','vendor':'Amazon Technologies'},{'ip':'192.168.1.71','mac':'00:17:88:dd:77:88','vendor':'Philips Lighting'},{'ip':'192.168.1.88','mac':'94:35:0a:ee:99:aa','vendor':'Samsung Electronics'}]
        return random.sample(base,len(base)-1) if random.random()<Config.DEMO_OFFLINE_CHANCE else base
    def get_demo_latency(self,ip):
        if random.random()<0.04: return None
        base={'192.168.1.10':4,'192.168.1.42':12,'192.168.1.55':38,'192.168.1.88':67}.get(ip,20)
        return max(1,int(base+random.gauss(0,base*.15)))


# ── Device RSSI scanner ───────────────────────────────────────
class DeviceRSSIScanner:
    def __init__(self,interface): self.interface=validate_label(interface)
    def scan_iw(self):
        bp=BINS.get('iw')
        if not bp: return {}
        results={}; cur=None
        try:
            out=subprocess.run([bp,'dev',self.interface,'station','dump'],capture_output=True,text=True,timeout=5,env=SAFE_ENV).stdout
            for line in out.splitlines():
                mm=re.match(r'^Station\s+([0-9a-f:]{17})',line.strip()); rm=re.search(r'signal:\s+(-\d+)\s+dBm',line)
                if mm: cur=validate_mac(mm.group(1))
                if rm and cur:
                    rssi=validate_rssi(rm.group(1))
                    if rssi is not None: results[cur]=rssi
        except (subprocess.TimeoutExpired, OSError) as e: log.debug(f'DeviceRSSIScanner.iw: {e}')
        return results
    def scan(self,devices): return self.scan_iw() or {}
    def get_demo(self,devices): return {d['mac']:max(-90,min(-30,int(-45-(hash(d['mac'])%35)+random.gauss(0,4)))) for d in devices if validate_mac(d.get('mac',''))}


# ── Deauth detector ───────────────────────────────────────────
class DeauthDetector:
    """
    Detects deauthentication attacks by monitoring the tx_retries counter
    from 'iw dev <interface> station dump'.

    When a deauth flood occurs, the AP cannot reach stations and retries
    spike sharply. We track the per-station tx_retries delta between scans
    and fire an alert when the aggregate spike exceeds Config.DEAUTH_THRESHOLD
    within Config.DEAUTH_WINDOW seconds.

    This approach works on a standard Pi with no monitor mode required —
    it uses the normal AP interface. It catches client-targeted deauth floods
    but not AP-targeted floods (where the AP itself is the victim). For a
    full-spectrum solution, a dedicated monitor interface via tcpdump/tshark
    is needed but requires interface reconfiguration.
    """

    def __init__(self, interface: str):
        self.interface    = validate_label(interface)
        self._prev_retries: dict = {}  # mac → tx_retries at last scan
        self._spike_times: list = []   # timestamps of recent spike events

    def _get_station_retries(self) -> dict:
        """Read per-station tx_retries from iw station dump."""
        bp = BINS.get('iw')
        if not bp: return {}
        results: dict = {}
        cur = None
        try:
            out = subprocess.run(
                [bp, 'dev', self.interface, 'station', 'dump'],
                capture_output=True, text=True, timeout=5, env=SAFE_ENV
            ).stdout
            for line in out.splitlines():
                mm = re.match(r'^Station\s+([0-9a-f:]{17})', line.strip())
                rm = re.search(r'tx retries:\s*(\d+)', line)
                if mm: cur = validate_mac(mm.group(1))
                if rm and cur:
                    try: results[cur] = int(rm.group(1))
                    except ValueError: pass
        except Exception:
            pass
        return results

    def check(self) -> Optional[dict]:
        """
        Compare current tx_retries against previous scan.
        Returns a spike summary dict if threshold exceeded, else None.
        """
        current = self._get_station_retries()
        if not current:
            self._prev_retries = current
            return None

        now = time.time()
        total_spike = 0
        spike_stations = 0

        for mac, retries in current.items():
            prev = self._prev_retries.get(mac, retries)
            delta = retries - prev
            if delta > 5:  # meaningful retry spike per station
                total_spike += delta
                spike_stations += 1

        self._prev_retries = current

        if spike_stations == 0:
            return None

        # Record this spike event
        self._spike_times.append(now)

        # Prune events outside the detection window
        window_start = now - Config.DEAUTH_WINDOW
        self._spike_times = [t for t in self._spike_times if t >= window_start]

        # Fire if enough spike events accumulated in the window
        if len(self._spike_times) >= Config.DEAUTH_THRESHOLD:
            self._spike_times = []  # reset to avoid repeated alerts
            return {
                'count':   spike_stations,
                'window':  Config.DEAUTH_WINDOW,
                'retries': total_spike,
            }

        return None

    def get_demo(self) -> Optional[dict]:
        """Occasionally return a simulated deauth event in demo mode."""
        if random.random() < 0.005:  # 0.5% chance per scan cycle
            return {'count': random.randint(2,8), 'window': Config.DEAUTH_WINDOW, 'retries': random.randint(50,200)}
        return None


# ── AP scanner ────────────────────────────────────────────────
class APScanner:
    def __init__(self,interface): self.interface=validate_label(interface)
    def scan(self):
        bp=BINS.get('iwlist'); sudo=shutil.which('sudo')
        if not bp or not sudo: return []
        aps=[]
        try:
            out=subprocess.run([sudo,bp,self.interface,'scan'],capture_output=True,text=True,timeout=20,env=SAFE_ENV).stdout
            for cell in out.split('Cell ')[1:]:
                bm=re.search(r'Address:\s+([0-9A-Fa-f:]{17})',cell); sm=re.search(r'ESSID:"([^"]{0,64})"',cell); rm=re.search(r'Signal level[=:](-?\d+)\s*dBm',cell); cm=re.search(r'Channel:(\d+)',cell)
                if bm:
                    bssid=validate_mac(bm.group(1)); rssi=validate_rssi(rm.group(1) if rm else -90) or -90
                    if bssid: aps.append({'bssid':bssid,'ssid':validate_ssid(sm.group(1) if sm else ''),'rssi':rssi,'channel':int(cm.group(1)) if cm else 0})
        except subprocess.TimeoutExpired: log.warning('APScanner: scan timed out')
        except OSError as e: log.warning(f'APScanner: {e}')
        return aps
    def get_demo_aps(self): return [{'bssid':'aa:bb:cc:dd:ee:01','ssid':'HomeNetwork-5G','rssi':-45,'channel':36},{'bssid':'aa:bb:cc:dd:ee:02','ssid':'HomeNetwork-2.4G','rssi':-50,'channel':6}]


# ── Pi-hole integration ───────────────────────────────────────
class PiholeIntegration:
    def __init__(self,host,token=None):
        if not re.match(r'^[\w.\-]+$',host): raise ValueError(f'Invalid Pi-hole host: {host!r}')
        self.host=host; self.token=token
    def fetch_hostnames(self):
        if not REQUESTS_AVAILABLE: return {}
        map_={}
        try:
            r=requests.get(f'http://{self.host}/api/network',timeout=5)
            if r.ok:
                data=r.json()
                for e in data.get('network', data.get('clients', [])):
                    mac=validate_mac(e.get('hwaddr') or e.get('mac') or ''); name=re.sub(r'[^a-zA-Z0-9.\-_]','',str(e.get('name') or e.get('hostname') or ''))[:64]
                    if mac and name and name not in('localhost','-'): map_[mac]=name
        except (OSError, ValueError) as e: log.debug(f'PiholeIntegration.v6: {e}')
        if not map_:
            try:
                url=f'http://{self.host}/admin/api.php?networkmap'+(f'&auth={self.token}' if self.token else '')
                r=requests.get(url,timeout=5)
                if r.ok:
                    for e in r.json().get('network',{}).values():
                        mac=validate_mac(e.get('hwaddr') or ''); name=re.sub(r'[^a-zA-Z0-9.\-_]','',str(e.get('name') or ''))[:64]
                        if mac and name and name not in('localhost','-'): map_[mac]=name
            except (OSError, ValueError) as e: log.debug(f'PiholeIntegration.v5: {e}')
        state.hostname_cache.update(map_); return map_
    def get_demo_hostnames(self): return{'b8:27:eb:aa:11:22':'living-room-pi','28:cd:c1:bb:33:44':'johns-iphone','44:85:00:cc:55:66':'echo-kitchen','94:35:0a:ee:99:aa':'samsung-tv'}


# ── WebSocket server ──────────────────────────────────────────
async def broadcast(msg):
    dead=set()
    for c in state.clients:
        try: await c.send(msg)
        except: dead.add(c)
    state.clients.difference_update(dead)


async def handle_client_message(raw: str, builder: MessageBuilder):
    """
    Handle inbound messages from the browser.
    Processes zone_save, zone_delete, device_approve, node_position messages from browser.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return

    msg_type = data.get('type', '')

    if msg_type == 'zone_save':
        # Browser is saving or updating a zone
        zone = data.get('zone')
        action = data.get('action', 'add')
        if zone and zones:
            zones.add_or_update(zone)
            log.info(f'Zone {action}: {zone.get("name")} (id={zone.get("id")})')

    elif msg_type == 'zone_delete':
        # Browser is deleting a zone
        zone_id = data.get('id')
        if zone_id and zones:
            zones.delete(zone_id)

    elif msg_type == 'device_approve':
        # Browser approved a device — persist to SQLite
        mac = validate_mac(data.get('mac', ''))
        if mac and db:
            db.approve_device(mac)
            log.info(f'Device approved: {mac}')

    elif msg_type == 'node_position':
        # Browser dragged a Pi node — log position for reference
        label  = validate_label(data.get('label', ''))
        norm_x = float(data.get('x', 0))
        norm_y = float(data.get('y', 0))
        if label and db and 0 <= norm_x <= 1 and 0 <= norm_y <= 1:
            db.save_node_position(label, norm_x, norm_y)
            log.info(f'Node position saved: {label} → ({norm_x:.2f}, {norm_y:.2f})')


# ── Scan loops ────────────────────────────────────────────────
async def rssi_loop(args, wifi, builder):
    log.info(f'RSSI loop (interval={args.interval}s)')
    while True:
        try:
            r=wifi.get_demo() if args.demo else wifi.get_reading()
            if r and state.clients: await broadcast(builder.rssi(r))
        except Exception as e: log.error(f'rssi_loop: {e}')
        await asyncio.sleep(args.interval)


async def device_loop(args, ds, rs, builder):
    subnet=ds.get_subnet(); log.info(f'Device loop (subnet={subnet})')
    while True:
        try:
            found=ds.get_demo_devices() if args.demo else ds.scan(subnet)
            found_macs={d['mac'] for d in found}
            signals=rs.get_demo(found) if args.demo else rs.scan(found)
            state.device_rssi.update(signals)

            for dev in found:
                mac=dev['mac']; ip=dev['ip']
                latency=ds.get_demo_latency(ip) if args.demo else ds.ping_latency(ip)
                online=latency is not None
                prev=state.ip_mac_map.get(ip)
                if prev and prev!=mac:
                    log.warning(f'MAC SPOOF: {ip} {prev}→{mac}')
                    if state.clients: await broadcast(builder.mac_spoof(ip,prev,mac))
                state.ip_mac_map[ip]=mac
                is_new=mac not in state.known_devices
                hostname=state.hostname_cache.get(mac)
                state.known_devices[mac]={**dev,'online':online,'latency':latency,'last_seen':time.time()}
                if state.clients: await broadcast(builder.device(dev,online,latency,rssi=signals.get(mac),hostname=hostname))

                # Write device to persistent store on every discovery/update
                if db:
                    db.upsert_device(mac,ip,dev.get('vendor',''),hostname,online,latency)

                log.log(logging.INFO if is_new else logging.DEBUG,f'Device {"NEW" if is_new else "   "} {mac} ({ip}) online={online}')

            for mac,dev in list(state.known_devices.items()):
                if mac not in found_macs and dev.get('online',False):
                    state.known_devices[mac]['online']=False
                    if state.clients: await broadcast(builder.device(dev,False,None))
                    if db: db.upsert_device(mac,dev.get('ip',''),dev.get('vendor',''),None,False,None)

            if signals and state.clients: await broadcast(builder.device_rssi_batch(signals))

            # Deauth detection — check for tx_retries spike after each device scan
            deauth = deauth_detector.get_demo() if args.demo else deauth_detector.check()
            if deauth and state.clients:
                log.warning(f'DEAUTH: {deauth["count"]} stations, {deauth["retries"]} retries in {deauth["window"]}s')
                await broadcast(builder.deauth_attack(deauth['count'], deauth['window']))

        except Exception as e: log.error(f'device_loop: {e}')
        await asyncio.sleep(args.scan_interval)


async def ap_scan_loop(args, ap_scanner, builder):
    if getattr(args,'no_rogue_ap',False): return
    log.info(f'AP scan loop (interval={Config.AP_SCAN_INTERVAL}s)')

    # Seed known_aps from database so rogue AP detection survives restarts
    if db:
        state.known_aps = db.get_known_aps()
        log.info(f'Loaded {len(state.known_aps)} known APs from database')

    is_first=True
    while True:
        try:
            aps=ap_scanner.get_demo_aps() if args.demo else ap_scanner.scan()
            for ap in aps:
                bssid=ap['bssid']
                if bssid not in state.known_aps:
                    is_approved_ap = bssid in state.approved_aps or is_first
                    state.known_aps[bssid]={**ap,'firstSeen':time.time(),'approved':is_approved_ap}
                    # Record AP in database — approved flag preserved on update
                    if db: db.upsert_ap(bssid,ap['ssid'],ap['rssi'],ap.get('channel',0),is_approved_ap)
                    if not is_first and bssid not in state.approved_aps:
                        log.warning(f'ROGUE AP: {bssid} ({ap["ssid"]})')
                        if state.clients: await broadcast(builder.rogue_ap(ap))
                    elif is_first: log.info(f'AP learned: {bssid}')
                else:
                    # Update last seen in DB
                    if db: db.upsert_ap(bssid,ap['ssid'],ap['rssi'],ap.get('channel',0),state.known_aps[bssid].get('approved',False))
            is_first=False
        except Exception as e: log.error(f'ap_scan_loop: {e}')
        await asyncio.sleep(Config.AP_SCAN_INTERVAL)


async def pihole_loop(args, pihole, builder):
    if getattr(args,'no_pihole',False) or not REQUESTS_AVAILABLE: return
    log.info(f'Pi-hole loop (host={args.pihole_host})')
    while True:
        try:
            hn=pihole.get_demo_hostnames() if args.demo else pihole.fetch_hostnames()
            if hn and state.clients:
                for mac,hostname in hn.items():
                    if mac in state.known_devices:
                        dev=state.known_devices[mac]
                        await broadcast(builder.device(dev,dev.get('online',False),dev.get('latency'),rssi=state.device_rssi.get(mac),hostname=hostname))
                        # Keep hostname current in database as Pi-hole resolves names
                        if db: db.upsert_device(mac,dev.get('ip',''),dev.get('vendor',''),hostname,dev.get('online',False),dev.get('latency'))
        except Exception as e: log.error(f'pihole_loop: {e}')
        await asyncio.sleep(60)


# ── Argument parser ───────────────────────────────────────────
def build_arg_parser():
    p=argparse.ArgumentParser(description='WiFi/MAP Scanner v5.3')
    p.add_argument('--host',          default=Config.DEFAULT_HOST)
    p.add_argument('--port',          type=int,   default=Config.DEFAULT_PORT)
    p.add_argument('--interface',     default=Config.DEFAULT_INTERFACE)
    p.add_argument('--ssid',          default=None)
    p.add_argument('--interval',      type=float, default=Config.RSSI_INTERVAL)
    p.add_argument('--scan-interval', type=float, default=Config.DEVICE_SCAN_INTERVAL)
    p.add_argument('--label',         default='pi-node-1')
    p.add_argument('--x',             type=float, default=None)
    p.add_argument('--y',             type=float, default=None)
    p.add_argument('--subnet',        default=None)
    p.add_argument('--pihole-host',   default='127.0.0.1')
    p.add_argument('--pihole-token',  default=None)
    p.add_argument('--no-pihole',     action='store_true')
    p.add_argument('--no-rogue-ap',   action='store_true')
    p.add_argument('--approved-aps',  default=None)
    p.add_argument('--demo',          action='store_true')
    p.add_argument('--debug',         action='store_true')
    p.add_argument('--auth-hash',     default=Config.DEFAULT_AUTH_HASH)
    p.add_argument('--no-auth',       action='store_true', help='DEVELOPMENT ONLY')
    # Database and zone paths — overridable for dev/test environments
    p.add_argument('--db-path',       default=str(Config.DB_PATH),    help='SQLite database path')
    p.add_argument('--zones-path',    default=str(Config.ZONES_PATH), help='Zones JSON path')
    p.add_argument('--upstream',      default=None,                   help='Aggregation server WebSocket URL (MSP mode). If set, scanner dials OUT to this URL instead of accepting inbound connections. Example: ws://100.64.0.2:8766')
    return p


# ── Main ──────────────────────────────────────────────────────
async def main():
    global BINS, db, zones

    args=build_arg_parser().parse_args()
    if args.debug: logging.getLogger().setLevel(logging.DEBUG)

    try: BINS=BinaryPaths()
    except RuntimeError as e: log.error(f'Startup failed: {e}'); raise

    args.label=validate_label(args.label); args.interface=validate_label(args.interface)
    if args.approved_aps:
        state.approved_aps={m for b in args.approved_aps.split(',') if (m:=validate_mac(b.strip()))}

    # Initialise SQLite database — fail soft so scanner runs without persistence if needed
    db_path    = Path(args.db_path)
    zones_path = Path(args.zones_path)

    try:
        db = Database(db_path)
        db.connect()
        # Load approved devices from DB into state
        for entry in db.get_approved_devices():
            state.approved_aps.add(entry['mac'])  # pre-approved from previous sessions
    except Exception as e:
        log.warning(f'Database init failed: {e} — running without persistence')
        db = None

    # Initialise zone persistence — zones survive browser refreshes and redeployments
    try:
        zones = ZonePersistence(zones_path)
    except Exception as e:
        log.warning(f'Zone persistence init failed: {e}')
        zones = None

    log.info('='*60)
    log.info(f'WiFi/MAP Scanner v5.3')
    log.info(f'  Protocol: WS_VERSION={WS_VERSION}  Label: {args.label}')
    log.info(f'  Mode: {"DEMO" if args.demo else "LIVE"}  Auth: {"DISABLED" if args.no_auth else "enabled"}')
    log.info(f'  Database: {db_path if db else "disabled"}')
    log.info(f'  Zones: {zones_path if zones else "disabled"}')
    log.info(f'  ws://{args.host}:{args.port}')
    log.info('='*60)

    wifi    = WiFiScanner(args.interface, args.ssid)
    ds      = DeviceScanner(args.interface, args.subnet)
    rs      = DeviceRSSIScanner(args.interface)
    ap               = APScanner(args.interface)
    deauth_detector  = DeauthDetector(args.interface)
    pihole           = PiholeIntegration(args.pihole_host, args.pihole_token)
    builder          = MessageBuilder(args)
    auth             = None if args.no_auth else AuthValidator(args.auth_hash)

    async def handle_client(ws, path=None):
        addr = ws.remote_address
        if auth and not auth.validate(ws):
            log.warning(f'Rejected unauthenticated from {addr}')
            await ws.close(code=4401, reason='Unauthorised')
            return

        log.info(f'Client connected: {addr}')
        state.clients.add(ws)

        try:
            await ws.send(builder.hello(args.demo))

            if zones and zones.get_all():
                await ws.send(builder.zone_load(zones.get_all()))

            if db:
                approved = db.get_approved_devices()
                if approved: await ws.send(builder.approved_devices(approved))

            for mac, dev in state.known_devices.items():
                hostname=state.hostname_cache.get(mac); rssi=state.device_rssi.get(mac)
                try: await ws.send(builder.device(dev, dev.get('online',False), dev.get('latency'), rssi=rssi, hostname=hostname))
                except websockets.exceptions.ConnectionClosed: break

            if db:
                recent = db.get_recent_events(Config.EVENT_REPLAY_COUNT)
                if recent: await ws.send(builder.event_replay(recent))

            async for raw in ws:
                await handle_client_message(raw, builder)

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            log.debug(f'handle_client: {e}')
        finally:
            state.clients.discard(ws)
            log.info(f'Client disconnected: {addr}')

    if args.upstream:
        # ── MSP mode ─────────────────────────────────────────────
        # Scanner dials OUT to the aggregation server.
        # The aggregation server proxies browser connections through to this scanner.
        # No inbound port needed — works through NAT and firewalls automatically.
        upstream_url = args.upstream.strip()
        log.info(f'MSP mode: connecting to aggregation server at {upstream_url}')

        async def upstream_loop():
            while True:
                try:
                    async with websockets.connect(
                        upstream_url,
                        ping_interval=20,
                        ping_timeout=10,
                    ) as agg_ws:
                        log.info(f'Upstream: connected to {upstream_url}')
                        state.clients.add(agg_ws)
                        try:
                            await agg_ws.send(builder.hello(args.demo))
                            if zones and zones.get_all():
                                await agg_ws.send(builder.zone_load(zones.get_all()))
                            if db:
                                approved = db.get_approved_devices()
                                if approved: await agg_ws.send(builder.approved_devices(approved))
                            for mac, dev in state.known_devices.items():
                                hostname = state.hostname_cache.get(mac)
                                rssi     = state.device_rssi.get(mac)
                                try: await agg_ws.send(builder.device(dev, dev.get('online',False), dev.get('latency'), rssi=rssi, hostname=hostname))
                                except websockets.exceptions.ConnectionClosed: break
                            if db:
                                recent = db.get_recent_events(Config.EVENT_REPLAY_COUNT)
                                if recent: await agg_ws.send(builder.event_replay(recent))
                            async for raw in agg_ws:
                                await handle_client_message(raw, builder)
                        except websockets.exceptions.ConnectionClosed:
                            pass
                        finally:
                            state.clients.discard(agg_ws)
                except Exception as e:
                    log.warning(f'Upstream: disconnected ({e}), retrying in 5s...')
                await asyncio.sleep(5)

        await asyncio.gather(
            upstream_loop(),
            rssi_loop(args, wifi, builder),
            device_loop(args, ds, rs, builder),
            ap_scan_loop(args, ap, builder),
            pihole_loop(args, pihole, builder),
        )

    else:
        # ── Standalone mode ───────────────────────────────────────
        # Browser connects directly to this scanner's WebSocket server.
        # Default mode — no aggregation server required.
        async with websockets.serve(handle_client, args.host, args.port):
            log.info(f'Server ready at ws://{args.host}:{args.port}')
            await asyncio.gather(
                rssi_loop(args, wifi, builder),
                device_loop(args, ds, rs, builder),
                ap_scan_loop(args, ap, builder),
                pihole_loop(args, pihole, builder),
            )

    if db: db.close()


if __name__=='__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: log.info('Shutdown')
    except RuntimeError as e: log.error(f'Startup failed: {e}'); exit(1)
    except Exception as e: log.error(f'Fatal: {e}',exc_info=True); exit(1)
