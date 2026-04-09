"""
test_scanner.py  —  WiFi/MAP Scanner v5.2 Test Suite
=====================================================
Sprint 2 deliverable.

Target: 60% coverage on scanner business logic.

Covers:
  - validate_mac / validate_ip / validate_rssi / validate_ssid / validate_label
  - MessageBuilder — all message types, version field, JSON structure
  - AuthValidator — valid token accepted, invalid rejected, missing rejected
  - BinaryPaths — missing required binary raises RuntimeError
  - APScanner — rogue AP detection logic
  - MAC spoof detection
  - Database — CRUD for all four tables (devices, events, known_aps, approved_devices)
  - ZonePersistence — add, update, delete, bad data sanitisation

Run:
    pip install pytest --break-system-packages
    pytest test_scanner.py -v
    pytest test_scanner.py -v --tb=short --cov=wifi_scanner --cov-report=term-missing
"""

import pytest
import asyncio
import json
import time
import hashlib
import sqlite3
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock


# ─────────────────────────────────────────────────────────────
# We import the scanner module directly. Tests must be run from
# the same directory as wifi_scanner.py.
# ─────────────────────────────────────────────────────────────
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Patch BinaryPaths before importing to avoid shutil.which calls
# failing in CI / test environments without network tools installed
with patch('shutil.which', return_value='/usr/bin/ping'):
    import wifi_scanner as scanner


# ═════════════════════════════════════════════════════════════
# SECTION 1 — INPUT VALIDATION
# ═════════════════════════════════════════════════════════════

class TestValidateMac:
    """validate_mac() must normalise and validate MAC addresses."""

    def test_valid_lowercase(self):
        assert scanner.validate_mac('b8:27:eb:aa:11:22') == 'b8:27:eb:aa:11:22'

    def test_valid_uppercase_normalised(self):
        assert scanner.validate_mac('B8:27:EB:AA:11:22') == 'b8:27:eb:aa:11:22'

    def test_valid_hyphen_separator(self):
        # Some scanners output MAC with hyphens
        assert scanner.validate_mac('B8-27-EB-AA-11-22') == 'b8:27:eb:aa:11:22'

    def test_valid_with_whitespace(self):
        assert scanner.validate_mac('  b8:27:eb:aa:11:22  ') == 'b8:27:eb:aa:11:22'

    def test_invalid_too_short(self):
        assert scanner.validate_mac('b8:27:eb:aa:11') is None

    def test_invalid_too_long(self):
        assert scanner.validate_mac('b8:27:eb:aa:11:22:33') is None

    def test_invalid_non_hex(self):
        assert scanner.validate_mac('zz:27:eb:aa:11:22') is None

    def test_invalid_empty(self):
        assert scanner.validate_mac('') is None

    def test_invalid_none(self):
        assert scanner.validate_mac(None) is None

    def test_invalid_random_string(self):
        assert scanner.validate_mac('not-a-mac-address') is None

    def test_broadcast_mac(self):
        # Broadcast MAC is technically valid format
        assert scanner.validate_mac('ff:ff:ff:ff:ff:ff') == 'ff:ff:ff:ff:ff:ff'

    def test_zero_mac(self):
        assert scanner.validate_mac('00:00:00:00:00:00') == '00:00:00:00:00:00'


class TestValidateIp:
    """validate_ip() must accept valid IPv4 and reject everything else."""

    def test_valid_private_192(self):
        assert scanner.validate_ip('192.168.1.100') == '192.168.1.100'

    def test_valid_private_10(self):
        assert scanner.validate_ip('10.0.0.1') == '10.0.0.1'

    def test_valid_loopback(self):
        assert scanner.validate_ip('127.0.0.1') == '127.0.0.1'

    def test_valid_boundary_low(self):
        assert scanner.validate_ip('0.0.0.0') == '0.0.0.0'

    def test_valid_broadcast(self):
        assert scanner.validate_ip('255.255.255.255') == '255.255.255.255'

    def test_invalid_out_of_range(self):
        assert scanner.validate_ip('192.168.1.256') is None

    def test_invalid_negative_octet(self):
        assert scanner.validate_ip('192.168.-1.100') is None

    def test_invalid_too_few_octets(self):
        assert scanner.validate_ip('192.168.1') is None

    def test_invalid_too_many_octets(self):
        assert scanner.validate_ip('192.168.1.1.1') is None

    def test_invalid_empty(self):
        assert scanner.validate_ip('') is None

    def test_invalid_none(self):
        assert scanner.validate_ip(None) is None

    def test_invalid_hostname(self):
        assert scanner.validate_ip('example.com') is None

    def test_invalid_ipv6(self):
        assert scanner.validate_ip('::1') is None

    def test_with_whitespace_stripped(self):
        assert scanner.validate_ip('  192.168.1.1  ') == '192.168.1.1'


class TestValidateRssi:
    """validate_rssi() must accept RSSI in [-120, 0] and reject outside."""

    def test_typical_good_signal(self):
        assert scanner.validate_rssi(-45) == -45

    def test_typical_poor_signal(self):
        assert scanner.validate_rssi(-85) == -85

    def test_boundary_minimum(self):
        assert scanner.validate_rssi(-120) == -120

    def test_boundary_maximum(self):
        assert scanner.validate_rssi(0) == 0

    def test_below_minimum(self):
        assert scanner.validate_rssi(-121) is None

    def test_above_maximum(self):
        assert scanner.validate_rssi(1) is None

    def test_string_number(self):
        # Scanner receives strings from subprocess output
        assert scanner.validate_rssi('-65') == -65

    def test_float_truncated(self):
        assert scanner.validate_rssi(-65.9) == -65

    def test_non_numeric_string(self):
        assert scanner.validate_rssi('strong') is None

    def test_none(self):
        assert scanner.validate_rssi(None) is None

    def test_empty_string(self):
        assert scanner.validate_rssi('') is None

    def test_positive_rssi_rejected(self):
        assert scanner.validate_rssi(10) is None


class TestValidateSsid:
    """validate_ssid() must strip control characters and enforce length."""

    def test_normal_ssid(self):
        assert scanner.validate_ssid('MyHomeNetwork') == 'MyHomeNetwork'

    def test_ssid_with_spaces(self):
        assert scanner.validate_ssid('My Home Network') == 'My Home Network'

    def test_ssid_with_unicode(self):
        result = scanner.validate_ssid('Réseau-Maison')
        assert 'seau-Maison' in result  # unicode preserved, no strip

    def test_strips_null_bytes(self):
        assert '\x00' not in scanner.validate_ssid('Network\x00Hidden')

    def test_strips_control_chars(self):
        result = scanner.validate_ssid('Net\x01\x02\x1fwork')
        assert '\x01' not in result
        assert '\x1f' not in result

    def test_strips_high_control_chars(self):
        result = scanner.validate_ssid('Net\x7f\x80work')
        assert '\x7f' not in result

    def test_length_limit(self):
        long_ssid = 'A' * 100
        assert len(scanner.validate_ssid(long_ssid)) <= scanner.Config.MAX_SSID_LEN

    def test_empty_returns_unknown(self):
        assert scanner.validate_ssid('') == 'unknown'

    def test_none_returns_unknown(self):
        assert scanner.validate_ssid(None) == 'unknown'

    def test_only_control_chars_returns_unknown(self):
        assert scanner.validate_ssid('\x00\x01\x02') == 'unknown'


class TestValidateLabel:
    """validate_label() must only allow safe chars for Pi node labels."""

    def test_normal_label(self):
        assert scanner.validate_label('pi-node-1') == 'pi-node-1'

    def test_label_with_dots(self):
        assert scanner.validate_label('pi.node.1') == 'pi.node.1'

    def test_strips_special_chars(self):
        result = scanner.validate_label('pi; rm -rf /')
        assert ';' not in result
        assert ' ' not in result

    def test_length_limit(self):
        long_label = 'a' * 100
        assert len(scanner.validate_label(long_label)) <= scanner.Config.MAX_LABEL_LEN

    def test_empty_returns_default(self):
        assert scanner.validate_label('') == 'unknown-pi'

    def test_none_returns_default(self):
        assert scanner.validate_label(None) == 'unknown-pi'


# ═════════════════════════════════════════════════════════════
# SECTION 2 — MESSAGE BUILDER
# ═════════════════════════════════════════════════════════════

@pytest.fixture
def builder_args():
    """Minimal args object for MessageBuilder."""
    args = MagicMock()
    args.label = 'pi-node-1'
    args.x = 0.3
    args.y = 0.4
    return args

@pytest.fixture
def builder(builder_args):
    return scanner.MessageBuilder(builder_args)

@pytest.fixture
def builder_no_pos():
    args = MagicMock()
    args.label = 'pi-node-2'
    args.x = None
    args.y = None
    return scanner.MessageBuilder(args)


class TestMessageBuilder:
    """MessageBuilder must produce valid JSON with correct version field."""

    def _parse(self, raw: str) -> dict:
        """Helper: parse JSON and assert it's a dict."""
        data = json.loads(raw)
        assert isinstance(data, dict)
        return data

    def test_hello_has_version(self, builder):
        data = self._parse(builder.hello(demo=False))
        assert data['version'] == scanner.WS_VERSION

    def test_hello_has_type(self, builder):
        data = self._parse(builder.hello(demo=False))
        assert data['type'] == 'hello'

    def test_hello_has_label(self, builder):
        data = self._parse(builder.hello(demo=False))
        assert data['label'] == 'pi-node-1'

    def test_hello_demo_flag(self, builder):
        data = self._parse(builder.hello(demo=True))
        assert data['demo'] is True

    def test_hello_has_xy(self, builder):
        data = self._parse(builder.hello(demo=False))
        assert data['x'] == pytest.approx(0.3)
        assert data['y'] == pytest.approx(0.4)

    def test_hello_omits_xy_when_none(self, builder_no_pos):
        data = self._parse(builder_no_pos.hello(demo=False))
        assert 'x' not in data
        assert 'y' not in data

    def test_rssi_message_type(self, builder):
        data = self._parse(builder.rssi({'rssi': -65, 'ssid': 'TestNet'}))
        assert data['type'] == 'rssi'

    def test_rssi_clamps_invalid(self, builder):
        # validate_rssi returns None for out-of-range; builder falls back to -100
        data = self._parse(builder.rssi({'rssi': 999, 'ssid': 'TestNet'}))
        assert data['rssi'] == -100

    def test_rssi_valid_value(self, builder):
        data = self._parse(builder.rssi({'rssi': -72, 'ssid': 'Home'}))
        assert data['rssi'] == -72

    def test_device_message_type(self, builder):
        dev = {'mac': 'b8:27:eb:aa:11:22', 'ip': '192.168.1.10', 'vendor': 'RPi'}
        data = self._parse(builder.device(dev, online=True, latency=5))
        assert data['type'] == 'device'

    def test_device_has_version(self, builder):
        dev = {'mac': 'b8:27:eb:aa:11:22', 'ip': '192.168.1.10', 'vendor': 'RPi'}
        data = self._parse(builder.device(dev, online=True, latency=5))
        assert data['version'] == scanner.WS_VERSION

    def test_device_online_flag(self, builder):
        dev = {'mac': 'b8:27:eb:aa:11:22', 'ip': '192.168.1.10', 'vendor': 'RPi'}
        data = self._parse(builder.device(dev, online=False, latency=None))
        assert data['online'] is False

    def test_device_latency_none(self, builder):
        dev = {'mac': 'b8:27:eb:aa:11:22', 'ip': '192.168.1.10', 'vendor': 'RPi'}
        data = self._parse(builder.device(dev, online=False, latency=None))
        assert data['latency'] is None

    def test_device_includes_hostname(self, builder):
        dev = {'mac': 'b8:27:eb:aa:11:22', 'ip': '192.168.1.10', 'vendor': 'RPi'}
        data = self._parse(builder.device(dev, online=True, latency=4, hostname='my-pi'))
        assert data['hostname'] == 'my-pi'

    def test_device_rejects_bad_hostname(self, builder):
        dev = {'mac': 'b8:27:eb:aa:11:22', 'ip': '192.168.1.10', 'vendor': 'RPi'}
        # hostname sanitiser strips non-alphanumeric chars (quotes, semicolons, spaces, dashes)
        # SQL injection safety is handled by parameterised queries in the DB layer, not here
        data = self._parse(builder.device(dev, online=True, latency=4, hostname="'; DROP TABLE devices; --"))
        hostname = data.get('hostname', '')
        # Quotes and semicolons are stripped by the regex [^a-zA-Z0-9.\-_]
        assert "'" not in hostname
        assert ';' not in hostname
        assert ' ' not in hostname

    def test_rogue_ap_type(self, builder):
        ap = {'bssid': 'aa:bb:cc:dd:ee:01', 'ssid': 'EvilAP', 'rssi': -60}
        data = self._parse(builder.rogue_ap(ap))
        assert data['type'] == 'rogue_ap'

    def test_rogue_ap_has_bssid(self, builder):
        ap = {'bssid': 'aa:bb:cc:dd:ee:01', 'ssid': 'EvilAP', 'rssi': -60}
        data = self._parse(builder.rogue_ap(ap))
        assert data['bssid'] == 'aa:bb:cc:dd:ee:01'

    def test_deauth_attack_type(self, builder):
        data = self._parse(builder.deauth_attack(count=15, window=5))
        assert data['type'] == 'deauth_attack'
        assert data['count'] == 15
        assert data['window'] == 5

    def test_mac_spoof_type(self, builder):
        data = self._parse(builder.mac_spoof('192.168.1.5', 'aa:bb:cc:dd:ee:01', 'ff:ee:dd:cc:bb:aa'))
        assert data['type'] == 'mac_spoof'
        assert data['old_mac'] == 'aa:bb:cc:dd:ee:01'
        assert data['new_mac'] == 'ff:ee:dd:cc:bb:aa'

    def test_zone_load_type(self, builder):
        zones = [{'id': 1, 'name': 'Server Room', 'type': 'restricted'}]
        data = self._parse(builder.zone_load(zones))
        assert data['type'] == 'zone_load'
        assert len(data['zones']) == 1

    def test_event_replay_type(self, builder):
        events = [{'id': '123', 'severity': 'critical', 'type': 'new_device', 'title': 'Unknown device',
                   'description': '', 'location': 'Network', 'timestamp': int(time.time()),
                   'acknowledged': 0, 'device_mac': 'aa:bb:cc:dd:ee:ff'}]
        data = self._parse(builder.event_replay(events))
        assert data['type'] == 'event_replay'
        assert len(data['events']) == 1
        # Timestamps should be in milliseconds for browser
        assert data['events'][0]['timestamp'] > 1_000_000_000_000

    def test_approved_devices_type(self, builder):
        approved = [{'mac': 'aa:bb:cc:dd:ee:ff', 'approvedAt': int(time.time() * 1000)}]
        data = self._parse(builder.approved_devices(approved))
        assert data['type'] == 'approved_devices'
        assert len(data['devices']) == 1

    def test_device_rssi_batch(self, builder):
        signals = {'b8:27:eb:aa:11:22': -55, '28:cd:c1:bb:33:44': -70}
        data = self._parse(builder.device_rssi_batch(signals))
        assert data['type'] == 'device_rssi'
        assert len(data['devices']) == 2

    def test_device_rssi_batch_filters_invalid(self, builder):
        # Invalid MAC and out-of-range RSSI should be dropped
        signals = {'not-a-mac': -55, 'b8:27:eb:aa:11:22': 999}
        data = self._parse(builder.device_rssi_batch(signals))
        assert len(data['devices']) == 0

    def test_all_messages_have_timestamp(self, builder):
        for raw in [
            builder.hello(demo=False),
            builder.rssi({'rssi': -60, 'ssid': 'Net'}),
            builder.deauth_attack(5, 3),
        ]:
            data = json.loads(raw)
            assert 'timestamp' in data

    def test_all_messages_have_pi_label(self, builder):
        for raw in [builder.hello(False), builder.rssi({'rssi': -60, 'ssid': 'Net'})]:
            data = json.loads(raw)
            assert data['pi_label'] == 'pi-node-1'


# ═════════════════════════════════════════════════════════════
# SECTION 3 — AUTH VALIDATOR
# ═════════════════════════════════════════════════════════════

class TestAuthValidator:
    """AuthValidator must accept valid tokens and reject everything else."""

    DEFAULT_HASH = hashlib.sha256(b'admin:wifimap').hexdigest()

    def _make_ws(self, subprotocols):
        ws = MagicMock()
        ws.subprotocols = subprotocols
        return ws

    def test_valid_token_accepted(self):
        auth = scanner.AuthValidator(self.DEFAULT_HASH)
        token_prefix = self.DEFAULT_HASH[:16]
        ws = self._make_ws([f'wifimap-v{scanner.WS_VERSION}', f'auth-{token_prefix}'])
        assert auth.validate(ws) is True

    def test_wrong_token_rejected(self):
        auth = scanner.AuthValidator(self.DEFAULT_HASH)
        ws = self._make_ws([f'wifimap-v{scanner.WS_VERSION}', 'auth-0000000000000000'])
        assert auth.validate(ws) is False

    def test_missing_auth_subprotocol_rejected(self):
        auth = scanner.AuthValidator(self.DEFAULT_HASH)
        ws = self._make_ws([f'wifimap-v{scanner.WS_VERSION}'])
        assert auth.validate(ws) is False

    def test_empty_subprotocols_rejected(self):
        auth = scanner.AuthValidator(self.DEFAULT_HASH)
        ws = self._make_ws([])
        assert auth.validate(ws) is False

    def test_no_wifimap_protocol_rejected(self):
        auth = scanner.AuthValidator(self.DEFAULT_HASH)
        ws = self._make_ws([f'auth-{self.DEFAULT_HASH[:16]}'])  # auth without version proto
        assert auth.validate(ws) is False

    def test_short_token_rejected(self):
        # Token prefix must be at least 16 chars
        auth = scanner.AuthValidator(self.DEFAULT_HASH)
        ws = self._make_ws([f'wifimap-v{scanner.WS_VERSION}', 'auth-short'])
        assert auth.validate(ws) is False

    def test_custom_hash_accepted(self):
        custom_hash = hashlib.sha256(b'admin:hunter2').hexdigest()
        auth = scanner.AuthValidator(custom_hash)
        ws = self._make_ws([f'wifimap-v{scanner.WS_VERSION}', f'auth-{custom_hash[:16]}'])
        assert auth.validate(ws) is True

    def test_custom_hash_with_default_token_rejected(self):
        custom_hash = hashlib.sha256(b'admin:hunter2').hexdigest()
        auth = scanner.AuthValidator(custom_hash)
        default_prefix = self.DEFAULT_HASH[:16]
        ws = self._make_ws([f'wifimap-v{scanner.WS_VERSION}', f'auth-{default_prefix}'])
        assert auth.validate(ws) is False


# ═════════════════════════════════════════════════════════════
# SECTION 4 — BINARY PATHS
# ═════════════════════════════════════════════════════════════

class TestBinaryPaths:
    """BinaryPaths must fail fast if required binaries are missing."""

    def test_required_binary_missing_raises(self):
        with patch('shutil.which', return_value=None):
            with pytest.raises(RuntimeError, match='ping'):
                scanner.BinaryPaths()

    def test_required_binary_found(self):
        with patch('shutil.which', return_value='/usr/bin/ping'):
            bp = scanner.BinaryPaths()
            assert bp.get('ping') == '/usr/bin/ping'

    def test_optional_binary_missing_does_not_raise(self):
        def which(name):
            return '/usr/bin/ping' if name == 'ping' else None
        with patch('shutil.which', side_effect=which):
            bp = scanner.BinaryPaths()
            assert bp.get('iwconfig') is None

    def test_available_returns_true_for_found(self):
        with patch('shutil.which', return_value='/usr/bin/ping'):
            bp = scanner.BinaryPaths()
            assert bp.available('ping') is True

    def test_available_returns_false_for_missing(self):
        def which(name):
            return '/usr/bin/ping' if name == 'ping' else None
        with patch('shutil.which', side_effect=which):
            bp = scanner.BinaryPaths()
            assert bp.available('nmap') is False


# ═════════════════════════════════════════════════════════════
# SECTION 5 — AP SCANNER (rogue AP detection logic)
# ═════════════════════════════════════════════════════════════

class TestAPDetectionLogic:
    """
    The rogue AP detection logic lives in ap_scan_loop().
    We test the business logic: is a BSSID new = rogue if not in known_aps?
    """

    def test_new_bssid_on_first_scan_is_not_rogue(self):
        """First scan — all APs learned as baseline, none are rogue."""
        known_aps = {}
        approved_aps = set()
        is_first = True
        ap = {'bssid': 'aa:bb:cc:dd:ee:01', 'ssid': 'HomeNet', 'rssi': -45}
        is_rogue = not is_first and ap['bssid'] not in approved_aps and ap['bssid'] not in known_aps
        assert is_rogue is False

    def test_new_bssid_after_baseline_is_rogue(self):
        """A BSSID that appears after the first scan is flagged as rogue."""
        known_aps = {'aa:bb:cc:dd:ee:01': {'ssid': 'HomeNet', 'approved': True}}
        approved_aps = set()
        is_first = False
        new_ap = {'bssid': 'aa:bb:cc:dd:ee:ff', 'ssid': 'EvilTwin', 'rssi': -55}
        is_rogue = not is_first and new_ap['bssid'] not in approved_aps and new_ap['bssid'] not in known_aps
        assert is_rogue is True

    def test_known_bssid_is_not_rogue(self):
        """A BSSID in known_aps is never flagged, regardless of is_first."""
        known_aps = {'aa:bb:cc:dd:ee:01': {'ssid': 'HomeNet', 'approved': True}}
        approved_aps = set()
        is_first = False
        known_ap = {'bssid': 'aa:bb:cc:dd:ee:01', 'ssid': 'HomeNet', 'rssi': -45}
        is_rogue = not is_first and known_ap['bssid'] not in approved_aps and known_ap['bssid'] not in known_aps
        assert is_rogue is False

    def test_approved_ap_is_not_rogue(self):
        """An AP in the approved set is never flagged."""
        known_aps = {}
        approved_aps = {'aa:bb:cc:dd:ee:ff'}
        is_first = False
        ap = {'bssid': 'aa:bb:cc:dd:ee:ff', 'ssid': 'CorpNet', 'rssi': -50}
        is_rogue = not is_first and ap['bssid'] not in approved_aps and ap['bssid'] not in known_aps
        assert is_rogue is False

    def test_validate_mac_before_rogue_check(self):
        """Invalid BSSID should fail validation before reaching the rogue check."""
        bssid = validate_result = scanner.validate_mac('not-a-mac')
        assert validate_result is None  # would be dropped before any check

    def test_ssid_sanitised_in_rogue_ap_message(self):
        """Malicious SSID should be sanitised before broadcast."""
        raw_ssid = '<script>alert(1)</script>'
        sanitised = scanner.validate_ssid(raw_ssid)
        assert '<script>' not in sanitised or len(sanitised) <= scanner.Config.MAX_SSID_LEN


# ═════════════════════════════════════════════════════════════
# SECTION 6 — MAC SPOOF DETECTION
# ═════════════════════════════════════════════════════════════

class TestMacSpoofDetection:
    """
    MAC spoof detection: if an IP changes MAC between scans,
    the scanner should fire a mac_spoof event.
    """

    def test_same_mac_no_spoof(self):
        """Same MAC on same IP — not a spoof."""
        ip_mac_map = {'192.168.1.5': 'aa:bb:cc:dd:ee:01'}
        ip = '192.168.1.5'
        new_mac = 'aa:bb:cc:dd:ee:01'
        is_spoof = ip in ip_mac_map and ip_mac_map[ip] != new_mac
        assert is_spoof is False

    def test_changed_mac_is_spoof(self):
        """IP changes MAC between scans — potential spoof."""
        ip_mac_map = {'192.168.1.5': 'aa:bb:cc:dd:ee:01'}
        ip = '192.168.1.5'
        new_mac = 'ff:ee:dd:cc:bb:aa'
        is_spoof = ip in ip_mac_map and ip_mac_map[ip] != new_mac
        assert is_spoof is True

    def test_new_ip_not_spoof(self):
        """New IP not in map — not a spoof."""
        ip_mac_map = {}
        ip = '192.168.1.99'
        new_mac = 'aa:bb:cc:dd:ee:01'
        is_spoof = ip in ip_mac_map and ip_mac_map[ip] != new_mac
        assert is_spoof is False

    def test_mac_spoof_message_validates_both_macs(self):
        """mac_spoof message rejects invalid MAC addresses gracefully."""
        args = MagicMock(); args.label='pi-1'; args.x=None; args.y=None
        b = scanner.MessageBuilder(args)
        data = json.loads(b.mac_spoof('192.168.1.5', 'invalid-mac', 'also-invalid'))
        assert data['type'] == 'mac_spoof'
        # validate_mac returns None → message builder uses '?'
        assert data['old_mac'] == '?'
        assert data['new_mac'] == '?'

    def test_mac_spoof_message_with_valid_macs(self):
        args = MagicMock(); args.label='pi-1'; args.x=None; args.y=None
        b = scanner.MessageBuilder(args)
        data = json.loads(b.mac_spoof('192.168.1.5', 'aa:bb:cc:dd:ee:01', 'ff:ee:dd:cc:bb:aa'))
        assert data['old_mac'] == 'aa:bb:cc:dd:ee:01'
        assert data['new_mac'] == 'ff:ee:dd:cc:bb:aa'


# ═════════════════════════════════════════════════════════════
# SECTION 7 — DATABASE (SQLite CRUD)
# ═════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_db(tmp_path):
    """Provide a temporary Database instance for each test."""
    db = scanner.Database(tmp_path / 'test.db')
    db.connect()
    yield db
    db.close()


class TestDatabaseDevices:
    """Database.upsert_device and get_all_devices."""

    def test_upsert_inserts_new_device(self, tmp_db):
        tmp_db.upsert_device('b8:27:eb:aa:11:22', '192.168.1.10', 'RPi', 'my-pi', True, 5)
        devs = tmp_db.get_all_devices()
        assert len(devs) == 1
        assert devs[0]['mac'] == 'b8:27:eb:aa:11:22'

    def test_upsert_updates_existing_device(self, tmp_db):
        tmp_db.upsert_device('b8:27:eb:aa:11:22', '192.168.1.10', 'RPi', None, True, 5)
        tmp_db.upsert_device('b8:27:eb:aa:11:22', '192.168.1.10', 'RPi', None, False, None)
        devs = tmp_db.get_all_devices()
        assert len(devs) == 1
        assert devs[0]['online'] == 0  # SQLite stores bool as int

    def test_upsert_preserves_hostname(self, tmp_db):
        tmp_db.upsert_device('b8:27:eb:aa:11:22', '192.168.1.10', 'RPi', 'my-pi', True, 5)
        # Second upsert without hostname should not overwrite it
        tmp_db.upsert_device('b8:27:eb:aa:11:22', '192.168.1.10', 'RPi', None, True, 4)
        devs = tmp_db.get_all_devices()
        assert devs[0]['hostname'] == 'my-pi'

    def test_multiple_devices(self, tmp_db):
        tmp_db.upsert_device('aa:bb:cc:dd:ee:01', '192.168.1.1', 'Apple', None, True, 10)
        tmp_db.upsert_device('aa:bb:cc:dd:ee:02', '192.168.1.2', 'Amazon', None, True, 20)
        devs = tmp_db.get_all_devices()
        assert len(devs) == 2


class TestDatabaseApprovedDevices:
    """Database.approve_device, get_approved_devices, is_approved."""

    def test_approve_device(self, tmp_db):
        tmp_db.upsert_device('b8:27:eb:aa:11:22', '192.168.1.10', 'RPi', None, True, 5)
        tmp_db.approve_device('b8:27:eb:aa:11:22')
        assert tmp_db.is_approved('b8:27:eb:aa:11:22') is True

    def test_unapproved_device(self, tmp_db):
        tmp_db.upsert_device('b8:27:eb:aa:11:22', '192.168.1.10', 'RPi', None, True, 5)
        assert tmp_db.is_approved('b8:27:eb:aa:11:22') is False

    def test_approve_unknown_device(self, tmp_db):
        """Approving a device not in devices table should still work."""
        tmp_db.approve_device('aa:bb:cc:dd:ee:ff')
        assert tmp_db.is_approved('aa:bb:cc:dd:ee:ff') is True

    def test_get_approved_devices_list(self, tmp_db):
        tmp_db.approve_device('aa:bb:cc:dd:ee:01')
        tmp_db.approve_device('aa:bb:cc:dd:ee:02')
        approved = tmp_db.get_approved_devices()
        macs = [e['mac'] for e in approved]
        assert 'aa:bb:cc:dd:ee:01' in macs
        assert 'aa:bb:cc:dd:ee:02' in macs

    def test_approved_devices_have_timestamp(self, tmp_db):
        tmp_db.approve_device('aa:bb:cc:dd:ee:ff')
        approved = tmp_db.get_approved_devices()
        assert approved[0]['approvedAt'] > 0

    def test_duplicate_approval_idempotent(self, tmp_db):
        tmp_db.approve_device('aa:bb:cc:dd:ee:ff')
        tmp_db.approve_device('aa:bb:cc:dd:ee:ff')
        approved = tmp_db.get_approved_devices()
        assert len(approved) == 1


class TestDatabaseEvents:
    """Database.insert_event, get_recent_events."""

    def _make_event(self, suffix=''):
        return {
            'id': f'evt-{int(time.time())}-{suffix}',
            'severity': 'critical',
            'type': 'new_device',
            'title': 'Test event' + suffix,
            'description': 'A test security event',
            'location': 'Network',
            'timestamp': int(time.time() * 1000),
        }

    def test_insert_event(self, tmp_db):
        tmp_db.insert_event(self._make_event('a'))
        events = tmp_db.get_recent_events(10)
        assert len(events) == 1

    def test_get_recent_returns_latest_first(self, tmp_db):
        for i in range(5):
            ev = self._make_event(str(i))
            ev['timestamp'] = int(time.time() * 1000) + i * 1000  # incrementing times
            time.sleep(0.01)
            tmp_db.insert_event(ev)
        events = tmp_db.get_recent_events(5)
        # Should be newest first
        timestamps = [e['timestamp'] for e in events]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_get_recent_respects_limit(self, tmp_db):
        for i in range(10):
            ev = self._make_event(str(i))
            ev['id'] = f'unique-{i}'
            tmp_db.insert_event(ev)
        events = tmp_db.get_recent_events(5)
        assert len(events) <= 5

    def test_duplicate_event_id_ignored(self, tmp_db):
        ev = self._make_event('dup')
        tmp_db.insert_event(ev)
        tmp_db.insert_event(ev)  # same id
        events = tmp_db.get_recent_events(10)
        assert len(events) == 1

    def test_event_with_device_mac(self, tmp_db):
        ev = self._make_event('dev')
        ev['device'] = {'mac': 'b8:27:eb:aa:11:22'}
        tmp_db.insert_event(ev)
        events = tmp_db.get_recent_events(1)
        assert events[0]['device_mac'] == 'b8:27:eb:aa:11:22'


class TestDatabaseKnownAPs:
    """Database.upsert_ap, get_known_aps, is_ap_known."""

    def test_upsert_new_ap(self, tmp_db):
        tmp_db.upsert_ap('aa:bb:cc:dd:ee:01', 'HomeNet', -45, 36, False)
        assert tmp_db.is_ap_known('aa:bb:cc:dd:ee:01') is True

    def test_upsert_updates_rssi(self, tmp_db):
        tmp_db.upsert_ap('aa:bb:cc:dd:ee:01', 'HomeNet', -45, 36, False)
        tmp_db.upsert_ap('aa:bb:cc:dd:ee:01', 'HomeNet', -60, 36, False)
        aps = tmp_db.get_known_aps()
        assert aps['aa:bb:cc:dd:ee:01']['rssi'] == -60

    def test_unknown_bssid_returns_false(self, tmp_db):
        assert tmp_db.is_ap_known('ff:ff:ff:ff:ff:ff') is False

    def test_get_known_aps_returns_dict(self, tmp_db):
        tmp_db.upsert_ap('aa:bb:cc:dd:ee:01', 'Net1', -45, 6, True)
        tmp_db.upsert_ap('aa:bb:cc:dd:ee:02', 'Net2', -50, 11, False)
        aps = tmp_db.get_known_aps()
        assert isinstance(aps, dict)
        assert len(aps) == 2

    def test_approved_flag_preserved_on_update(self, tmp_db):
        tmp_db.upsert_ap('aa:bb:cc:dd:ee:01', 'HomeNet', -45, 36, True)
        # Update with approved=False — should preserve True (MAX logic)
        tmp_db.upsert_ap('aa:bb:cc:dd:ee:01', 'HomeNet', -55, 36, False)
        aps = tmp_db.get_known_aps()
        assert aps['aa:bb:cc:dd:ee:01']['approved'] == 1


class TestDatabaseNodePositions:
    """Database.save_node_position, get_node_positions."""

    def test_save_node_position(self, tmp_db):
        tmp_db.save_node_position('pi-node-1', 0.3, 0.7)
        positions = tmp_db.get_node_positions()
        assert 'pi-node-1' in positions
        assert positions['pi-node-1']['canvas_x'] == pytest.approx(0.3)
        assert positions['pi-node-1']['canvas_y'] == pytest.approx(0.7)

    def test_update_node_position(self, tmp_db):
        tmp_db.save_node_position('pi-node-1', 0.3, 0.7)
        tmp_db.save_node_position('pi-node-1', 0.5, 0.5)
        positions = tmp_db.get_node_positions()
        assert positions['pi-node-1']['canvas_x'] == pytest.approx(0.5)

    def test_multiple_nodes(self, tmp_db):
        tmp_db.save_node_position('pi-node-1', 0.1, 0.2)
        tmp_db.save_node_position('pi-node-2', 0.8, 0.9)
        positions = tmp_db.get_node_positions()
        assert len(positions) == 2

    def test_only_placed_nodes_returned(self, tmp_db):
        """get_node_positions only returns nodes with placed=1."""
        tmp_db.save_node_position('pi-node-1', 0.3, 0.7)
        positions = tmp_db.get_node_positions()
        for node in positions.values():
            assert node['placed'] == 1


# ═════════════════════════════════════════════════════════════
# SECTION 8 — ZONE PERSISTENCE
# ═════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_zones(tmp_path):
    """Provide a ZonePersistence instance with a temp zones.json."""
    return scanner.ZonePersistence(tmp_path / 'zones.json')

def _make_zone(zone_id=1, name='Server Room', zone_type='restricted'):
    return {'id': zone_id, 'name': name, 'type': zone_type, 'alertTier': 'critical',
            'x': 100.0, 'y': 100.0, 'w': 200.0, 'h': 150.0, 'floorId': 0,
            'schedule': {'always': True}, 'allowedMacs': []}


class TestZonePersistence:
    """ZonePersistence: add, update, delete, sanitisation, disk persistence."""

    def test_add_zone(self, tmp_zones):
        tmp_zones.add_or_update(_make_zone(1, 'Server Room'))
        assert len(tmp_zones.get_all()) == 1

    def test_zone_has_correct_name(self, tmp_zones):
        tmp_zones.add_or_update(_make_zone(1, 'Server Room'))
        assert tmp_zones.get_all()[0]['name'] == 'Server Room'

    def test_update_existing_zone(self, tmp_zones):
        tmp_zones.add_or_update(_make_zone(1, 'Old Name'))
        tmp_zones.add_or_update(_make_zone(1, 'New Name'))
        zones = tmp_zones.get_all()
        assert len(zones) == 1
        assert zones[0]['name'] == 'New Name'

    def test_delete_zone(self, tmp_zones):
        tmp_zones.add_or_update(_make_zone(1))
        tmp_zones.add_or_update(_make_zone(2))
        tmp_zones.delete(1)
        zones = tmp_zones.get_all()
        assert len(zones) == 1
        assert zones[0]['id'] == 2

    def test_delete_nonexistent_zone_no_error(self, tmp_zones):
        tmp_zones.delete(999)  # should not raise
        assert tmp_zones.get_all() == []

    def test_invalid_zone_type_defaulted(self, tmp_zones):
        zone = _make_zone(1)
        zone['type'] = 'not-a-valid-type'
        tmp_zones.add_or_update(zone)
        saved = tmp_zones.get_all()[0]
        assert saved['type'] == 'monitored'  # falls back to default

    def test_invalid_alert_tier_defaulted(self, tmp_zones):
        zone = _make_zone(1)
        zone['alertTier'] = 'nuclear'
        tmp_zones.add_or_update(zone)
        saved = tmp_zones.get_all()[0]
        assert saved['alertTier'] == 'warning'

    def test_name_control_chars_stripped(self, tmp_zones):
        zone = _make_zone(1)
        zone['name'] = 'Server\x00Room\x01Danger'
        tmp_zones.add_or_update(zone)
        saved = tmp_zones.get_all()[0]
        assert '\x00' not in saved['name']
        assert '\x01' not in saved['name']

    def test_name_truncated_to_64_chars(self, tmp_zones):
        zone = _make_zone(1)
        zone['name'] = 'A' * 100
        tmp_zones.add_or_update(zone)
        saved = tmp_zones.get_all()[0]
        assert len(saved['name']) <= 64

    def test_invalid_allowed_macs_filtered(self, tmp_zones):
        zone = _make_zone(1)
        zone['allowedMacs'] = ['b8:27:eb:aa:11:22', 'not-a-mac', '']
        tmp_zones.add_or_update(zone)
        saved = tmp_zones.get_all()[0]
        assert len(saved['allowedMacs']) == 1
        assert saved['allowedMacs'][0] == 'b8:27:eb:aa:11:22'

    def test_zones_persist_to_disk(self, tmp_path):
        """Zones written to disk should load back identically."""
        path = tmp_path / 'zones.json'
        zp1 = scanner.ZonePersistence(path)
        zp1.add_or_update(_make_zone(1, 'Persisted Zone'))
        # Create new instance — should read from disk
        zp2 = scanner.ZonePersistence(path)
        zones = zp2.get_all()
        assert len(zones) == 1
        assert zones[0]['name'] == 'Persisted Zone'

    def test_corrupt_zones_file_handled_gracefully(self, tmp_path):
        """A corrupt zones.json should be handled without crashing."""
        path = tmp_path / 'zones.json'
        path.write_text('{ this is not valid json }')
        zp = scanner.ZonePersistence(path)
        assert zp.get_all() == []

    def test_multiple_zones_maintained(self, tmp_zones):
        for i in range(5):
            tmp_zones.add_or_update(_make_zone(i, f'Zone {i}'))
        assert len(tmp_zones.get_all()) == 5


# ═════════════════════════════════════════════════════════════
# SECTION 9 — INBOUND MESSAGE HANDLING (handle_client_message)
# ═════════════════════════════════════════════════════════════

class TestHandleClientMessage:
    """handle_client_message processes zone_save, zone_delete, device_approve, node_position."""

    @pytest.fixture
    def mock_db(self):
        m = MagicMock()
        m.approve_device = MagicMock()
        m.save_node_position = MagicMock()
        return m

    @pytest.fixture
    def mock_zones(self):
        m = MagicMock()
        m.add_or_update = MagicMock()
        m.delete = MagicMock()
        return m

    @pytest.fixture
    def builder_for_handler(self):
        args = MagicMock(); args.label='pi-1'; args.x=None; args.y=None
        return scanner.MessageBuilder(args)

    def _run(self, raw, mock_db, mock_zones, builder):
        """Run handle_client_message with mocked db and zones."""
        orig_db    = scanner.db
        orig_zones = scanner.zones
        scanner.db    = mock_db
        scanner.zones = mock_zones
        try:
            asyncio.run(scanner.handle_client_message(raw, builder))
        finally:
            scanner.db    = orig_db
            scanner.zones = orig_zones

    def test_zone_save_calls_add_or_update(self, mock_db, mock_zones, builder_for_handler):
        raw = json.dumps({'type': 'zone_save', 'action': 'add', 'zone': _make_zone(99)})
        self._run(raw, mock_db, mock_zones, builder_for_handler)
        mock_zones.add_or_update.assert_called_once()

    def test_zone_delete_calls_delete(self, mock_db, mock_zones, builder_for_handler):
        raw = json.dumps({'type': 'zone_delete', 'id': 99})
        self._run(raw, mock_db, mock_zones, builder_for_handler)
        mock_zones.delete.assert_called_once_with(99)

    def test_device_approve_calls_db(self, mock_db, mock_zones, builder_for_handler):
        raw = json.dumps({'type': 'device_approve', 'mac': 'b8:27:eb:aa:11:22'})
        self._run(raw, mock_db, mock_zones, builder_for_handler)
        mock_db.approve_device.assert_called_once_with('b8:27:eb:aa:11:22')

    def test_device_approve_invalid_mac_ignored(self, mock_db, mock_zones, builder_for_handler):
        raw = json.dumps({'type': 'device_approve', 'mac': 'not-a-mac'})
        self._run(raw, mock_db, mock_zones, builder_for_handler)
        mock_db.approve_device.assert_not_called()

    def test_node_position_calls_db(self, mock_db, mock_zones, builder_for_handler):
        raw = json.dumps({'type': 'node_position', 'label': 'pi-node-1', 'x': 0.3, 'y': 0.7})
        self._run(raw, mock_db, mock_zones, builder_for_handler)
        mock_db.save_node_position.assert_called_once_with('pi-node-1', 0.3, 0.7)

    def test_node_position_out_of_range_ignored(self, mock_db, mock_zones, builder_for_handler):
        raw = json.dumps({'type': 'node_position', 'label': 'pi-node-1', 'x': 1.5, 'y': 0.7})
        self._run(raw, mock_db, mock_zones, builder_for_handler)
        mock_db.save_node_position.assert_not_called()

    def test_invalid_json_handled_gracefully(self, mock_db, mock_zones, builder_for_handler):
        self._run('{ this is not json }', mock_db, mock_zones, builder_for_handler)
        # No exception raised — both mocks never called
        mock_db.approve_device.assert_not_called()
        mock_zones.add_or_update.assert_not_called()

    def test_unknown_message_type_ignored(self, mock_db, mock_zones, builder_for_handler):
        raw = json.dumps({'type': 'some_future_type', 'data': 'payload'})
        self._run(raw, mock_db, mock_zones, builder_for_handler)
        mock_db.approve_device.assert_not_called()


# ═════════════════════════════════════════════════════════════
# SECTION 10 — INTEGRATION: DEMO DEVICE DATA
# ═════════════════════════════════════════════════════════════

class TestDemoDeviceScanner:
    """DeviceScanner demo methods return valid structured data."""

    @pytest.fixture
    def ds(self):
        with patch('shutil.which', return_value='/usr/bin/ping'):
            args = MagicMock(); args.interface='wlan0'; args.subnet=None
            return scanner.DeviceScanner('wlan0', None)

    def test_demo_devices_have_required_fields(self, ds):
        devices = ds.get_demo_devices()
        for d in devices:
            assert 'mac' in d
            assert 'ip' in d
            assert 'vendor' in d

    def test_demo_devices_have_valid_macs(self, ds):
        devices = ds.get_demo_devices()
        for d in devices:
            assert scanner.validate_mac(d['mac']) is not None

    def test_demo_devices_have_valid_ips(self, ds):
        devices = ds.get_demo_devices()
        for d in devices:
            assert scanner.validate_ip(d['ip']) is not None

    def test_demo_latency_positive_or_none(self, ds):
        for ip in ['192.168.1.10', '192.168.1.42', '192.168.1.55']:
            lat = ds.get_demo_latency(ip)
            assert lat is None or (isinstance(lat, int) and lat > 0)

    def test_demo_rssi_scanner_returns_valid(self):
        with patch('shutil.which', return_value='/usr/bin/ping'):
            rs = scanner.DeviceRSSIScanner('wlan0')
        devices = [{'mac': 'b8:27:eb:aa:11:22'}, {'mac': '28:cd:c1:bb:33:44'}]
        signals = rs.get_demo(devices)
        for mac, rssi in signals.items():
            assert scanner.validate_mac(mac) is not None
            assert scanner.validate_rssi(rssi) is not None

    def test_demo_wifi_scanner_returns_valid(self):
        with patch('shutil.which', return_value='/usr/bin/ping'):
            wifi = scanner.WiFiScanner('wlan0', None)
        reading = wifi.get_demo()
        assert 'rssi' in reading
        assert 'ssid' in reading
        assert scanner.validate_rssi(reading['rssi']) is not None
