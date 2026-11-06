import ctypes
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import json
from pathlib import Path
from sentinelai.core import Store
from sentinelai.wifi import WifiEvaluator, WifiSession
from sentinelai.windows_wifi import Connection, Interface, Association, Guid
from sentinelai.windows_wifi import collect_snapshot

ROOT = Path(__file__).resolve().parents[1]


def snapshot(second=0, **fields):
    network = dict(interface_id='test-adapter', interface='Wi-Fi', ssid='Test hotspot',
        bssid='00:11:22:33:44:55', signal=80, security_enabled=True, auth='WPA2-PSK',
        cipher='CCMP', ip='192.0.2.20', gateway='192.0.2.1', dns=['192.0.2.53'], category='Public')
    network.update(fields)
    return dict(timestamp=f'2026-10-20T12:00:{second:02}+00:00', networks=[network],
                public_firewall_enabled=True, warnings=[])


class WifiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / 'wifi.db')
        self.addCleanup(self.store.close)
        self.evaluator = WifiEvaluator(self.store)

    def test_encrypted_baseline_is_not_reported_as_an_attack(self):
        self.assertEqual(self.evaluator.process(snapshot()), [])

    def test_open_wifi_alert_and_dedup(self):
        value = snapshot(security_enabled=False, auth='Open', cipher='None')
        alerts = self.evaluator.process(value)
        self.assertEqual([a['rule'] for a in alerts], ['wifi_open'])
        self.assertEqual(alerts[0]['evidence']['source_kind'], 'local_device')
        self.assertEqual(self.evaluator.process(value), [])

    def test_legacy_security_and_firewall(self):
        value = snapshot(cipher='TKIP')
        value['public_firewall_enabled'] = False
        rules = {a['rule'] for a in self.evaluator.process(value)}
        self.assertEqual(rules, {'wifi_legacy_security', 'wifi_firewall_disabled'})

    def test_unknown_firewall_not_misreported_disabled(self):
        value = snapshot()
        value['public_firewall_enabled'] = None
        self.assertEqual(self.evaluator.process(value), [])

    def test_partial_coverage_and_collector_metadata_mapping(self):
        network = snapshot()['networks'][0]
        adapter = dict(interface_id='{TEST-ADAPTER}', ip='192.0.2.20', gateway='192.0.2.1',
                       dns=['192.0.2.53'], category='Public')
        for key in ('ip', 'gateway', 'dns', 'category'):
            network.pop(key)
        raw = dict(adapters=[adapter], public_firewall_enabled=None, warnings=['Firewall unavailable'])
        with patch('sentinelai.windows_wifi.wlan_connections', return_value=[network]), \
             patch('sentinelai.windows_wifi.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(raw))):
            value = collect_snapshot()
        self.assertEqual(value['networks'][0]['gateway'], '192.0.2.1')
        session = WifiSession(Path(self.directory.name) / 'partial.db', lambda: value, background=False)
        try:
            session.poll()
            self.assertIn('PARTIAL COVERAGE', session.status_text)
        finally:
            session.close()

    def test_configuration_error_keeps_wifi_data_and_marks_missing_coverage(self):
        with patch('sentinelai.windows_wifi.wlan_connections', return_value=[snapshot()['networks'][0]]), \
             patch('sentinelai.windows_wifi.subprocess.run', side_effect=OSError('blocked')):
            value = collect_snapshot()
        self.assertEqual(len(value['networks']), 1)
        self.assertTrue(value['warnings'])
        self.assertIsNone(value['public_firewall_enabled'])

    def test_gateway_dns_and_roaming_changes_are_review_signals(self):
        self.evaluator.process(snapshot())
        alerts = self.evaluator.process(snapshot(1, gateway='192.0.2.2', dns=['192.0.2.54'], bssid='00:11:22:33:44:66'))
        self.assertEqual({a['rule'] for a in alerts}, {'wifi_gateway_changed', 'wifi_dns_changed', 'wifi_access_point_changed'})
        self.assertIn('not proof', next(a for a in alerts if a['rule'] == 'wifi_access_point_changed')['evidence']['advice'])

    def test_different_network_does_not_trigger_gateway_change(self):
        self.evaluator.process(snapshot())
        self.assertEqual(self.evaluator.process(snapshot(1, ssid='Other hotspot', gateway='192.0.2.2')), [])

    def test_missing_metadata_does_not_destroy_baseline(self):
        self.evaluator.process(snapshot())
        self.assertEqual(self.evaluator.process(snapshot(1, gateway=None, dns=[])), [])
        alerts = self.evaluator.process(snapshot(2, gateway='192.0.2.2', dns=['192.0.2.54']))
        self.assertEqual({a['rule'] for a in alerts}, {'wifi_gateway_changed', 'wifi_dns_changed'})

    def test_restart_keeps_baseline(self):
        self.evaluator.process(snapshot())
        another = Store(Path(self.directory.name) / 'wifi.db')
        try:
            alerts = WifiEvaluator(another).process(snapshot(1, gateway='192.0.2.2'))
            self.assertEqual(alerts[0]['rule'], 'wifi_gateway_changed')
        finally:
            another.close()

    def test_access_denied_and_disconnected_are_not_safe(self):
        def denied():
            raise PermissionError('Access denied')
        session = WifiSession(Path(self.directory.name) / 'session.db', denied, background=False)
        try:
            self.assertEqual(session.poll()[0], [])
            self.assertIn('No safety assessment', session.status_text)
            self.assertIsNotNone(session.error)
            self.assertIsNone(session.last_snapshot)
            value = snapshot()
            value['networks'] = []
            session.collector = lambda: value
            self.assertEqual(session.poll()[0], [])
            self.assertIn('not a safety assessment', session.status_text)
        finally:
            session.close()

    def test_background_collection_does_not_block_poll_or_stop(self):
        release = threading.Event()
        def slow():
            release.wait(2)
            return snapshot()
        session = WifiSession(Path(self.directory.name) / 'thread.db', slow)
        try:
            start = time.monotonic()
            self.assertEqual(session.poll(), ([], []))
            session.close()
            self.assertLess(time.monotonic() - start, 0.5)
        finally:
            release.set()
            session.worker.join(timeout=3)

    @unittest.skipUnless(os.name == 'nt', 'Windows ABI')
    def test_native_structures_match_windows_abi(self):
        self.assertEqual([ctypes.sizeof(c) for c in [Guid, Interface, Association, Connection]], [16, 532, 68, 604])
