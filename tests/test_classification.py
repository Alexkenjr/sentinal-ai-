import csv
import json
import tempfile
import unittest
from pathlib import Path
from sentinelai.classification import classify
from sentinelai.core import Store
from sentinelai.service import export_alerts

ROOT = Path(__file__).resolve().parents[1]


class ClassificationTests(unittest.TestCase):
    def test_rule_families_do_not_label_wifi_as_confirmed_attacks(self):
        self.assertEqual(classify('ssh_brute_force')['attack_type'], 'brute_force')
        self.assertEqual(classify('port_scan')['classification'], 'attack_indicator')
        self.assertEqual(classify('wifi_open')['classification'], 'configuration_risk')
        self.assertEqual(classify('wifi_dns_changed')['classification'], 'change_indicator')
        self.assertEqual(classify('new_external_rule')['classification'], 'unclassified')

    def test_filter_before_limit_combines_with_status_and_export(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            store = Store(Path(directory) / 'alerts.db')
            try:
                for i, rule in enumerate(['ssh_brute_force', 'port_scan', 'suspicious_auth', 'wifi_open', 'wifi_dns_changed', 'custom_rule']):
                    store.add(dict(timestamp='2026-10-20T12:00:00+00:00', rule=rule,
                        src_ip=f'192.0.2.{i+1}', score=80, severity='high', evidence={}), 0)
                store.set_status(1, 'acknowledged')
                rows = store.list_alerts('high', 'acknowledged', 1, attack_type='brute_force')
                self.assertEqual([row['id'] for row in rows], [1])
                self.assertEqual(store.list_alerts(status='new', attack_type='brute_force'), [])
                self.assertEqual(store.list_alerts(attack_type='wifi_security')[0]['rule'], 'wifi_open')
                self.assertEqual(store.list_alerts(attack_type='wifi_change')[0]['rule'], 'wifi_dns_changed')
                self.assertEqual(store.list_alerts(attack_type='other')[0]['rule'], 'custom_rule')
                for suffix in ['json', 'csv']:
                    target = Path(directory) / f'filtered.{suffix}'
                    export_alerts(rows, target)
                    if suffix == 'json':
                        result = json.loads(target.read_text())
                    else:
                        with target.open(newline='') as stream:
                            result = list(csv.DictReader(stream))
                    self.assertEqual(len(result), 1)
                    self.assertEqual(result[0]['attack_type'], 'brute_force')
                    self.assertEqual(result[0]['classification'], 'attack_indicator')
            finally:
                store.close()
