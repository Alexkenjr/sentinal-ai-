import csv
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from sentinelai.core import Store, event_from_line
from sentinelai.demo import generate
from sentinelai.service import MonitorSession, export_alerts

ROOT = Path(__file__).resolve().parents[1]


class ProductTests(unittest.TestCase):
    def test_full_workflow_export_filter_triage_and_replay(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            directory = Path(directory)
            path = generate(directory / 'events.jsonl')
            db = directory / 'alerts.sqlite3'
            session = MonitorSession(path, db)
            try:
                alerts, warnings = session.poll()
                self.assertEqual(len(alerts), 3)
                self.assertEqual(warnings, [])
                self.assertEqual(session.poll(), ([], []))
                rows = session.store.list_alerts(severity='critical')
                self.assertEqual(len(rows), 1)
                session.store.set_status(rows[0]['id'], 'acknowledged')
                self.assertEqual(len(session.store.list_alerts(status='acknowledged')), 1)
                for suffix in ['json', 'csv']:
                    target = directory / f'export.{suffix}'
                    export_alerts(session.store.list_alerts(), target)
                    if suffix == 'json':
                        data = json.loads(target.read_text())
                    else:
                        with target.open(newline='') as stream:
                            data = list(csv.DictReader(stream))
                    self.assertEqual(len(data), 3)
                with self.assertRaises(ValueError):
                    session.store.set_status(99999, 'dismissed')
                with self.assertRaises(ValueError):
                    session.store.set_status(1, 'unknown')
            finally:
                session.close()
            replay = MonitorSession(path, db)
            try:
                self.assertEqual(replay.poll()[0], [])
            finally:
                replay.close()

    def test_original_v02_database_migrates_without_losing_alerts(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'legacy.db'
            db = sqlite3.connect(path)
            db.execute('CREATE TABLE alerts (id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE, timestamp TEXT, rule TEXT, src_ip TEXT, severity TEXT, score INTEGER, evidence TEXT)')
            db.execute("INSERT INTO alerts VALUES (1,'abc','2026-01-01T00:00:00+00:00','port_scan','192.0.2.1','medium',50,'{}')")
            db.commit()
            db.close()
            store = Store(path)
            try:
                self.assertEqual(store.list_alerts()[0]['status'], 'new')
                store.set_status(1, 'acknowledged')
            finally:
                store.close()

    def test_cli_demo_triage_and_json_export(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            def run(*args):
                result = subprocess.run([sys.executable, '-m', 'sentinelai', *map(str, args)],
                                        cwd=ROOT, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout
            self.assertIn('new_alerts=3', run('demo', '--directory', directory))
            db = Path(directory) / 'alerts.sqlite3'
            run('triage', '1', 'acknowledged', '--db', db)
            rows = json.loads(run('alerts', '--db', db, '--status', 'acknowledged', '--json'))
            self.assertEqual([row['id'] for row in rows], [1])
            target = Path(directory) / 'critical.json'
            run('alerts', '--db', db, '--severity', 'critical', '--export', target)
            self.assertEqual(len(json.loads(target.read_text())), 1)
            typed = json.loads(run('alerts', '--db', db, '--attack-type', 'port_scan', '--json'))
            self.assertEqual(len(typed), 1)
            self.assertEqual(typed[0]['attack_label'], 'Port scanning')

    def test_normalized_ips_and_nonstring_rejection(self):
        value = dict(timestamp='2026-01-01T00:00:00Z', src_ip='2001:0db8::1',
                     event_type='connection', dst_port=22)
        self.assertEqual(event_from_line(json.dumps(value))['src_ip'], '2001:db8::1')
        value['src_ip'] = 12345
        with self.assertRaises(ValueError):
            event_from_line(json.dumps(value))
