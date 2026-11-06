import copy
import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from sentinelai.core import Store, event_from_line
from sentinelai.importers import import_suricata, convert
from sentinelai.insights import explain, explanation_text, timeline
from sentinelai.investigation_demo import InvestigationSimulation
from sentinelai.service import MonitorSession

ROOT = Path(__file__).resolve().parents[1]


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def run_demo(self):
        simulation = InvestigationSimulation(self.path / 'demo')
        session = MonitorSession(simulation.path, simulation.db)
        self.addCleanup(session.close)
        while not simulation.complete:
            simulation.step()
            session.poll()
        return simulation, session

    def test_cross_source_chain_and_mongolian_explanation_with_logs(self):
        simulation, session = self.run_demo()
        self.assertTrue(simulation.report(session.store)['passed'])
        self.assertEqual(session.store.db.execute('SELECT count(*) FROM events').fetchone()[0], 15)
        alerts = session.store.list_alerts()
        self.assertEqual(len(alerts), 4)
        brute = next(a for a in alerts if a['rule'] == 'ssh_brute_force')
        reason = explain(session.store, brute['id'])
        self.assertEqual(reason['method'], 'offline_evidence')
        self.assertEqual(reason['decision']['threshold'], 5)
        self.assertEqual(len(reason['log_samples']), 5)
        self.assertIn('амжилтгүй', explanation_text(reason))
        chain = timeline(session.store, '192.0.2.10')
        self.assertEqual(len(chain['incidents']), 1)
        self.assertTrue(chain['incidents'][0]['sequence_candidate'])
        self.assertEqual(len(chain['incidents'][0]['events']), 15)

    def test_suricata_different_signatures_preserved_and_replay_deduplicated(self):
        simulation = InvestigationSimulation(self.path / 'fixtures')
        rows = [json.loads(line) for line in (simulation.directory/'eve.json').read_text().splitlines()]
        alert = rows[-1]
        second = copy.deepcopy(alert)
        second['alert']['signature_id'] += 1
        second['alert']['signature'] = 'SYNTHETIC second signature'
        text = '\n'.join(json.dumps(e) for e in [alert, second]) + '\n'
        path = self.path/'eve.json'
        path.write_text(text)
        result = convert(path, 'suricata', self.path/'events.jsonl')
        self.assertEqual(len(result['events']), 2)
        for run in range(2):
            session = MonitorSession(self.path/'events.jsonl', self.path/'alerts.db')
            try:
                self.assertEqual(len(session.poll()[0]), 2 if run == 0 else 0)
                self.assertEqual(len(session.store.list_alerts(attack_type='external_ids', source='suricata')), 2)
                self.assertEqual(session.store.db.execute('SELECT count(*) FROM events').fetchone()[0], 2)
            finally:
                session.close()

    def test_eve_skip_invalid_and_offset_timestamp(self):
        path = self.path/'eve.json'
        row = dict(timestamp='2026-10-21T20:00:00+0800', event_type='alert', src_ip='192.0.2.1',
            dest_ip='198.51.100.1', proto='ICMP', alert=dict(signature_id=1, signature='Synthetic ICMP', severity=1))
        path.write_text(json.dumps(row)+'\n'+json.dumps(dict(event_type='stats'))+'\nBAD\n')
        result = import_suricata(path)
        self.assertEqual((len(result['events']), result['skipped'], result['invalid']), (1,1,1))
        self.assertEqual(result['events'][0]['timestamp'], '2026-10-21T12:00:00+00:00')
        path.write_bytes(b'\xef\xbb\xbf'+(json.dumps(row)+'\n').encode())
        self.assertEqual(import_suricata(path)['events'][0]['provenance']['file_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_timeline_truncation_is_explicit(self):
        _, session = self.run_demo()
        result = timeline(session.store, '192.0.2.10', limit=2)
        self.assertTrue(result['truncated'])
        self.assertEqual(sum(len(i['events']) for i in result['incidents']), 2)
        self.assertFalse(any(i['sequence_candidate'] for i in result['incidents']))

    def test_cli_unicode_explanation_timeline_and_missing_provider_keys(self):
        simulation, session = self.run_demo()
        def run(*args, env=None):
            return subprocess.run([sys.executable, '-m', 'sentinelai', *map(str, args)], cwd=ROOT,
                capture_output=True, encoding='utf-8', timeout=10, env=env)
        result = run('explain', '3', '--db', simulation.db, '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['decision']['threshold'], 5)
        result = run('timeline', '--ip', '192.0.2.10', '--db', simulation.db)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['incidents'][0]['sequence_candidate'])
        env = dict(os.environ, ABUSEIPDB_API_KEY='', VIRUSTOTAL_API_KEY='')
        result = run('reputation', '8.8.8.8', '--provider', 'both', '--db', simulation.db, env=env)
        self.assertEqual(result.returncode, 2)
        self.assertEqual({r['status'] for r in json.loads(result.stdout)}, {'unavailable'})

    def test_no_false_chain_across_targets_usernames_or_gaps(self):
        simulation = InvestigationSimulation(self.path/'scenario')
        for variant in ['target', 'username', 'gap']:
            path = self.path/f'{variant}.jsonl'
            events = [copy.deepcopy(event) for _, event in simulation.plan]
            for event in events:
                if event['event_type'] == 'auth':
                    if variant == 'target':
                        event['dst_ip'] = '198.51.100.99'
                    if variant == 'username' and event['outcome'] == 'success':
                        event['username'] = 'different-user'
                    if variant == 'gap':
                        from datetime import datetime, timedelta
                        event['timestamp'] = (datetime.fromisoformat(event['timestamp'])+timedelta(hours=1)).isoformat()
            path.write_text(''.join(json.dumps(e)+'\n' for e in events))
            session = MonitorSession(path, self.path/f'{variant}.db')
            try:
                session.poll()
                result = timeline(session.store, '192.0.2.10')
                self.assertFalse(any(i['sequence_candidate'] for i in result['incidents']))
            finally:
                session.close()

    def test_old_alert_explanation_does_not_invent_logs_or_threshold(self):
        store = Store(':memory:')
        try:
            store.add(dict(timestamp='2026-10-21T12:00:00+00:00', rule='port_scan', src_ip='192.0.2.1',
                           severity='medium', score=50, evidence={'count': 8, 'window_seconds': 30}), 0)
            result = explain(store, 1)
            self.assertIsNone(result['decision']['threshold'])
            self.assertEqual(result['log_samples'], [])
            self.assertTrue(any('Хуучин' in text for text in result['caveats_mn']))
            self.assertEqual(timeline(store, '192.0.2.1')['incidents'], [])
        finally:
            store.close()

    def test_raw_log_whitelist_excludes_password_and_repeated_rows(self):
        row = dict(timestamp='2026-10-21T12:00:00Z', event_type='auth', src_ip='192.0.2.1', username='user',
                   service='ssh', outcome='failure', password='DO-NOT-STORE')
        path = self.path/'auth.jsonl'
        path.write_text((json.dumps(row)+'\n')*8)
        session = MonitorSession(path, self.path/'auth.db')
        try:
            self.assertEqual(session.poll()[0], [])
            data = session.store.db.execute('SELECT data FROM events').fetchall()
            self.assertEqual(len(data), 1)
            self.assertNotIn('DO-NOT-STORE', data[0][0])
        finally:
            session.close()
