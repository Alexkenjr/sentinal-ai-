import json
import tempfile
import unittest
import subprocess
import sys
import time
from pathlib import Path
from sentinelai.core import Detector, Store, TailReader, configuration, event_from_line

ROOT = Path(__file__).resolve().parents[1]


def temporary_directory():
    return tempfile.TemporaryDirectory(dir=ROOT)


def event(second, kind='auth', **extra):
    value = dict(timestamp=f'2026-01-01T00:{second // 60:02}:{second % 60:02}Z',
                 src_ip='192.0.2.10', event_type=kind)
    if kind == 'auth':
        value.update(username='demo', service='ssh', outcome='failure')
    else:
        value['dst_port'] = 22
    value.update(extra)
    return event_from_line(json.dumps(value))


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.addCleanup(self.store.close)
        self.detector = Detector(configuration(), self.store)

    def test_brute_force_threshold_and_dedup(self):
        for i in range(4):
            self.assertEqual(self.detector.process(event(i)), [])
        alerts = self.detector.process(event(4))
        self.assertEqual(alerts[0]['rule'], 'ssh_brute_force')
        self.assertEqual(alerts[0]['score'], 65)
        self.assertEqual(self.detector.process(event(5)), [])

    def test_window_expiry(self):
        for i in range(4):
            self.detector.process(event(i))
        self.assertEqual(self.detector.process(event(64)), [])

    def test_boundary_inclusive(self):
        for i in range(4):
            self.detector.process(event(i))
        self.assertEqual(len(self.detector.process(event(60))), 1)

    def test_distinct_ports_and_source_isolation(self):
        for i in range(10):
            self.assertEqual(self.detector.process(event(i, 'connection')), [])
        for i in range(6):
            self.assertEqual(self.detector.process(event(10+i, 'connection', dst_port=100+i)), [])
        self.assertEqual(self.detector.process(event(16, 'connection', dst_port=999, src_ip='192.0.2.11')), [])
        self.assertEqual(self.detector.process(event(17, 'connection', dst_port=999))[0]['rule'], 'port_scan')

    def test_suspicious_success_and_critical_scoring(self):
        for i in range(5):
            self.detector.process(event(i, service='web'))
        alert = self.detector.process(event(5, service='web', outcome='success'))[0]
        self.assertEqual(alert['rule'], 'suspicious_auth')
        self.assertEqual(alert['severity'], 'critical')

    def test_late_event_dropped(self):
        self.detector.process(event(10))
        self.assertEqual(self.detector.process(event(1)), [])
        self.assertEqual(self.detector.late_events, 1)

    def test_configurable_threshold(self):
        config = configuration()
        config['ssh_brute_force']['threshold'] = 1
        self.assertEqual(len(Detector(config, self.store).process(event(0))), 1)

    def test_restart_dedup_and_cooldown(self):
        with temporary_directory() as directory:
            path = str(Path(directory) / 'alerts.db')
            for run in range(2):
                store = Store(path)
                detector = Detector(configuration(), store)
                results = [a for i in range(5) for a in detector.process(event(i))]
                self.assertEqual(len(results), 1 if run == 0 else 0)
                store.close()
            store = Store(path)
            detector = Detector(configuration(), store)
            results = [a for i in range(70, 75) for a in detector.process(event(i))]
            self.assertEqual(len(results), 1)
            store.close()

    def test_invalid_schema(self):
        for value in ['{}', '[]', '{', json.dumps(dict(timestamp='2026-01-01', src_ip='bad', event_type='auth'))]:
            with self.assertRaises((ValueError, KeyError)):
                event_from_line(value)


class ReaderTests(unittest.TestCase):
    def test_append_partial_truncate_rotate_missing(self):
        with temporary_directory() as directory:
            path = Path(directory) / 'events.jsonl'
            reader = TailReader(path)
            self.assertEqual(reader.read(), [])
            path.write_bytes(b'one\npar')
            self.assertEqual(reader.read(), [b'one'])
            self.assertEqual(reader.read(), [])
            with path.open('ab') as stream:
                stream.write(b'tial\n')
            self.assertEqual(reader.read(), [b'partial'])
            path.write_bytes(b'new\n')
            self.assertEqual(reader.read(), [b'new'])
            path.rename(path.with_suffix('.old'))
            path.write_bytes(b'rotated\n')
            self.assertEqual(reader.read(), [b'rotated'])
            path.write_bytes(b'rewritten-longer\n')
            self.assertEqual(reader.read(), [b'rewritten-longer'])

    def test_invalid_configuration(self):
        with temporary_directory() as directory:
            path = Path(directory) / 'config.json'
            for value in [[], {'bad': {}}, {'port_scan': {'threshold': 0}}, {'port_scan': {'threshold': True}}]:
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    configuration(path)


class CLITests(unittest.TestCase):
    def test_live_append_partial_line_and_persistence(self):
        with temporary_directory() as directory:
            path = Path(directory) / 'live.jsonl'
            db = Path(directory) / 'live.db'
            path.write_bytes(b'')
            process = subprocess.Popen([sys.executable, '-u', '-m', 'sentinelai', 'monitor',
                str(path), '--follow', '--poll', '0.02', '--db', str(db), '--color', 'always'],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertIn('SentinelAI v', process.stdout.readline())
                records = []
                for i in range(5):
                    value = event(i)
                    del value['_time']
                    records.append(json.dumps(value))
                # Initial invalid record must not stop following. Last record is unfinished.
                path.write_bytes(('invalid\n' + '\n'.join(records)).encode())
                time.sleep(0.15)
                store = Store(db)
                self.assertEqual(store.db.execute('SELECT count(*) FROM alerts').fetchone()[0], 0)
                store.close()
                with path.open('ab') as stream:
                    stream.write(b'\n')
                deadline = time.monotonic() + 5
                persisted = 0
                while time.monotonic() < deadline:
                    store = Store(db)
                    persisted = store.db.execute('SELECT count(*) FROM alerts').fetchone()[0]
                    store.close()
                    if persisted:
                        break
                    time.sleep(0.02)
                self.assertEqual(persisted, 1)
            finally:
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
            self.assertIn('\033[93mMEDIUM', stdout)
            self.assertIn('WARN invalid record', stderr)

    def test_missing_input_is_friendly_error(self):
        with temporary_directory() as directory:
            result = subprocess.run([sys.executable, '-m', 'sentinelai', 'monitor',
                str(Path(directory) / 'absent'), '--db', str(Path(directory) / 'db')],
                cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('ERROR:', result.stderr)


if __name__ == '__main__':
    unittest.main()
