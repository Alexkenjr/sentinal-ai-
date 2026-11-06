import json
import tempfile
import unittest
from pathlib import Path
from sentinelai.service import MonitorSession
from sentinelai.simulation import Simulation, run

ROOT = Path(__file__).resolve().parents[1]


class SimulationTests(unittest.TestCase):
    def test_fifty_ips_and_exact_alert_sources(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            simulation = Simulation(Path(directory) / 'run', hosts=50)
            session = MonitorSession(simulation.path, simulation.db)
            try:
                observed = set()
                while not simulation.complete:
                    _, event = simulation.step()
                    observed.add(event['src_ip'])
                    alerts, warnings = session.poll()
                    self.assertEqual(warnings, [])
                    if simulation.position <= 50:
                        self.assertEqual(alerts, [])
                self.assertEqual(len(observed), 50)
                self.assertEqual(simulation.position, 120)
                report = simulation.report(session.store)
                self.assertTrue(report['passed'])
                self.assertEqual(report['unique_ips'], 50)
                self.assertEqual(len(report['observed_rules']), 15)
                self.assertEqual(report['observed_rules'].count('ssh_brute_force'), 5)
                self.assertEqual(report['observed_rules'].count('suspicious_auth'), 5)
                self.assertEqual(report['observed_rules'].count('port_scan'), 5)
                self.assertEqual(len((simulation.directory / 'ips.txt').read_text().splitlines()), 50)
                self.assertEqual({a['src_ip'] for a in session.store.list_alerts()},
                                 {f'192.0.2.{i}' for i in range(1, 11)})
            finally:
                session.close()

    def test_live_stages_trigger_at_expected_records(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            simulation = Simulation(Path(directory) / 'run')
            session = MonitorSession(simulation.path, simulation.db)
            try:
                expected = {8: 'ssh_brute_force', 9: 'suspicious_auth', 17: 'port_scan'}
                while not simulation.complete:
                    simulation.step()
                    alerts, warnings = session.poll()
                    self.assertEqual(warnings, [])
                    self.assertEqual([a['rule'] for a in alerts],
                                     [expected[simulation.position]] if simulation.position in expected else [])
                self.assertEqual(simulation.position, 19)
                report = simulation.report(session.store)
                self.assertTrue(report['passed'])
                self.assertTrue(json.loads((simulation.directory / 'report.json').read_text())['passed'])
                self.assertEqual(len(json.loads((simulation.directory / 'alerts.json').read_text())), 3)
                self.assertIsNone(simulation.step())
            finally:
                session.close()

    def test_incomplete_run_does_not_claim_success(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            simulation = Simulation(Path(directory) / 'run')
            session = MonitorSession(simulation.path, simulation.db)
            try:
                simulation.step()
                session.poll()
                result = simulation.report(session.store)
                self.assertFalse(result['complete'])
                self.assertFalse(result['passed'])
            finally:
                session.close()

    def test_invalid_interval_creates_no_artifacts(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            for interval in [-1, float('nan'), float('inf')]:
                with self.assertRaises(ValueError):
                    run(directory, interval)
            self.assertEqual(list(Path(directory).iterdir()), [])
