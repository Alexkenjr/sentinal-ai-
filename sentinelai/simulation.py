"""Synthetic live feed. Writes local JSONL only; performs no network activity."""
import json
import math
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .service import MonitorSession, export_alerts


def scenario(hosts=6):
    if hosts not in (6, 50):
        raise ValueError('Simulation supports 6 or 50 IP addresses')
    start = datetime.now(timezone.utc)
    plan = []

    def add(stage, **fields):
        plan.append((stage, dict(timestamp=(start + timedelta(seconds=len(plan))).isoformat(), **fields)))

    if hosts == 50:
        for i in range(1, 51):
            add('Baseline - 50 unique IP addresses, no alerts expected', event_type='auth',
                src_ip=f'192.0.2.{i}', username=f'user-{i}', service='ssh', outcome='success')
        for i in range(1, 6):
            for _ in range(5):
                add('SSH failures - five suspicious sources', event_type='auth', src_ip=f'192.0.2.{i}',
                    username=f'user-{i}', service='ssh', outcome='failure')
            add('Successful login after failures', event_type='auth', src_ip=f'192.0.2.{i}',
                username=f'user-{i}', service='ssh', outcome='success')
        for i in range(6, 11):
            for port in range(1000, 1008):
                add('Port scans - five suspicious sources', event_type='connection',
                    src_ip=f'192.0.2.{i}', dst_port=port)
        return plan

    for i in range(3):
        add('Normal traffic - no alert expected', event_type='auth', src_ip=f'203.0.113.{10+i}',
            username='employee', service='ssh', outcome='success')
    for _ in range(5):
        add('SSH brute force - five failed logins', event_type='auth', src_ip='192.0.2.10',
            username='demo-admin', service='ssh', outcome='failure')
    add('Suspicious authentication - success after failures', event_type='auth', src_ip='192.0.2.10',
        username='demo-admin', service='ssh', outcome='success')
    for i in range(8):
        add('Port scan - eight distinct destination ports', event_type='connection',
            src_ip='198.51.100.20', dst_port=1000+i)
    for i in range(2):
        add('Normal traffic resumes - no additional alert expected', event_type='connection',
            src_ip='203.0.113.50', dst_port=443)
    return plan


class Simulation:
    def __init__(self, directory, hosts=6):
        self.plan = scenario(hosts)
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.path = self.directory / 'events.jsonl'
        self.db = self.directory / 'alerts.sqlite3'
        self.path.write_bytes(b'')
        self.ips = sorted({event['src_ip'] for _, event in self.plan}, key=lambda ip: tuple(map(int, ip.split('.'))))
        (self.directory / 'ips.txt').write_text('\n'.join(self.ips) + '\n', encoding='utf-8')
        self.hosts = hosts
        self.position = 0

    @property
    def complete(self):
        return self.position == len(self.plan)

    def step(self):
        if self.complete:
            return None
        stage, event = self.plan[self.position]
        with self.path.open('a', encoding='utf-8', newline='\n') as stream:
            stream.write(json.dumps(event) + '\n')
        self.position += 1
        return stage, event

    def report(self, store):
        alerts = store.list_alerts()
        if self.hosts == 50:
            expected_pairs = [(rule, f'192.0.2.{i}') for i in range(1, 6)
                              for rule in ('ssh_brute_force', 'suspicious_auth')]
            expected_pairs += [('port_scan', f'192.0.2.{i}') for i in range(6, 11)]
        else:
            expected_pairs = [('ssh_brute_force', '192.0.2.10'), ('suspicious_auth', '192.0.2.10'),
                              ('port_scan', '198.51.100.20')]
        expected = sorted(rule for rule, _ in expected_pairs)
        observed = sorted(alert['rule'] for alert in alerts)
        actual_pairs = sorted((alert['rule'], alert['src_ip']) for alert in alerts)
        result = dict(synthetic=True, complete=self.complete, events_written=self.position,
                      unique_ips=len({event['src_ip'] for _, event in self.plan[:self.position]}),
                      expected_unique_ips=len(self.ips), expected_alert_count=len(expected),
                      expected_rules=expected, observed_rules=observed,
                      passed=self.complete and actual_pairs == sorted(expected_pairs))
        export_alerts(alerts, self.directory / 'alerts.json')
        export_alerts(alerts, self.directory / 'alerts.csv')
        (self.directory / 'report.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        return result


def fresh_directory(parent):
    return Path(parent) / ('simulation-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))


def validate_interval(interval):
    if not math.isfinite(interval) or interval < 0:
        raise ValueError('--interval must be a finite nonnegative number')


def run(directory, interval=0.5, hosts=6):
    validate_interval(interval)
    return run_session(Simulation(fresh_directory(directory), hosts), interval)


def run_session(simulation, interval):
    session = MonitorSession(simulation.path, simulation.db)
    print('SentinelAI LIVE SIMULATION | synthetic local events | no network traffic', flush=True)
    print(f'Artifacts: {simulation.directory}', flush=True)
    previous = None
    interrupted = False
    try:
        try:
            while not simulation.complete:
                stage, event = simulation.step()
                if stage != previous:
                    print(f'\nSTAGE: {stage}', flush=True)
                    previous = stage
                detail = event.get('outcome', f"port={event.get('dst_port')}")
                print(f'  [{simulation.position:02}/{len(simulation.plan)}] {event["src_ip"]} {detail}', flush=True)
                alerts, _ = session.poll()
                for alert in alerts:
                    print(f"  ALERT {alert['severity'].upper()} score={alert['score']} {alert['rule']} source={alert['src_ip']}", flush=True)
                if interval and not simulation.complete:
                    time.sleep(interval)
        except KeyboardInterrupt:
            interrupted = True
        result = simulation.report(session.store)
        state = 'INTERRUPTED' if interrupted else 'PASS' if result['passed'] else 'FAIL'
        print(f'\nSimulation {state}: ips={result["unique_ips"]} {session.summary()}', flush=True)
        print('Saved: ips.txt, events.jsonl, alerts.sqlite3, alerts.csv, alerts.json, report.json', flush=True)
        return 130 if interrupted else 0 if result['passed'] else 1
    finally:
        session.close()
