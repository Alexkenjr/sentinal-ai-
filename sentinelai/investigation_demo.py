"""Synthetic cross-source evidence demo; never queries reputation services."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .importers import convert
from .simulation import Simulation, fresh_directory, run_session, validate_interval
from .service import export_alerts
from .insights import explain, timeline


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    start = datetime.now(timezone.utc)
    stamp = lambda second: (start+timedelta(seconds=second)).isoformat()
    rows = [dict(timestamp=stamp(i), event_type='flow', src_ip='192.0.2.10', dest_ip='198.51.100.20',
        src_port=40000+i, dest_port=1000+i, proto='TCP', flow_id=10000+i) for i in range(8)]
    rows.append(dict(timestamp=stamp(8), event_type='alert', src_ip='192.0.2.10', dest_ip='198.51.100.20',
        src_port=40007, dest_port=1007, proto='TCP', flow_id=10007,
        alert=dict(signature_id=1999001, gid=1, rev=1, signature='SYNTHETIC investigation test signature',
                   category='Synthetic test only', severity=2, action='allowed')))
    (directory / 'eve.json').write_text(''.join(json.dumps(row)+'\n' for row in rows), encoding='utf-8')
    result = convert(directory / 'eve.json', 'suricata', directory / 'eve-normalized.jsonl')
    events = result['events']
    auth = [dict(timestamp=stamp(9+i), event_type='auth', source='jsonl', src_ip='192.0.2.10',
        dst_ip='198.51.100.20', dst_port=22, protocol='tcp', username='demo-user', service='ssh',
        outcome='success' if i == 5 else 'failure', event_id=f'SYNTHETIC-AUTH-{i}-{stamp(0)}') for i in range(6)]
    (directory / 'auth.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in auth), encoding='utf-8')
    events.extend(auth)
    events.sort(key=lambda event: event['timestamp'])
    (directory / 'normalized.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events), encoding='utf-8')
    (directory / 'manifest.json').write_text(json.dumps(dict(synthetic=True, records=15, expected_alerts=4,
        expected_sequence='port_scan -> login failures -> successful login', reputation_network_calls=0), indent=2)+'\n', encoding='utf-8')
    return directory, events


class InvestigationSimulation(Simulation):
    def __init__(self, directory):
        self.directory, events = generate(directory)
        self.path = self.directory / 'events.jsonl'
        self.path.write_bytes(b'')
        self.db = self.directory / 'alerts.sqlite3'
        self.plan = [('SYNTHETIC Suricata flow/signature' if e['source']=='suricata' else
                      'SYNTHETIC auth log: '+e['outcome'], e) for e in events]
        self.position, self.hosts, self.ips = 0, 6, ['192.0.2.10']
        (self.directory / 'ips.txt').write_text('192.0.2.10\n', encoding='utf-8')

    def report(self, store):
        alerts = store.list_alerts()
        incident = timeline(store, '192.0.2.10')
        expected = ['port_scan','ssh_brute_force','suspicious_auth','suricata_alert']
        observed = sorted(a['rule'] for a in alerts)
        candidates = sum(i['sequence_candidate'] for i in incident['incidents'])
        result = dict(synthetic=True, complete=self.complete, events_written=self.position,
            unique_ips=len({e['src_ip'] for _,e in self.plan[:self.position]}), expected_unique_ips=1,
            expected_alert_count=4, expected_rules=sorted(expected), observed_rules=observed,
            sequence_candidates=candidates, passed=self.complete and observed==sorted(expected) and candidates==1)
        (self.directory/'timeline.json').write_text(json.dumps(incident, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        for alert in alerts:
            (self.directory/f'explanation-{alert["id"]}.json').write_text(json.dumps(explain(store, alert['id']), ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        export_alerts(alerts, self.directory/'alerts.csv')
        export_alerts(alerts, self.directory/'alerts.json')
        (self.directory/'report.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        return result


def run(directory, interval=0.2):
    validate_interval(interval)
    return run_session(InvestigationSimulation(fresh_directory(directory)), interval)
