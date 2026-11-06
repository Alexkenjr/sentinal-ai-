import hashlib
import ipaddress
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .classification import TYPES, classified
from .filters import validate, ip_matches, evidence_matches

DEFAULTS = {
    'ssh_brute_force': {'window_seconds': 60, 'threshold': 5},
    'port_scan': {'window_seconds': 30, 'threshold': 8},
    'suspicious_auth': {'window_seconds': 300, 'threshold': 3},
}


def configuration(path=None):
    config = json.loads(json.dumps(DEFAULTS))
    if path:
        supplied = json.loads(Path(path).read_text(encoding='utf-8-sig'))
        if not isinstance(supplied, dict):
            raise ValueError('Configuration must be an object')
        for name, values in supplied.items():
            if name not in config or not isinstance(values, dict):
                raise ValueError(f'Unknown rule: {name}')
            if set(values) - {'window_seconds', 'threshold'}:
                raise ValueError(f'Unknown setting for {name}')
            config[name].update(values)
    for values in config.values():
        for value in values.values():
            if type(value) is not int or value < 1:
                raise ValueError('Windows and thresholds must be positive integers')
    return config


def event_from_line(line):
    if isinstance(line, bytes):
        line = line.decode('utf-8-sig')
    event = json.loads(line)
    if not isinstance(event, dict):
        raise ValueError('Event must be an object')
    stamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    if not isinstance(event['src_ip'], str):
        raise ValueError('src_ip must be an IP address string')
    event['src_ip'] = str(ipaddress.ip_address(event['src_ip']))
    if event['event_type'] not in ('auth', 'connection', 'ids_alert'):
        raise ValueError('event_type must be auth, connection or ids_alert')
    if event['event_type'] == 'ids_alert':
        for key in ('signature_id', 'ids_severity'):
            if type(event.get(key)) is not int or event[key] < 1:
                raise ValueError(f'{key} must be a positive integer')
        if not isinstance(event.get('signature'), str) or not event['signature']:
            raise ValueError('IDS signature text is required')
    if event['event_type'] == 'auth':
        if event.get('outcome') not in ('success', 'failure'):
            raise ValueError('auth outcome must be success or failure')
        if not isinstance(event.get('username'), str) or not event['username']:
            raise ValueError('auth username required')
    if event['event_type'] == 'connection':
        port = event.get('dst_port')
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('dst_port must be 1..65535')
    if event.get('dst_ip') is not None:
        if not isinstance(event['dst_ip'], str):
            raise ValueError('dst_ip must be an IP address string')
        event['dst_ip'] = str(ipaddress.ip_address(event['dst_ip']))
    if event.get('dst_port') is not None:
        if type(event['dst_port']) is not int or not 1 <= event['dst_port'] <= 65535:
            raise ValueError('dst_port must be 1..65535')
    if event.get('protocol') is not None:
        allowed = ('tcp', 'udp', 'icmp', 'icmpv6') if event['event_type'] == 'ids_alert' else ('tcp', 'udp')
        if not isinstance(event['protocol'], str) or event['protocol'].lower() not in allowed:
            raise ValueError('protocol must be tcp or udp')
        event['protocol'] = event['protocol'].lower()
    if event.get('source') is not None and (not isinstance(event['source'], str) or not event['source']):
        raise ValueError('source must be a nonempty string')
    event['timestamp'] = stamp.astimezone(timezone.utc).isoformat()
    event['_time'] = stamp.timestamp()
    return event


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.create_function('ip_matches', 2, ip_matches)
        self.db.create_function('evidence_matches', 5, evidence_matches)
        self.db.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE, timestamp TEXT,
            rule TEXT, src_ip TEXT, severity TEXT, score INTEGER, evidence TEXT)''')
        columns = {row[1] for row in self.db.execute('PRAGMA table_info(alerts)')}
        if 'status' not in columns:
            self.db.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'new'")
        self.db.execute('CREATE INDEX IF NOT EXISTS alerts_source_rule ON alerts(rule, src_ip, timestamp)')
        self.db.execute('''CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_time REAL NOT NULL,
            src_ip TEXT NOT NULL, dst_ip TEXT, kind TEXT NOT NULL, source TEXT NOT NULL,
            late INTEGER NOT NULL, data TEXT NOT NULL)''')
        self.db.execute('CREATE INDEX IF NOT EXISTS events_source_time ON events(src_ip,event_time)')
        self.db.commit()

    def add(self, alert, cooldown, exact_key=None):
        # Suppress overlapping windows, including replay and process restarts.
        latest = self.db.execute(
            'SELECT timestamp FROM alerts WHERE rule=? AND src_ip=? ORDER BY timestamp DESC LIMIT 1',
            (alert['rule'], alert['src_ip'])).fetchone()
        if exact_key is None and latest and datetime.fromisoformat(alert['timestamp']).timestamp() <= datetime.fromisoformat(latest[0]).timestamp() + cooldown:
            return False
        fingerprint = hashlib.sha256(('external:' + exact_key if exact_key else json.dumps(alert, sort_keys=True)).encode()).hexdigest()
        with self.db:
            cursor = self.db.execute('INSERT OR IGNORE INTO alerts (fingerprint,timestamp,rule,src_ip,severity,score,evidence) VALUES (?,?,?,?,?,?,?)',
                (fingerprint, alert['timestamp'], alert['rule'], alert['src_ip'], alert['severity'], alert['score'], json.dumps(alert['evidence'])))
        return cursor.rowcount == 1

    def close(self):
        self.db.close()

    def record_event(self, event, late=False):
        keys = ('timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'event_type', 'source',
                'protocol', 'username', 'service', 'outcome', 'event_id', 'signature_id', 'signature',
                'gid', 'rev', 'category', 'ids_severity', 'action', 'flow_id', 'community_id', 'provenance')
        saved = {key: event[key] for key in keys if key in event}
        source = event.get('source', 'jsonl')
        identity = (source + ':' + str(event['event_id']) if event.get('event_id') else
                    json.dumps({k: v for k, v in saved.items() if k != 'provenance'}, sort_keys=True))
        event_id = hashlib.sha256(identity.encode()).hexdigest()
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?)',
                (event_id, event['timestamp'], event['_time'], event['src_ip'], event.get('dst_ip'),
                 event['event_type'], source, int(late), json.dumps(saved)))
        return event_id

    def get_alert(self, alert_id):
        row = self.db.execute('SELECT id,timestamp,rule,src_ip,severity,score,evidence,status FROM alerts WHERE id=?', (alert_id,)).fetchone()
        if not row:
            raise ValueError(f'Alert {alert_id} does not exist')
        alert = dict(zip(['id','timestamp','rule','src_ip','severity','score','evidence','status'], row))
        alert['evidence'] = json.loads(alert['evidence'])
        return classified(alert)

    def list_alerts(self, severity=None, status=None, limit=1000, attack_type=None,
                    *, src_ip=None, dst_ip=None, port=None, protocol=None, source=None):
        filters = validate(src_ip, dst_ip, port, protocol, source)
        query = 'SELECT id,timestamp,rule,src_ip,severity,score,evidence,status FROM alerts WHERE 1=1'
        params = []
        if filters['src_ip']:
            query += ' AND ip_matches(src_ip,?)'
            params.append(filters['src_ip'])
        if any(filters[key] for key in ('dst_ip', 'port', 'protocol', 'source')):
            query += ' AND evidence_matches(evidence,?,?,?,?)'
            params.extend(filters[key] for key in ('dst_ip', 'port', 'protocol', 'source'))
        if attack_type:
            if attack_type not in TYPES:
                raise ValueError('Unknown attack type')
            rules = TYPES[attack_type][2]
            if attack_type == 'other':
                rules = tuple(rule for _, _, group in TYPES.values() for rule in group)
            operator = 'NOT IN' if attack_type == 'other' else 'IN'
            query += f' AND rule {operator} ({",".join("?" for _ in rules)})'
            params.extend(rules)
        for field, value in [('severity', severity), ('status', status)]:
            if value:
                query += f' AND {field}=?'
                params.append(value)
        query += ' ORDER BY id DESC LIMIT ?'
        params.append(limit)
        names = ['id', 'timestamp', 'rule', 'src_ip', 'severity', 'score', 'evidence', 'status']
        result = []
        for row in self.db.execute(query, params):
            alert = dict(zip(names, row))
            alert['evidence'] = json.loads(alert['evidence'])
            result.append(classified(alert))
        return result

    def set_status(self, alert_id, status):
        if status not in ('new', 'acknowledged', 'dismissed'):
            raise ValueError('Invalid alert status')
        with self.db:
            changed = self.db.execute('UPDATE alerts SET status=? WHERE id=?', (status, alert_id))
        if changed.rowcount != 1:
            raise ValueError(f'Alert {alert_id} does not exist')


class Detector:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.events = []
        self.watermark = float('-inf')
        self.late_events = 0

    def process(self, event):
        now = event['_time']
        if event['event_type'] == 'ids_alert':
            score = {1: 90, 2: 70}.get(event['ids_severity'], 50)
            evidence = {key: event.get(key) for key in ('signature_id', 'signature', 'ids_severity',
                'gid', 'rev', 'category', 'action', 'flow_id', 'community_id', 'provenance')}
            evidence.update(source='suricata', count=1, window_seconds=None,
                trigger_log_id=event.get('_record_id'),
                log_ids=[event['_record_id']] if event.get('_record_id') else [],
                destinations=[event['dst_ip']] if event.get('dst_ip') else [],
                dst_ports=[event['dst_port']] if event.get('dst_port') else [],
                protocols=[event['protocol']] if event.get('protocol') else [],
                flows=[dict(dst_ip=event.get('dst_ip'), dst_port=event.get('dst_port'), protocol=event.get('protocol'))])
            alert = dict(timestamp=event['timestamp'], rule='suricata_alert', src_ip=event['src_ip'],
                         severity='critical' if score >= 90 else 'high' if score >= 70 else 'medium',
                         score=score, evidence=evidence)
            key = event.get('event_id') or hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
            return [alert] if self.store.add(alert, 0, exact_key='suricata:' + str(key)) else []
        # Explicit strict event-time ordering prevents stale events changing windows.
        if now < self.watermark:
            self.late_events += 1
            return []
        self.watermark = now
        horizon = max(v['window_seconds'] for v in self.config.values())
        self.events = [e for e in self.events if e['_time'] >= now - horizon]
        self.events.append(event)
        alerts = []
        for rule, settings in self.config.items():
            recent = [e for e in self.events if e['src_ip'] == event['src_ip'] and e['_time'] >= now - settings['window_seconds']]
            failures = [e for e in recent if e['event_type'] == 'auth' and e['outcome'] == 'failure']
            if rule == 'ssh_brute_force':
                relevant = [e for e in failures if e.get('service') == 'ssh']
                count = sum(e.get('service') == 'ssh' for e in failures)
                triggered = event['event_type'] == 'auth' and event.get('service') == 'ssh' and event['outcome'] == 'failure'
                base = 65
            elif rule == 'port_scan':
                relevant = [e for e in recent if e['event_type'] == 'connection']
                count = len({e['dst_port'] for e in recent if e['event_type'] == 'connection'})
                triggered = event['event_type'] == 'connection'
                base = 50
            else:
                relevant = failures + [event]
                count = len(failures)
                triggered = event['event_type'] == 'auth' and event['outcome'] == 'success'
                base = 80
            if not triggered or count < settings['threshold']:
                continue
            score = min(100, base + 5 * (count - settings['threshold']))
            alert = dict(timestamp=datetime.fromtimestamp(now, timezone.utc).isoformat(),
                         rule=rule, src_ip=event['src_ip'], score=score,
                         severity='critical' if score >= 90 else 'high' if score >= 70 else 'medium',
                         evidence={'count': count, 'window_seconds': settings['window_seconds'],
                            'threshold': settings['threshold'],
                            'window_start': datetime.fromtimestamp(now-settings['window_seconds'], timezone.utc).isoformat(),
                            'window_end': datetime.fromtimestamp(now, timezone.utc).isoformat(),
                            'log_ids': list(dict.fromkeys(e['_record_id'] for e in relevant if e.get('_record_id'))),
                            'trigger_log_id': event.get('_record_id'),
                            'source': event.get('source', 'jsonl'),
                            'destinations': sorted({e['dst_ip'] for e in relevant if e.get('dst_ip')}),
                            'dst_ports': sorted({e['dst_port'] for e in relevant if e.get('dst_port')}),
                            'protocols': sorted({e['protocol'] for e in relevant if e.get('protocol')}),
                            'flows': [dict(dst_ip=ip, dst_port=port, protocol=proto) for ip, port, proto in
                                sorted({(e.get('dst_ip', ''), e.get('dst_port', 0), e.get('protocol', '')) for e in relevant})]})
            if self.store.add(alert, settings['window_seconds']):
                alerts.append(alert)
        return alerts


class TailReader:
    """Binary offsets; only complete lines are consumed. Handles replacement/truncation."""
    def __init__(self, path):
        self.path = Path(path)
        self.offset = 0
        self.identity = None
        self.anchor = b''

    def read(self):
        try:
            with self.path.open('rb') as stream:
                import os
                stat = os.fstat(stream.fileno())
                identity = (stat.st_dev, stat.st_ino)
                stream.seek(max(0, self.offset - len(self.anchor)))
                changed = stream.read(len(self.anchor)) != self.anchor
                if identity != self.identity or stat.st_size < self.offset or changed:
                    self.offset = 0
                self.identity = identity
                stream.seek(self.offset)
                data = stream.read()
                end = data.rfind(b'\n') + 1
                self.offset += end
                stream.seek(max(0, self.offset - 64))
                self.anchor = stream.read(min(64, self.offset))
                return data[:end].splitlines()
        except FileNotFoundError:
            return []
