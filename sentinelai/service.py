"""Monitoring workflow shared by desktop and terminal interfaces."""
import csv
import json
from pathlib import Path
from .core import Detector, Store, TailReader, configuration, event_from_line
from .classification import classified


class MonitorSession:
    def __init__(self, path, db, config=None):
        settings = configuration(config)
        self.store = Store(db)
        self.detector = Detector(settings, self.store)
        self.reader = TailReader(path)
        self.records = self.invalid = self.alerts = 0
        self.seen_events = set()

    def poll(self):
        alerts, warnings = [], []
        for line in self.reader.read():
            try:
                event = event_from_line(line)
            except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, OverflowError):
                self.invalid += 1
                warnings.append(f'Invalid record #{self.records + self.invalid}')
                continue
            self.records += 1
            event['_record_id'] = self.store.record_event(event,
                late=event['event_type'] != 'ids_alert' and event['_time'] < self.detector.watermark)
            if event['_record_id'] in self.seen_events:
                continue
            self.seen_events.add(event['_record_id'])
            alerts.extend(self.detector.process(event))
        self.alerts += len(alerts)
        return alerts, warnings

    def summary(self):
        return (f'records={self.records} invalid={self.invalid} '
                f'late={self.detector.late_events} new_alerts={self.alerts}')

    def close(self):
        self.store.close()


def export_alerts(alerts, path):
    alerts = [classified(alert) for alert in alerts]
    path = Path(path)
    if path.suffix.lower() == '.csv':
        with path.open('w', encoding='utf-8', newline='') as stream:
            fields = ['id', 'timestamp', 'attack_type', 'attack_label', 'classification', 'rule', 'src_ip', 'severity', 'score', 'status', 'evidence']
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for alert in alerts:
                writer.writerow({**alert, 'evidence': json.dumps(alert['evidence'], sort_keys=True)})
    else:
        path.write_text(json.dumps(alerts, indent=2) + '\n', encoding='utf-8')
