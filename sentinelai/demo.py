"""Deterministic synthetic demo; not an accuracy benchmark."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate(path):
    events = []
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(5):
        events.append(dict(timestamp=(start + timedelta(seconds=i)).isoformat(),
            event_type='auth', src_ip='192.0.2.10', username='demo', service='ssh', outcome='failure'))
    events.append(dict(timestamp=(start + timedelta(seconds=5)).isoformat(),
        event_type='auth', src_ip='192.0.2.10', username='demo', service='ssh', outcome='success'))
    for i in range(8):
        events.append(dict(timestamp=(start + timedelta(seconds=10+i)).isoformat(),
            event_type='connection', src_ip='198.51.100.20', dst_port=1000+i))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
    return path
