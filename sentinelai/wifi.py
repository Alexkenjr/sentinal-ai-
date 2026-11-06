"""Local Wi-Fi posture monitoring; does not inspect or intercept packets."""
import json
import queue
import threading
from pathlib import Path
from .core import Store
from .windows_wifi import collect_snapshot


class WifiEvaluator:
    def __init__(self, store):
        self.store = store
        store.db.execute('CREATE TABLE IF NOT EXISTS wifi_state (interface_id TEXT PRIMARY KEY, snapshot TEXT NOT NULL)')
        store.db.commit()

    def process(self, snapshot):
        alerts = []
        for network in snapshot['networks']:
            interface_id = network['interface_id']
            row = self.store.db.execute('SELECT snapshot FROM wifi_state WHERE interface_id=?', (interface_id,)).fetchone()
            previous = json.loads(row[0]) if row else {}
            findings = []
            if network.get('security_enabled') is False or network.get('cipher') == 'None':
                findings.append(('wifi_open', 70, 'Wi-Fi link is unencrypted. Use HTTPS and a trusted VPN; avoid sensitive activity.'))
            elif network.get('cipher') in ('WEP', 'WEP40', 'WEP104', 'TKIP') or network.get('auth') in ('Shared', 'WPA', 'WPA-PSK', 'WPA-None'):
                findings.append(('wifi_legacy_security', 80, 'Legacy Wi-Fi protection detected. Prefer a WPA2/WPA3 connection.'))
            elif str(network.get('auth', '')).startswith('Unknown') or str(network.get('cipher', '')).startswith('Unknown'):
                findings.append(('wifi_unknown_security', 50, 'Wi-Fi security type is not recognized; protection could not be assessed.'))
            if network.get('category') in ('Private', 'DomainAuthenticated'):
                findings.append(('wifi_nonpublic_profile', 50, 'A public hotspot is using a trusted network profile. Review Windows network settings.'))
            if network.get('category') == 'Public' and snapshot.get('public_firewall_enabled') is False:
                findings.append(('wifi_firewall_disabled', 80, 'The Windows Public firewall profile is disabled. Review firewall settings.'))
            if previous.get('ssid') == network.get('ssid'):
                for field, rule, score, note in [
                    ('gateway', 'wifi_gateway_changed', 70, 'Gateway changed. DHCP or roaming may explain this; verify the hotspot.'),
                    ('dns', 'wifi_dns_changed', 60, 'DNS servers changed. VPN or DHCP changes may be legitimate; review the configuration.'),
                    ('bssid', 'wifi_access_point_changed', 50, 'Access point changed on the same SSID. Normal roaming is possible; this is not proof of an evil twin.')]:
                    old, new = previous.get(field), network.get(field)
                    if field == 'dns':
                        old, new = sorted(old or []), sorted(new or [])
                    if old and new and old != new:
                        findings.append((rule, score, note))
            for rule, score, advice in findings:
                alert = dict(timestamp=snapshot['timestamp'], rule=rule, src_ip=network.get('ip') or 'unknown',
                    severity='high' if score >= 70 else 'medium', score=score,
                    evidence=dict(source_kind='local_device', interface=network.get('interface'),
                        ssid=network.get('ssid'), auth=network.get('auth'), cipher=network.get('cipher'),
                        gateway=network.get('gateway'), dns=network.get('dns'), bssid=network.get('bssid'),
                        advice=advice, previous=previous if rule.endswith('changed') else None))
                if self.store.add(alert, 300):
                    alerts.append(alert)
            # Preserve known network metadata when a collection is partially unavailable.
            saved = dict(network)
            if previous.get('ssid') == network.get('ssid'):
                for field in ('ip', 'gateway', 'dns', 'category'):
                    if not saved.get(field):
                        saved[field] = previous.get(field)
            with self.store.db:
                self.store.db.execute('INSERT OR REPLACE INTO wifi_state VALUES (?,?)', (interface_id, json.dumps(saved)))
        return alerts


class WifiSession:
    """Collection runs off the Tk thread; database work stays on the caller thread."""
    def __init__(self, db, collector=None, background=True):
        Path(db).parent.mkdir(parents=True, exist_ok=True)
        self.store = Store(db)
        self.evaluator = WifiEvaluator(self.store)
        self.collector = collector or collect_snapshot
        self.records = self.invalid = self.alerts = 0
        self.status_text = 'Collecting local Wi-Fi data. Coverage is not yet known.'
        self.last_snapshot = None
        self.error = None
        self.background = background
        self.stopped = threading.Event()
        self.results = queue.Queue(maxsize=1)
        self.worker = None
        if background:
            self.worker = threading.Thread(target=self._work, daemon=True, name='SentinelAI-WiFi')
            self.worker.start()

    def _collect(self):
        try:
            return self.collector(), None
        except Exception as exc:
            return None, f'Wi-Fi telemetry unavailable: {exc}'

    def _work(self):
        while not self.stopped.is_set():
            result = self._collect()
            try:
                self.results.put_nowait(result)
            except queue.Full:
                pass
            if self.stopped.wait(30):
                return

    def poll(self):
        if self.background:
            try:
                snapshot, error = self.results.get_nowait()
            except queue.Empty:
                return [], []
        else:
            snapshot, error = self._collect()
        self.error = error
        if error:
            self.invalid += 1
            self.last_snapshot = None
            self.status_text = error + ' No safety assessment was made.'
            return [], [self.status_text]
        self.last_snapshot = snapshot
        self.records += 1
        alerts = self.evaluator.process(snapshot)
        self.alerts += len(alerts)
        warnings = snapshot.get('warnings', [])
        networks = snapshot['networks']
        if not networks:
            self.status_text = 'No connected Wi-Fi adapter found. This is not a safety assessment.'
        else:
            networks_text = ' | '.join(f"{n.get('ssid', '?')} / {n.get('auth', '?')} / {n.get('cipher', '?')} / signal {n.get('signal', '?')}%" for n in networks)
            self.status_text = ('PARTIAL COVERAGE: ' if warnings else 'LOCAL WI-FI: ') + networks_text
            if warnings:
                self.status_text += ' | ' + '; '.join(warnings)
            self.status_text += ' | Changes are review signals, not proof of interception.'
        return alerts, warnings

    def summary(self):
        return f'snapshots={self.records} errors={self.invalid} new_alerts={self.alerts}'

    def close(self):
        self.stopped.set()
        self.store.close()


def run(db, once=False, json_output=False):
    import time
    session = WifiSession(db, background=False)
    try:
        while True:
            alerts, warnings = session.poll()
            if json_output:
                print(json.dumps(dict(snapshot=session.last_snapshot, error=session.error, alerts=alerts,
                                      warnings=warnings), ensure_ascii=True), flush=True)
            else:
                print(session.status_text, flush=True)
                for alert in alerts:
                    print(f"{alert['severity'].upper()} {alert['rule']}: {alert['evidence']['advice']}", flush=True)
            if once:
                return 2 if session.error else 0
            time.sleep(30)
    except KeyboardInterrupt:
        return 0
    finally:
        session.close()
