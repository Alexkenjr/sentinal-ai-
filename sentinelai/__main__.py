import argparse
import json
import math
import sqlite3
import sys
import time
from pathlib import Path
from . import __version__
from .core import Store
from .service import MonitorSession, export_alerts
from .paths import data_directory
from .classification import TYPES


def main(argv=None):
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=f'SentinelAI {__version__} local security monitor')
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('gui', help='Open desktop application')
    bot = sub.add_parser('bot', help='Ask a local Ollama AI about stored alert evidence')
    bot.add_argument('question')
    bot.add_argument('--db')
    bot.add_argument('--alert', type=int)
    bot.add_argument('--model')
    investigation = sub.add_parser('investigation-demo', help='Synthetic Suricata + auth chain with Mongolian explanations')
    investigation.add_argument('--gui', action='store_true')
    investigation.add_argument('--directory')
    investigation.add_argument('--interval', type=float, default=0.2)
    tool_demo = sub.add_parser('tools-demo', help='Offline Nmap/Wireshark/Zeek format simulation')
    tool_demo.add_argument('--gui', action='store_true')
    tool_demo.add_argument('--directory')
    tool_demo.add_argument('--interval', type=float, default=0.1)
    importer = sub.add_parser('import-log', help='Read offline Nmap XML, TShark CSV or Zeek JSON conn.log')
    importer.add_argument('format', choices=['nmap', 'tshark', 'zeek', 'suricata'])
    importer.add_argument('path')
    importer.add_argument('--output', required=True, help='Inventory JSON for Nmap; normalized JSONL for flows')
    inventory = sub.add_parser('inventory', help='Filter Nmap XML targets and open services; no attack inference')
    inventory.add_argument('path')
    inventory.add_argument('--ip', help='Target IP or CIDR')
    inventory.add_argument('--port', help='Port/list/ranges')
    inventory.add_argument('--protocol', choices=['tcp', 'udp'])
    inventory.add_argument('--export', help='Filtered services CSV or JSON')
    wifi = sub.add_parser('wifi', help='Monitor this Windows device on public Wi-Fi (read-only)')
    wifi.add_argument('--gui', action='store_true', help='Open dashboard and start Wi-Fi monitoring')
    wifi.add_argument('--once', action='store_true', help='Collect one snapshot and exit')
    wifi.add_argument('--json', action='store_true', help='Print structured telemetry and alerts')
    wifi.add_argument('--db', help='Wi-Fi alert database; defaults to user data folder')
    simulation = sub.add_parser('simulate', help='Run a staged live synthetic demonstration')
    simulation.add_argument('--gui', action='store_true', help='Open dashboard and start simulation')
    simulation.add_argument('--directory', help='Output directory; defaults to your user data folder')
    simulation.add_argument('--hosts', type=int, choices=[6, 50], default=6, help='Distinct source IP count')
    simulation.add_argument('--interval', type=float, default=0.5, help='Seconds per event (terminal only)')
    demo = sub.add_parser('demo', help='Generate synthetic demo and run detection')
    demo.add_argument('--directory', help='Output directory; defaults to your user data folder')
    monitor = sub.add_parser('monitor', help='Monitor normalized JSONL records')
    monitor.add_argument('path')
    monitor.add_argument('--follow', action='store_true')
    monitor.add_argument('--poll', type=float, default=0.5)
    monitor.add_argument('--config')
    monitor.add_argument('--db', help='SQLite path; defaults to your user data folder')
    monitor.add_argument('--color', choices=['auto', 'always', 'never'], default='auto')
    listing = sub.add_parser('alerts', help='Review or export stored alerts')
    listing.add_argument('--db', help='SQLite path; defaults to your user data folder')
    listing.add_argument('--severity', choices=['medium', 'high', 'critical'])
    listing.add_argument('--attack-type', choices=list(TYPES), help='Filter by rule-derived attack/risk family')
    listing.add_argument('--src-ip', help='Source IP or CIDR')
    listing.add_argument('--dst-ip', help='Destination IP or CIDR (only where evidence is available)')
    listing.add_argument('--port', help='Destination port, list or ranges: 22,443,1000-1010')
    listing.add_argument('--protocol', choices=['tcp', 'udp'])
    listing.add_argument('--source', choices=['jsonl', 'tshark', 'zeek', 'suricata', 'windows_wifi'])
    listing.add_argument('--status', choices=['new', 'acknowledged', 'dismissed'])
    listing.add_argument('--limit', type=int, default=1000)
    listing.add_argument('--export', metavar='FILE', help='Export .csv or .json')
    listing.add_argument('--json', action='store_true')
    triage = sub.add_parser('triage', help='Change an alert review status')
    triage.add_argument('id', type=int)
    triage.add_argument('status', choices=['new', 'acknowledged', 'dismissed'])
    triage.add_argument('--db', help='SQLite path; defaults to your user data folder')
    explanation = sub.add_parser('explain', help='Offline evidence-grounded Mongolian alert explanation; no LLM API')
    explanation.add_argument('id', type=int)
    explanation.add_argument('--db')
    explanation.add_argument('--json', action='store_true')
    incident = sub.add_parser('timeline', help='Correlate persisted events by source, target and time')
    incident.add_argument('--ip', required=True)
    incident.add_argument('--db')
    incident.add_argument('--since', help='Timezone-aware ISO timestamp')
    incident.add_argument('--until')
    incident.add_argument('--gap', type=int, default=900)
    incident.add_argument('--limit', type=int, default=5000)
    incident.add_argument('--export')
    reputation = sub.add_parser('reputation', help='On-demand public IP lookup; sends only the IP to chosen provider')
    reputation.add_argument('ip')
    reputation.add_argument('--provider', choices=['abuseipdb','virustotal','both'], default='abuseipdb')
    reputation.add_argument('--db')
    reputation.add_argument('--refresh', action='store_true')
    args = parser.parse_args(argv)
    store = session = None
    try:
        if args.command == 'bot':
            from .bot import ask, evidence_context
            context = evidence_context(args.db or str(data_directory() / 'alerts.sqlite3'), args.alert)
            result = ask(args.question, context, model=args.model)
            print(result['answer'])
            print('\n' + result['caution'])
            return 0
        if args.command == 'investigation-demo':
            if args.gui:
                from .gui import launch
                return launch(investigation=True, data_dir=args.directory)
            from .investigation_demo import run
            return run(args.directory or data_directory(), args.interval)
        if args.command == 'inventory':
            from .importers import import_nmap, inventory_rows, export_inventory
            rows = inventory_rows(import_nmap(args.path), args.ip, args.port, args.protocol)
            if args.export:
                if Path(args.path).resolve() == Path(args.export).resolve():
                    raise ValueError('Output must differ from input')
                export_inventory(rows, args.export)
                print(f'Exported {len(rows)} inventory services; no attack inference.')
            else:
                print(json.dumps(rows, indent=2))
            return 0
        if args.command == 'import-log':
            from .importers import convert
            result = convert(args.path, args.format, args.output)
            if args.format == 'nmap':
                print(f'Inventory only: hosts={result["host_count"]} open_ports={result["open_ports"]}; no attack alerts inferred.')
            else:
                print(f'Imported: records={len(result["events"])} invalid={result["invalid"]} skipped={result["skipped"]}')
            print(result.get('warning', ''))
            print(f'Output: {args.output}')
            return 0
        if args.command == 'tools-demo':
            if args.gui:
                from .gui import launch
                return launch(tools=True, data_dir=args.directory)
            from .tool_simulation import run
            return run(args.directory or data_directory(), args.interval)
        if hasattr(args, 'db'):
            args.db = args.db or str(data_directory() / ('wifi-alerts.sqlite3' if args.command == 'wifi' else 'alerts.sqlite3'))
        if args.command in ('explain', 'timeline', 'reputation'):
            if args.command != 'reputation' and not Path(args.db).is_file():
                raise ValueError('Database does not exist; monitor/import logs first')
            if args.command == 'reputation':
                Path(args.db).parent.mkdir(parents=True, exist_ok=True)
            store = Store(args.db)
            if args.command == 'explain':
                from .insights import explain, explanation_text
                result = explain(store, args.id)
                print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else explanation_text(result))
            elif args.command == 'timeline':
                from .insights import timeline
                result = timeline(store, args.ip, args.since, args.until, args.gap, args.limit)
                output = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
                if args.export:
                    if Path(args.export).resolve() == Path(args.db).resolve():
                        raise ValueError('Export must not overwrite the database')
                    Path(args.export).write_text(output, encoding='utf-8')
                else:
                    print(output)
            else:
                from .reputation import lookup, PROVIDERS
                providers = PROVIDERS if args.provider == 'both' else [args.provider]
                result = [lookup(store, args.ip, p, args.refresh) for p in providers]
                print(json.dumps(result, ensure_ascii=False, indent=2))
                if any(item['status'] == 'unavailable' or item.get('refresh_failed') for item in result):
                    return 2
            return 0
        if args.command == 'wifi':
            if args.gui:
                from .gui import launch
                return launch(wifi=True, wifi_db=args.db)
            from .wifi import run
            return run(args.db, args.once, args.json)
        if args.command == 'gui':
            from .gui import launch
            return launch()
        if args.command == 'simulate':
            if args.gui:
                from .gui import launch
                return launch(simulate=True, data_dir=args.directory, hosts=args.hosts)
            from .simulation import run
            return run(args.directory or data_directory(), args.interval, args.hosts)
        if args.command == 'demo':
            from .demo import generate
            directory = Path(args.directory) if args.directory else data_directory() / 'demo-run'
            directory.mkdir(parents=True, exist_ok=True)
            path = generate(directory / 'events.jsonl')
            return main(['monitor', str(path), '--db', str(directory / 'alerts.sqlite3')])
        if args.command in ('alerts', 'triage'):
            if not Path(args.db).is_file():
                raise ValueError('Alert database does not exist; run a monitor first')
            store = Store(args.db)
            if args.command == 'triage':
                store.set_status(args.id, args.status)
                print(f'Alert {args.id}: {args.status}')
                return 0
            if args.limit < 1:
                raise ValueError('--limit must be positive')
            alerts = store.list_alerts(args.severity, args.status, args.limit, args.attack_type,
                src_ip=args.src_ip, dst_ip=args.dst_ip, port=args.port, protocol=args.protocol, source=args.source)
            if args.export:
                export_alerts(alerts, args.export)
                print(f'Exported {len(alerts)} alerts to {args.export}')
            elif args.json:
                print(json.dumps(alerts, indent=2))
            else:
                for alert in alerts:
                    print(' | '.join(str(alert[k]) for k in ['id', 'timestamp', 'severity', 'score', 'attack_label', 'classification', 'rule', 'src_ip', 'status']))
                if not alerts:
                    print('No matching alerts.')
            return 0
        if not math.isfinite(args.poll) or args.poll <= 0:
            raise ValueError('--poll must be positive')
        if not args.follow and not Path(args.path).is_file():
            raise ValueError('Input file does not exist')
        Path(args.db).parent.mkdir(parents=True, exist_ok=True)
        session = MonitorSession(args.path, args.db, args.config)
        color = args.color == 'always' or args.color == 'auto' and sys.stdout.isatty()
        print(f'SentinelAI v{__version__} | rule-based JSONL monitor', flush=True)
        try:
            while True:
                alerts, warnings = session.poll()
                for warning in warnings:
                    print(f'WARN {warning.lower()}', file=sys.stderr)
                for alert in alerts:
                    message = (f"{alert['severity'].upper():8} risk={alert['score']:3} "
                               f"{alert['rule']:20} {alert['src_ip']} count={alert['evidence']['count']}")
                    shade = {'medium': '93', 'high': '91', 'critical': '95'}[alert['severity']]
                    print(f'\033[{shade}m{message}\033[0m' if color else message, flush=True)
                if not args.follow:
                    break
                time.sleep(args.poll)
        except KeyboardInterrupt:
            pass
        print(f'Summary: {session.summary()}')
        return 0
    except (ValueError, OSError, sqlite3.Error, ImportError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2
    finally:
        if session:
            session.close()
        if store:
            store.close()


if __name__ == '__main__':
    sys.exit(main())
