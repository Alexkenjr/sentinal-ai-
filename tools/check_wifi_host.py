"""Probe native collection without putting SSIDs or IP addresses into the release log."""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--app', type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(dir=root) as directory:
    prefix = [str(args.app.resolve())] if args.app else ['-m', 'sentinelai']
    result = subprocess.run([sys.executable, *prefix, 'wifi', '--once', '--json', '--db',
                             str(Path(directory) / 'host.db')], cwd=root,
                            capture_output=True, text=True, timeout=30)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise SystemExit('Native Wi-Fi probe failed to produce structured output')
    if report.get('error'):
        assert result.returncode == 2, result.returncode
        print('NATIVE WI-FI HOST CHECK: UNAVAILABLE; no live-hotspot success claim.')
        print(report['error'])
        print('Verified: unavailable telemetry is explicit and produces no invented alerts.')
        assert report['snapshot'] is None and report['alerts'] == []
    else:
        assert result.returncode == 0, result.stderr
        snapshot = report['snapshot']
        count = len(snapshot['networks'])
        print(f'NATIVE WI-FI HOST CHECK: {count} connected adapter(s); {len(report["warnings"])} coverage warning(s).')
        print('No network identifiers included in the release log. This is not an attack-detection accuracy test.')
