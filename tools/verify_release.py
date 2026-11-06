"""Verify application, build a portable zipapp and package selected release files."""
import hashlib
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from sentinelai import __version__

transcript = []


def run(*args, cwd=root, env=None):
    transcript.append('$ python ' + ' '.join(str(a) for a in args))
    result = subprocess.run([sys.executable, *map(str, args)], cwd=cwd,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', timeout=60, env=env)
    transcript.append(result.stdout.rstrip())
    print(result.stdout, end='')
    if result.returncode:
        raise SystemExit(result.returncode)


run('-m', 'unittest', 'discover', '-s', 'tests', '-v')
run('tools/smoke_desktop.py')
dist = root / 'dist'
dist.mkdir(exist_ok=True)
portable = dist / 'SentinelAI.pyz'
with zipfile.ZipFile(portable, 'w', zipfile.ZIP_DEFLATED) as app:
    app.writestr('__main__.py', 'import sys\nfrom sentinelai.__main__ import main\nsys.exit(main(sys.argv[1:] or ["gui"]))\n')
    for path in sorted((root / 'sentinelai').glob('*.py')):
        app.write(path, 'sentinelai/' + path.name)
run('tools/check_wifi_host.py', '--app', portable)
with tempfile.TemporaryDirectory(dir=root) as directory:
    directory = Path(directory)
    run(portable, 'demo', '--directory', directory / 'demo', cwd=directory)
    db = directory / 'demo' / 'alerts.sqlite3'
    run(portable, 'monitor', directory / 'demo' / 'events.jsonl', '--db', db, '--color', 'never', cwd=directory)
    run(portable, 'triage', '1', 'acknowledged', '--db', db, cwd=directory)
    run(portable, 'alerts', '--db', db, '--status', 'acknowledged', '--json', cwd=directory)
    run(portable, 'alerts', '--db', db, '--export', directory / 'alerts.csv', cwd=directory)
    run(portable, 'simulate', '--directory', directory / 'simulation', '--interval', '0', cwd=directory)
    run(portable, 'simulate', '--hosts', '50', '--directory', directory / 'fifty', '--interval', '0', cwd=directory)
    run(portable, 'tools-demo', '--directory', directory / 'tools', '--interval', '0', cwd=directory)
    tool_run = next((directory / 'tools').glob('simulation-*'))
    run(portable, 'inventory', tool_run / 'nmap.xml', '--ip', '192.0.2.1', '--port', '22,443',
        '--export', directory / 'services.csv', cwd=directory)
    run(portable, 'import-log', 'tshark', tool_run / 'wireshark.csv', '--output', directory / 'packets.jsonl', cwd=directory)
    run(portable, 'monitor', directory / 'packets.jsonl', '--db', directory / 'packets.db', cwd=directory)
    run(portable, 'alerts', '--db', directory / 'packets.db', '--src-ip', '192.0.2.1',
        '--dst-ip', '198.51.100.80', '--port', '1000-1007', '--protocol', 'tcp', '--source', 'tshark', '--json', cwd=directory)
    run(portable, 'import-log', 'zeek', tool_run / 'zeek_conn.jsonl', '--output', directory / 'zeek.jsonl', cwd=directory)
    run(portable, 'investigation-demo', '--directory', directory / 'investigation', '--interval', '0', cwd=directory)
    investigation_run = next((directory / 'investigation').glob('simulation-*'))
    run(portable, 'import-log', 'suricata', investigation_run / 'eve.json', '--output', directory / 'eve.jsonl', cwd=directory)
    run(portable, 'explain', '3', '--db', investigation_run / 'alerts.sqlite3', '--json', cwd=directory)
    run(portable, 'timeline', '--ip', '192.0.2.10', '--db', investigation_run / 'alerts.sqlite3',
        '--export', directory / 'timeline.json', cwd=directory)
    run(portable, 'reputation', '192.0.2.10', '--provider', 'both', '--db', investigation_run / 'alerts.sqlite3', cwd=directory)
    if os.name == 'nt':
        env = dict(os.environ, LOCALAPPDATA=str(directory / 'profile'))
        env.pop('SENTINELAI_DATA_DIR', None)
        run(portable, 'simulate', '--hosts', '50', '--interval', '0',
            cwd=Path(os.environ['SystemRoot']) / 'System32', env=env)
(root / 'VERIFICATION.txt').write_text('\n\n'.join(transcript) + '\n', encoding='utf-8')
files = ['README.md', 'AI_BOT.md', 'VERIFICATION.txt', 'config.json', 'terminal_preview.py', '.gitignore',
         'pyproject.toml', 'PUBLIC_WIFI.md', 'INTEGRATIONS.md', 'INVESTIGATION.md', 'Start-SentinelAI.bat', 'Start-Demo.bat', 'Start-50-IP-Demo.bat', 'Start-Public-WiFi.bat', 'Start-Tools-Demo.bat', 'Start-Investigation-Demo.bat']
for folder in ['sentinelai', 'tests', 'tools']:
    files.extend(str(p.relative_to(root)) for p in (root / folder).glob('*.py'))
files.append('examples/demo.jsonl')
files.extend(['examples/ips_50.txt', 'examples/simulation_50_ips.jsonl'])
files.extend(str(p.relative_to(root)) for p in sorted((root / 'examples/network_tools').iterdir())
             if p.is_file() and p.suffix in ('.xml', '.csv', '.pcap', '.jsonl', '.json', '.txt'))
files.extend(str(p.relative_to(root)) for p in sorted((root / 'examples/investigation').iterdir())
             if p.is_file() and p.suffix in ('.jsonl', '.json'))
archive = dist / f'SentinelAI-v{__version__}-source.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
    prefix = f'SentinelAI-v{__version__}/'
    for name in sorted(files):
        package.write(root / name, prefix + name.replace('\\', '/'))
    package.write(portable, prefix + portable.name)
with zipfile.ZipFile(archive) as package:
    assert package.testzip() is None
    with tempfile.TemporaryDirectory(dir=root) as directory:
        package.extractall(directory)
        extracted = Path(directory) / f'SentinelAI-v{__version__}'
        result = subprocess.run([sys.executable, '-m', 'sentinelai', '--version'], cwd=extracted,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stdout.strip() == __version__, result.stderr
checksums = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in [portable, archive])
(dist / 'SHA256SUMS.txt').write_text(checksums, encoding='utf-8')
print(f'Verified portable app: {portable} ({portable.stat().st_size} bytes)')
print(f'Verified source archive: {archive} ({archive.stat().st_size} bytes)')
print('Archive extraction and source entry point: OK. SHA256SUMS.txt written.')
