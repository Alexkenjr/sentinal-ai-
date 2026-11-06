"""Regenerate explicitly selected synthetic format examples; never executes a tool."""
import shutil
import sys
import tempfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from sentinelai.tool_simulation import generate
from sentinelai.importers import convert

destination = root / 'examples/network_tools'
destination.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=root) as temporary:
    source = generate(Path(temporary) / 'fixtures')
    convert(source / 'wireshark.csv', 'tshark', source / 'normalized.jsonl')
    for name in ['nmap.xml', 'wireshark.csv', 'wireshark.pcap', 'zeek_conn.jsonl', 'manifest.json', 'ips.txt', 'normalized.jsonl']:
        shutil.copyfile(source / name, destination / name)
print(f'Synthetic examples ready: {destination}; 50 source IPs, 85 packets, 50 inventory hosts/150 services')
