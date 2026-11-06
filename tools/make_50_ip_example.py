"""Build a reusable example feed with exactly 50 synthetic source addresses."""
import sys
from pathlib import Path
import json
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from sentinelai.simulation import scenario

plan = scenario(50)
directory = root / 'examples'
directory.mkdir(exist_ok=True)
(directory / 'simulation_50_ips.jsonl').write_text(
    ''.join(json.dumps(event) + '\n' for _, event in plan), encoding='utf-8')
(directory / 'ips_50.txt').write_text(''.join(f'192.0.2.{i}\n' for i in range(1, 51)), encoding='utf-8')
print('Generated 50 unique source IP addresses and 120 JSONL events.')
