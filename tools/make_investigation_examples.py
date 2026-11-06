"""Create synthetic EVE + authentication inputs, without API calls or runtime DBs."""
import shutil
import sys
import tempfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from sentinelai.investigation_demo import generate

destination = root / 'examples/investigation'
destination.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=root) as temporary:
    source, _ = generate(Path(temporary) / 'fixtures')
    for name in ['eve.json', 'auth.jsonl', 'normalized.jsonl', 'eve-normalized.jsonl', 'manifest.json']:
        shutil.copyfile(source / name, destination / name)
print('Synthetic investigation inputs: 15 normalized records, 4 expected alerts, 1 sequence candidate; no reputation API calls.')
