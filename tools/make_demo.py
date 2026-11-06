"""Compatibility wrapper for the shared demo generator."""
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from sentinelai.demo import generate

print(f'Generated synthetic records: {generate(root / "examples" / "demo.jsonl")}')
