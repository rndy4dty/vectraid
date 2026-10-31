"""List expected test datasets and their expected-result files."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "datasets" / "expected-results"

for f in sorted(EXPECTED.glob("*.expected.json")):
    print(f"[dataset] {f.name}")
    print(json.dumps(json.loads(f.read_text()), indent=2)[:300])
