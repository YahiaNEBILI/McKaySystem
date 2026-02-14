import json
from pathlib import Path

p = Path("webapp_data/findings.json")  # adjust if your EXPORT_DIR differs
raw = p.read_text(encoding="utf-8")
print("file:", p, "bytes:", len(raw))

payload = json.loads(raw)
print("top-level type:", type(payload).__name__)

if isinstance(payload, dict):
    print("top-level keys:", sorted(payload.keys())[:80])
    for k in ("recommendations","findings","items","results","data","payload","run"):
        v = payload.get(k)
        if isinstance(v, list):
            print(f"key {k!r}: list len={len(v)} first_type={type(v[0]).__name__ if v else None}")
        elif isinstance(v, dict):
            print(f"key {k!r}: dict keys sample={sorted(v.keys())[:40]}")
elif isinstance(payload, list):
    print("list len:", len(payload))
    if payload:
        print("first elem type:", type(payload[0]).__name__)
        if isinstance(payload[0], dict):
            print("first elem keys:", sorted(payload[0].keys())[:60])

