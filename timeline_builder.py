#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from datetime import datetime

def normalise(item: dict, source: str) -> dict | None:
    ts = item.get("timestamp") or item.get("time") or item.get("created_utc")
    title = item.get("title") or item.get("event") or item.get("name") or "Artifact Event"
    detail = item.get("detail") or item.get("description") or item.get("url") or ""
    if ts is None: return None
    return {"timestamp": str(ts), "source": source, "title": title, "detail": detail}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--inputs", nargs="+", required=True)
    p.add_argument("--output", default="timeline/master_timeline.md")
    args = p.parse_args()

    events = []
    for raw in args.inputs:
        path = Path(raw)
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload if isinstance(payload, list) else payload.get("events", payload.get("artifacts", []))
        for item in items:
            ev = normalise(item, path.name)
            if ev: events.append(ev)

    events.sort(key=lambda x: x["timestamp"])
    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Master DFIR Timeline", "",
        "| Timestamp | Source | Event | Detail |",
        "|---|---|---|---|"
    ]
    for e in events:
        detail = str(e["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {e['timestamp']} | {e['source']} | {e['title']} | {detail} |")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[PASS] Master DFIR Timeline built with {len(events)} events -> {out}")

if __name__ == "__main__":
    main()
