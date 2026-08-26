#!/usr/bin/env python3
"""Read-only local browser artifact extractor for Chromium/Firefox where accessible."""

from __future__ import annotations
import argparse, json, os, shutil, sqlite3, tempfile
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()

def chromium_history_candidates():
    return [
        HOME/".config/google-chrome/Default/History",
        HOME/".config/chromium/Default/History",
        HOME/".config/microsoft-edge/Default/History",
    ]

def chrome_us_to_iso(value):
    try:
        # Chromium time = microseconds since 1601-01-01 UTC
        unix_us = int(value) - 11644473600000000
        return datetime.fromtimestamp(unix_us/1_000_000, timezone.utc).isoformat()
    except Exception:
        return None

def extract_chromium(path: Path):
    with tempfile.TemporaryDirectory() as td:
        copy = Path(td)/"History"
        shutil.copy2(path, copy)
        con = sqlite3.connect(copy)
        rows = con.execute("""
            SELECT url, title, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC LIMIT 100
        """).fetchall()
        downloads = []
        try:
            downloads = con.execute("""
                SELECT tab_url, target_path, start_time, end_time
                FROM downloads ORDER BY start_time DESC LIMIT 100
            """).fetchall()
        except sqlite3.Error:
            pass
        con.close()

    events = []
    for url, title, t in rows:
        events.append({"timestamp": chrome_us_to_iso(t), "source":"chrome", "title":"Visited URL", "detail": f"{title or ''} — {url}"})
    for tab_url, target_path, start, end in downloads:
        events.append({"timestamp": chrome_us_to_iso(end or start), "source":"chrome", "title":"Download", "detail": f"{target_path} from {tab_url}"})
    return events

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", default="evidence/live_browser_artifacts.json")
    args = p.parse_args()

    events = []
    for candidate in chromium_history_candidates():
        if candidate.exists():
            try:
                events.extend(extract_chromium(candidate))
                print(f"[PASS] Parsed {candidate}")
            except Exception as exc:
                print(f"[WARN] Could not parse {candidate}: {exc}")

    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"generated_utc": datetime.now(timezone.utc).isoformat(),
                               "artifacts": events}, indent=2), encoding="utf-8")
    print(f"[PASS] Exported {len(events)} browser artifacts -> {out}")

if __name__ == "__main__":
    main()
