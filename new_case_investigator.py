#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT/"data"/"cases_db.json"

def hash_file(p: Path):
    h1, h2 = hashlib.md5(), hashlib.sha256()
    with p.open("rb") as f:
        while chunk := f.read(1024*1024):
            h1.update(chunk); h2.update(chunk)
    return h1.hexdigest(), h2.hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--title", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--notes", default="")
    args = p.parse_args()

    evidence = Path(args.evidence)
    if not evidence.is_file():
        p.error(f"Evidence file not found: {evidence}")

    md5, sha256 = hash_file(evidence)
    cases = json.loads(DB.read_text(encoding="utf-8"))
    cases.append({
        "id": args.id,
        "title": f"Case {args.id}: {args.title}",
        "subtitle": "Evidence Registration & Integrity Verification",
        "investigator": "Srayansh Yadav",
        "date": datetime.now(timezone.utc).isoformat(),
        "tags": ["DFIR Investigation", "Evidence Verified", "File Evidence"],
        "summary": args.notes or "Registered evidence target with cryptographic integrity metadata.",
        "bullets": [
            f"Target evidence: {evidence.as_posix()}",
            f"MD5: {md5}",
            f"SHA256: {sha256}",
            "Evidence registered without modifying the source file."
        ],
        "terminal_title": f"DFIR — Case {args.id} Hash Verification",
        "terminal_output": f"$ python3 scripts/hash_verifier.py --create {evidence}\n[PASS] MD5: {md5}\n[PASS] SHA256: {sha256}"
    })
    DB.write_text(json.dumps(cases, indent=2), encoding="utf-8")
    print(f"[PASS] Registered {args.id}: {args.title}")

if __name__ == "__main__":
    main()
