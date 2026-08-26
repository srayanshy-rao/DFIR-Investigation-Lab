#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
from datetime import datetime, timezone

CHUNK = 1024 * 1024

def hash_file(path: Path) -> dict:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            size += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
    return {
        "path": str(path.resolve()),
        "size": size,
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
    }

def main():
    p = argparse.ArgumentParser(description="Create or verify a DFIR evidence hash manifest.")
    p.add_argument("--create", help="file to hash")
    p.add_argument("--verify", help="manifest JSON to verify")
    p.add_argument("--output", default="evidence/evidence_manifest.json")
    args = p.parse_args()

    if args.create:
        path = Path(args.create)
        if not path.is_file():
            print(f"[ERROR] File not found: {path}", file=sys.stderr)
            sys.exit(2)
        result = hash_file(path)
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print("[PASS] Cryptographic Integrity Manifest Created")
        print(f"       MD5    : {result['md5']}")
        print(f"       SHA256 : {result['sha256']}")
        print(f"       Output : {out}")
        return

    if args.verify:
        manifest = json.loads(Path(args.verify).read_text(encoding="utf-8"))
        path = Path(manifest["path"])
        if not path.is_file():
            print(f"[ERROR] Evidence file missing: {path}", file=sys.stderr)
            sys.exit(3)
        current = hash_file(path)
        ok = current["md5"] == manifest["md5"] and current["sha256"] == manifest["sha256"]
        print("[PASS] Cryptographic Integrity VERIFIED" if ok else "[FAIL] HASH MISMATCH")
        sys.exit(0 if ok else 4)

    p.error("Use --create FILE or --verify MANIFEST")

if __name__ == "__main__":
    main()
