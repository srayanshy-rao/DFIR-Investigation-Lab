#!/usr/bin/env python3
"""Simple non-destructive magic-byte carver for lab images."""

from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

SIGNATURES = {
    "pdf": (b"%PDF-", b"%%EOF"),
    "png": (b"\x89PNG\r\n\x1a\n", b"IEND"),
    "jpg": (b"\xff\xd8\xff", b"\xff\xd9"),
    "zip": (b"PK\x03\x04", b"PK\x05\x06"),
}

def carve(data: bytes, kind: str, start: int, end: int) -> bytes | None:
    sig, tail = SIGNATURES[kind]
    pos = data.find(sig, start, end)
    if pos < 0: return None
    tail_pos = data.find(tail, pos + len(sig), end)
    if tail_pos < 0: return None
    tail_end = tail_pos + len(tail)
    return data[pos:tail_end]

def main():
    p = argparse.ArgumentParser(description="Recover lab files using magic-byte signatures.")
    p.add_argument("--image", required=True)
    p.add_argument("--output", default="working/carved_output")
    args = p.parse_args()

    image = Path(args.image)
    if not image.is_file(): p.error(f"Image not found: {image}")

    data = image.read_bytes()
    out = Path(args.output); out.mkdir(parents=True, exist_ok=True)
    manifest = []
    counter = 1

    for kind in SIGNATURES:
        cursor = 0
        while cursor < len(data):
            blob = carve(data, kind, cursor, len(data))
            if blob is None: break
            path = out / f"CARV-{counter:03d}.{kind}"
            path.write_bytes(blob)
            manifest.append({
                "id": path.stem, "type": kind, "offset": data.find(blob, cursor),
                "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest(),
                "path": str(path)
            })
            counter += 1
            cursor = data.find(blob, cursor) + len(blob)

    (out/"carving_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[PASS] Recovered {len(manifest)} file(s)")
    print(f"[INFO] Manifest: {out/'carving_manifest.json'}")

if __name__ == "__main__":
    main()
