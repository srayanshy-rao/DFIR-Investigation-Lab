#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path
import mimetypes

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT/"reports"; REPORTS.mkdir(exist_ok=True)

def digest(path: Path):
    md5, sha = hashlib.md5(), hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024*1024):
            md5.update(chunk); sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()

def main():
    p = argparse.ArgumentParser(description="One-click non-destructive DFIR triage.")
    p.add_argument("target", nargs="?", default="data/cases_db.json")
    p.add_argument("--title", default="Quick DFIR Triage")
    args = p.parse_args()

    target = Path(args.target)
    if not target.is_absolute(): target = ROOT/target
    if not target.exists(): p.error(f"Target not found: {target}")

    files = [target] if target.is_file() else [x for x in target.rglob("*") if x.is_file()]
    results = []
    for f in files[:500]:
        md5, sha = digest(f)
        results.append({
            "path": str(f.relative_to(ROOT) if f.is_relative_to(ROOT) else f),
            "size": f.stat().st_size,
            "mime": mimetypes.guess_type(f.name)[0] or "application/octet-stream",
            "md5": md5, "sha256": sha
        })

    ts = datetime.now(timezone.utc).isoformat()
    report = REPORTS/f"{re.sub(r'[^A-Za-z0-9_-]+','_',args.title).strip('_')}.md"
    lines = [
        f"# {args.title}", "",
        f"**Generated (UTC):** {ts}", "",
        "> Lab note: this is non-destructive triage. It does not replace FTK Imager/Autopsy/Volatility acquisition or analysis.",
        "",
        "## Evidence summary", "",
        f"- Target: `{target}`",
        f"- Files inspected: **{len(results)}**",
        "",
        "## Integrity results", "",
        "| Path | Size | MIME | MD5 | SHA-256 |",
        "|---|---:|---|---|---|",
    ]
    for r in results:
        lines.append(f"| `{r['path']}` | {r['size']} | {r['mime']} | `{r['md5']}` | `{r['sha256']}` |")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[PASS] Investigation report written to {report}")
    print(f"[PASS] Inspected {len(results)} file(s)")

if __name__ == "__main__":
    main()
