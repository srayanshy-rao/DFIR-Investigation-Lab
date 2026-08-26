from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, shutil, mimetypes, uuid, math, zipfile

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "cases_db.json"
UPLOADS = BASE / "uploads"
REPORTS = BASE / "reports"
TIMELINE = BASE / "timeline"

for p in (UPLOADS, REPORTS, TIMELINE):
    p.mkdir(exist_ok=True)

app = FastAPI(title="DFIR Investigation Lab", version="3.0.0")

SIGNATURES = [
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"PK\x03\x04", "ZIP-based container"),
    (b"MZ", "Windows executable"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"ID3", "MP3 audio"),
]

RISK_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1",
    ".js", ".vbs", ".jar", ".apk"
}


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(path: Path) -> float:
    counts = [0] * 256
    total = 0
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            total += len(chunk)
            for b in chunk:
                counts[b] += 1
    if not total:
        return 0.0
    value = -sum((c / total) * math.log2(c / total) for c in counts if c)
    return round(value, 4)


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def inspect_zip(path: Path, suffix: str):
    suffix = suffix.lower()
    if suffix == ".docx":
        return "Microsoft Word document (DOCX)"
    if suffix == ".xlsx":
        return "Microsoft Excel workbook (XLSX)"
    if suffix == ".pptx":
        return "Microsoft PowerPoint presentation (PPTX)"
    if suffix == ".apk":
        return "Android application package (APK)"
    if suffix == ".jar":
        return "Java archive (JAR)"

    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            if "[Content_Types].xml" in names:
                if any(n.startswith("word/") for n in names):
                    return "Microsoft Word document (DOCX)"
                if any(n.startswith("xl/") for n in names):
                    return "Microsoft Excel workbook (XLSX)"
                if any(n.startswith("ppt/") for n in names):
                    return "Microsoft PowerPoint presentation (PPTX)"
    except Exception:
        pass
    return "ZIP archive"


def detect_signature(path: Path):
    with path.open("rb") as f:
        header = f.read(64)

    suffix = path.suffix.lower()
    for sig, name in SIGNATURES:
        if header.startswith(sig):
            if sig == b"PK\x03\x04":
                name = inspect_zip(path, suffix)
            return name, sig.hex(" ")

    return "Unknown / unsupported signature", header[:16].hex(" ")


def expected_types(ext: str):
    return {
        ".pdf": {"PDF document"},
        ".png": {"PNG image"},
        ".jpg": {"JPEG image"},
        ".jpeg": {"JPEG image"},
        ".docx": {"Microsoft Word document (DOCX)"},
        ".xlsx": {"Microsoft Excel workbook (XLSX)"},
        ".pptx": {"Microsoft PowerPoint presentation (PPTX)"},
        ".zip": {"ZIP archive"},
        ".exe": {"Windows executable"},
        ".gif": {"GIF image"},
        ".rar": {"RAR archive"},
        ".7z": {"7-Zip archive"},
        ".gz": {"GZIP archive"},
        ".apk": {"Android application package (APK)"},
        ".jar": {"Java archive (JAR)"},
    }.get(ext.lower(), set())


def risk_assessment(ext: str, dtype: str, ent: float):
    reasons = []
    score = 0

    expected = expected_types(ext)
    mismatch = bool(expected and dtype not in expected)

    if mismatch:
        score += 60
        reasons.append("File extension does not match the detected binary signature.")

    if ext.lower() in RISK_EXTENSIONS:
        score += 20
        reasons.append("Evidence uses an executable or script-oriented extension.")

    if ent >= 7.5:
        score += 20
        reasons.append("High entropy may indicate compressed, encrypted, or packed content.")

    if dtype == "Unknown / unsupported signature":
        score += 10
        reasons.append("No supported signature was identified from the inspected header.")

    score = min(score, 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW"

    if not reasons:
        reasons.append("No high-confidence risk indicators were triggered by the current analysis rules.")

    return score, level, mismatch, reasons


def load_cases():
    try:
        raw = json.loads(DATA.read_text(encoding="utf-8"))
        return raw["cases"] if isinstance(raw, dict) and "cases" in raw else raw
    except Exception:
        return []


def save_cases(cases):
    DATA.parent.mkdir(exist_ok=True)
    DATA.write_text(json.dumps({"cases": cases}, indent=2), encoding="utf-8")


def get_case(case_id: str):
    for case in load_cases():
        if case.get("id") == case_id:
            return case
    raise HTTPException(404, "Case not found")


def build_report(case):
    e = case["evidence"]
    r = case["risk"]
    lines = [
        "# DFIR INVESTIGATION REPORT",
        "",
        "## 1. CASE INFORMATION",
        f"- **Case ID:** {case['id']}",
        f"- **Case Title:** {case['title']}",
        f"- **Investigator:** {case['investigator']}",
        f"- **Analysis Time:** {case['date']}",
        "",
        "## 2. EVIDENCE DETAILS",
        f"- **Original File Name:** `{e['filename']}`",
        f"- **File Extension:** `{e['extension'] or 'None'}`",
        f"- **File Size:** {human_size(e['size'])} ({e['size']} bytes)",
        f"- **MIME Type:** `{e['mime_type']}`",
        f"- **Detected Type:** {e['detected_type']}",
        "",
        "## 3. CRYPTOGRAPHIC HASHES",
        f"- **MD5:** `{e['md5']}`",
        f"- **SHA-256:** `{e['sha256']}`",
        "",
        "## 4. FILE SIGNATURE ANALYSIS",
        f"- **Magic Bytes:** `{e['magic_bytes']}`",
        f"- **Extension / Signature Match:** {'FAILED' if r['extension_mismatch'] else 'VALID'}",
        f"- **Shannon Entropy:** {e['entropy']} / 8.0",
        "",
        "## 5. RISK ASSESSMENT",
        f"- **Risk Score:** {r['score']} / 100",
        f"- **Risk Level:** {r['level']}",
        "",
        "## 6. FORENSIC FINDINGS",
    ]

    lines.extend(f"- {reason}" for reason in r["reasons"])

    lines += [
        "",
        "## 7. INVESTIGATION TIMELINE",
        f"- {case['date']}: Evidence acquired and analyzed by the DFIR Investigation Lab.",
        f"- {case['date']}: MD5 and SHA-256 integrity values generated.",
        f"- {case['date']}: File signature and entropy assessment completed.",
        "",
        "## 8. CONCLUSION",
        f"The evidence was automatically analyzed and assigned a {r['level']} risk classification with a score of {r['score']}/100. "
        "This result is an explainable screening assessment and should be reviewed with additional forensic tooling when required.",
        "",
        "## 9. CHAIN OF CUSTODY NOTE",
        "The application records the original evidence filename, stored copy reference, acquisition timestamp, cryptographic hashes, "
        "signature result, entropy value, and risk findings for the investigation record.",
    ]

    path = REPORTS / f"{case['id']}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def add_timeline_event(case_id: str, event: str, detail: str):
    tp = TIMELINE / "events.json"
    events = []
    if tp.exists():
        try:
            events = json.loads(tp.read_text(encoding="utf-8"))
        except Exception:
            events = []

    item = {
        "time": now_utc(),
        "case_id": case_id,
        "event": event,
        "detail": detail,
    }
    events.insert(0, item)
    tp.write_text(json.dumps(events, indent=2), encoding="utf-8")
    return item


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "3.0.0"}


@app.get("/api/cases")
def cases():
    return load_cases()


@app.get("/api/cases/{case_id}")
def case_details(case_id: str):
    return get_case(case_id)


from fastapi import Form

@app.post("/api/verify/{case_id}")
async def verify_hash(case_id: str, expected_hash: str = Form(...)):
    file: UploadFile = File(...),
    title: str = "Instant Security Audit",
    investigator: str = "Srayansh Yadav",
    if not file.filename:
        raise HTTPException(400, "No file supplied")

    safe = Path(file.filename).name
    stored = f"{uuid.uuid4().hex}_{safe}"
    target = UPLOADS / stored

    with target.open("wb") as out:
        shutil.copyfileobj(file.file, out)

    dtype, magic = detect_signature(target)
    ext = Path(safe).suffix.lower()
    ent = entropy(target)
    score, level, mismatch, reasons = risk_assessment(ext, dtype, ent)

    timestamp = now_utc()
    case_id = "CASE-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4].upper()

    evidence = {
        "filename": safe,
        "stored_name": stored,
        "size": target.stat().st_size,
        "extension": ext,
        "mime_type": mimetypes.guess_type(safe)[0] or "application/octet-stream",
        "detected_type": dtype,
        "magic_bytes": magic,
        "md5": digest(target, "md5"),
        "sha256": digest(target, "sha256"),
        "entropy": ent,
    }

    risk = {
        "score": score,
        "level": level,
        "extension_mismatch": mismatch,
        "reasons": reasons,
    }

    case = {
        "id": case_id,
        "title": title or "Instant Security Audit",
        "subtitle": "Automated evidence hashing, signature inspection and explainable risk assessment",
        "investigator": investigator or "Srayansh Yadav",
        "date": timestamp,
        "tags": ["DFIR Investigation", "Evidence Verified", f"{level} Risk"],
        "summary": (
            f"Automated analysis completed for {safe}. The application calculated cryptographic hashes, "
            "inspected the file signature, measured entropy, checked extension consistency, and applied risk rules."
        ),
        "bullets": [
            f"Detected type: {dtype}",
            f"Entropy: {ent}",
            f"Risk score: {score}/100 ({level})",
        ],
        "terminal_title": "Automated Investigation Result",
        "terminal_output": (
            f"$ dfir investigate {safe}\n"
            f"[OK] MD5: {evidence['md5']}\n"
            f"[OK] SHA256: {evidence['sha256']}\n"
            f"[OK] Signature: {dtype}\n"
            f"[OK] Entropy: {ent}\n"
            f"[RISK] {score}/100 ({level})\n"
            f"[PASS] Investigation completed"
        ),
        "evidence": evidence,
        "risk": risk,
    }

    all_cases = load_cases()
    all_cases.insert(0, case)
    save_cases(all_cases)
    build_report(case)

    add_timeline_event(
        case_id,
        "Evidence analyzed",
        f"{safe} analyzed | {dtype} | risk {score}/100",
    )

    return {**case, "report_url": f"/api/reports/{case_id}"}


@app.post("/api/cases/{case_id}/verify")
def verify_hash(case_id: str, expected_hash: str):
    case = get_case(case_id)
    expected = (expected_hash or "").strip().lower()

    if len(expected) not in (32, 64):
        raise HTTPException(400, "Provide a valid 32-character MD5 or 64-character SHA-256 hash.")

    algorithm = "MD5" if len(expected) == 32 else "SHA-256"
    actual = case["evidence"]["md5"] if algorithm == "MD5" else case["evidence"]["sha256"]
    matched = expected == actual.lower()

    add_timeline_event(
        case_id,
        "Hash integrity verified",
        f"{algorithm} comparison {'MATCHED' if matched else 'FAILED'} for {case['evidence']['filename']}",
    )

    return {
        "case_id": case_id,
        "algorithm": algorithm,
        "matched": matched,
        "expected_hash": expected,
        "actual_hash": actual,
        "message": (
            "Evidence integrity verified: supplied hash matches the stored forensic value."
            if matched
            else "Hash mismatch: supplied value does not match the stored forensic value."
        ),
    }


@app.get("/api/timeline")
def timeline():
    p = TIMELINE / "events.json"
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8"))


@app.get("/api/reports/{case_id}")
def report(case_id: str):
    get_case(case_id)
    p = REPORTS / f"{case_id}.md"
    if not p.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(p, media_type="text/markdown", filename=p.name)


app.mount("/", StaticFiles(directory=str(BASE / "static"), html=True), name="static")
