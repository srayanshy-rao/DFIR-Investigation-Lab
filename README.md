# DFIR Investigation Lab

A web-based Digital Forensics and Incident Response (DFIR) application designed to analyze uploaded files and assist with basic forensic investigation workflows.

## Features

- File upload and investigation
- MD5 hash generation
- SHA-256 hash generation
- File signature / magic byte analysis
- File type detection
- Extension and signature mismatch detection
- Risk scoring
- Investigation case management
- Case details dashboard
- Hash integrity verification
- Investigation timeline
- Automated forensic report generation

## Tech Stack

- Python
- FastAPI
- HTML
- CSS
- JavaScript
- Uvicorn

## How It Works

1. Upload a file for investigation.
2. The application calculates MD5 and SHA-256 hashes.
3. Magic bytes are inspected to determine the actual file type.
4. The claimed file extension is compared with the detected signature.
5. A forensic risk assessment is generated.
6. An investigation case is stored.
7. The investigator can review case details and verify hashes.
8. A forensic investigation report can be generated.

## Installation

Clone the repository:

git clone YOUR_REPOSITORY_URL

Navigate to the project:

cd DFIR-Investigation-Lab

Create a virtual environment:

python -m venv .venv

Activate it on Windows:

.venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Run the application:

uvicorn backend.main:app --reload

Open:

http://127.0.0.1:8000

## Demo

A working demonstration video is available in the `demo` folder.

## Disclaimer

This project is an educational and portfolio-focused DFIR application. It is not intended to replace professional forensic investigation tools or procedures.