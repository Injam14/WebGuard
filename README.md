# WebGuard

A beginner-friendly, passive web security assessment dashboard built with Python, Flask, SQLite and ReportLab.

## Features
- HTTPS check and TLS certificate expiry inspection
- HTTP security header checks
- Basic cookie attribute checks
- Risk score and severity counts
- SQLite scan history
- Downloadable PDF reports

## Important safety scope
Use only on websites you own or have explicit permission to assess. WebGuard performs limited passive checks; it does not exploit vulnerabilities, brute-force accounts, crawl hidden paths, or perform a full penetration test. A high score is not proof that a site is secure.

## Setup on Windows 11

1. Install Python 3.10 or newer.
2. Extract this ZIP file.
3. Open the `WebGuard` folder in VS Code.
4. Open Terminal and run:

```powershell
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
py app.py
```

5. Open `http://127.0.0.1:5000` in your browser.

If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

## Project structure

```text
WebGuard/
├── app.py
├── scanner.py
├── database.py
├── report.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── index.html
│   └── results.html
└── static/
    └── style.css
```
## Live Project Demo

Website: https://webguard-q7nt.onrender.com/

Username: admin

Password: webguard@1234
## Evaluation ideas
Test against a local training app or a site you control. Record known header and cookie configurations, compare expected and observed findings, and calculate precision, recall, false-positive rate, and scan duration. Do not claim the tool detects SQL injection or XSS: those checks are intentionally outside this passive first version.
