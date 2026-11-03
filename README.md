# DNS Tunneling Detection System

A beginner-friendly Flask web application for analyzing DNS logs for suspicious characteristics such as long queries, long subdomains, high entropy, and TXT records.

## Run in VS Code

### 1. Open the project folder
Open `DNS-Tunneling-Detector` in VS Code.

### 2. Create a virtual environment

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

Kali/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install packages
```bash
pip install -r requirements.txt
```

### 4. Start the website
Windows:
```bash
python app.py
```

Kali/Linux:
```bash
python3 app.py
```

### 5. Open the website

Visit:
`http://127.0.0.1:5000`

Upload `data/dns_logs.csv` to test the detector.

## Detection logic

- Query length >= 60: suspicious points
- Longest subdomain >= 35: suspicious points
- Entropy >= 3.5 with a sufficiently long label: suspicious points
- TXT record: additional suspicious point
- Score >= 4: HIGH
- Score 2-3: MEDIUM
- Otherwise: NORMAL

This is an educational detection project, not a production IDS.
