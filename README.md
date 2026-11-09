# TrustLens (TriNayan) 🛡️
> **Explainable AI Trust Sentinel** — Beyond the padlock: inspect SSL/TLS certificate chains, brand impersonation, passive transport headers, and crowd-sourced intelligence before you trust a website.

---

## 🚀 Quick Start Guide (Run on Any Laptop)

Follow these exact steps when cloning or pulling on a fresh machine.

### Prerequisites
- **Python 3.10+** (Python 3.11 or 3.12 recommended)
- **Node.js 18+** & npm

---

### Step 1: Start the Backend (Port 8000)

Open your terminal (PowerShell, Command Prompt, or Bash):

```bash
cd TriNayan/backend

# 1. Create and activate a clean virtual environment
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# (Or Windows cmd: venv\Scripts\activate.bat)
# (Or Mac/Linux: source venv/bin/activate)

# 2. Install all required dependencies
pip install -r requirements.txt

# 3. Start the FastAPI server with reload
uvicorn app.main:app --reload --port 8000
```

Verify backend health at: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

### Step 2: Start the Next.js Frontend (Port 3000)

Open a **second terminal**:

```bash
cd TriNayan/frontend

# 1. Install frontend packages
npm install

# 2. Run the development server
npm run dev
```

Open your browser at: **[http://localhost:3000](http://localhost:3000)**

---

### Step 3: Load the Chrome / Edge Extension (Optional)

1. Open `chrome://extensions` or `edge://extensions` in your browser.
2. Enable **Developer mode** (toggle in top right).
3. Click **Load unpacked** and select the `TriNayan/extension` folder.
4. The TrustLens shield icon will appear in your browser toolbar, protecting tabs in real-time.

---

## 🎯 Verification Benchmark URLs

Test these URLs on `http://localhost:3000` to verify accurate scoring:

| URL | Type | Expected Risk | Expected Verdict |
| :--- | :--- | :--- | :--- |
| `https://github.com` | Official Developer Platform | **4 - 8 / 100** | 🟢 **Safe** |
| `https://www.onlinesbi.sbi` | Official State Bank of India | **0 - 10 / 100** | 🟢 **Safe** |
| `https://treasurefun.xyz` | Risky Disposable TLD + Missing Security | **68 / 100** | 🔴 **Dangerous** |
| `https://sbi-login-secure-verify.com` | Brand Impersonation / Phishing | **88 / 100** | 🔴 **Dangerous** |
| `https://notarealsitedummy123999.com` | Fake / Dead / Non-existent Domain | **85 / 100** | 🔴 **Dangerous** |
| `https://expired.badssl.com` | Expired Certificate Test | **75 / 100** | 🔴 **Dangerous** |

---

## 🌐 Multilingual Support
TrustLens includes complete, interactive language switching:
- **EN** — English
- **हिन्दी** — Hindi
- **বাংলা** — Bengali

---

## 📦 Project Structure
```
TriNayan/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app with universal CORS
│   │   ├── orchestrator.py      # Multi-module asynchronous runner
│   │   ├── fusion.py            # Calibrated risk fusion & override engine
│   │   └── modules/
│   │       ├── threat/          # Lexical heuristics & brand impersonation
│   │       ├── cert/            # TLS chain inspection & cryptography
│   │       └── websec/          # Passive HTTP/HTTPS header auditor
│   └── requirements.txt         # Complete portable backend dependencies
├── frontend/                    # Next.js 16 + Tailwind CSS web interface
│   ├── src/app/                 # Home, Result, Report, and Monitor pages
│   └── src/lib/                 # API client, i18n dictionaries, utils
├── extension/                   # Manifest V3 browser extension
└── demo/                        # Hackathon benchmark seeds & pitch deck
```
