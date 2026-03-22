# 🛡️ PhishGuard — Real-Time Phishing URL Detection

> A Chrome extension + backend API that detects phishing URLs using **rule-based analysis only** (no machine learning).

---

## 📁 Project Structure

```
phishguard/
├── backend/                  ← Node.js Express API
│   ├── server.js             ← Entry point (port 3000)
│   ├── package.json
│   ├── routes/
│   │   ├── check.js          ← POST /check — main analysis endpoint
│   │   ├── history.js        ← GET /history
│   │   └── stats.js          ← GET /stats
│   ├── utils/
│   │   ├── analyzer.js       ← ✅ Core rule-based detection engine
│   │   ├── virustotal.js     ← VirusTotal API integration
│   │   ├── whois.js          ← Domain age checker
│   │   └── db.js             ← JSON file database
│   └── data/
│       └── scans.json        ← Auto-created scan history
│
├── extension/                ← Chrome Extension (MV3)
│   ├── manifest.json         ← Extension config
│   ├── background.js         ← Service worker (intercepts navigation)
│   ├── popup.html/js         ← Extension popup UI
│   ├── content.js            ← Page-level script
│   ├── blocked.html          ← Full-page phishing warning
│   └── icons/                ← Extension icons
│
└── dashboard/
    └── index.html            ← Web dashboard (served by backend)
```

---

## ⚡ Quick Start

### Step 1 — Install backend dependencies

```bash
cd backend
npm install
```

### Step 2 — (Optional) Add API keys

Edit `backend/utils/virustotal.js` and set your VirusTotal API key:
```js
const VT_API_KEY = 'YOUR_ACTUAL_KEY_HERE';
```
Get a free key at: https://www.virustotal.com/gui/join-us

Or set as environment variable:
```bash
export VT_API_KEY=your_key_here
```

> The app works without a VirusTotal key — rule-based analysis still runs.

### Step 3 — Start the backend

```bash
cd backend
npm start
```

You should see:
```
🛡️  PhishGuard API running at http://localhost:3000
📊  Dashboard available at http://localhost:3000/
🔍  Check endpoint: POST http://localhost:3000/check
```

### Step 4 — Load the Chrome Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (top right toggle)
3. Click **"Load unpacked"**
4. Select the `extension/` folder
5. The PhishGuard shield icon should appear in your toolbar

---

## 🔍 How It Works

### Rule-Based Detection Engine (`analyzer.js`)

The engine checks 14 rules and assigns a score 0–100:

| Rule | Score |
|------|-------|
| HTTP instead of HTTPS | +20 |
| URL > 75 chars | +10 |
| URL > 100 chars | +20 |
| IP address as hostname | +30 |
| `@` symbol in URL | +25 |
| `//` in URL path | +15 |
| 3+ hyphens in domain | +15 |
| Phishing keywords (login, verify...) | +10 per keyword |
| Brand spoofing via subdomain | +35 |
| Brand name embedded in domain | +20 |
| Suspicious TLD (.tk, .ml, .xyz...) | +15 |
| Deep subdomain nesting (5+ levels) | +20 |
| Hex-encoded hostname | +25 |
| URL shortener | +15 |

### Score → Status

| Score | Status |
|-------|--------|
| 0–30  | ✅ Safe |
| 31–70 | ⚠️ Suspicious |
| 71–100 | 🚨 Dangerous |

---

## 🧪 Test URLs

Try these in the dashboard or extension to see detection in action:

```
# Should be SAFE (score ~0–10)
https://www.google.com
https://github.com
https://stackoverflow.com

# Should be SUSPICIOUS (score ~30–60)
http://example.com/login
https://free-gift.xyz/claim

# Should be DANGEROUS (score ~70–100)
http://paypal.verify-account.tk/login?user=admin@secure
http://192.168.1.1/banking/login
https://paypal.fake-domain.com/account/verify
http://microsoft-account-login-verify.com/update/password
```

---

## 🌐 API Reference

### `POST /check`

**Request:**
```json
{ "url": "https://example.com/login" }
```

**Response:**
```json
{
  "url": "https://example.com/login",
  "status": "Suspicious",
  "score": 40,
  "reasons": [
    "Contains phishing keyword: \"login\"",
    "URL length is suspicious (42 chars)"
  ],
  "details": {
    "hostname": "example.com",
    "protocol": "https:",
    "registeredDomain": "example.com",
    "urlLength": 27
  }
}
```

### `GET /history`
Returns recent scan history (JSON array).

### `GET /stats`
Returns aggregate counts: `{ total, safe, suspicious, dangerous }`.

---

## 🔐 Security Notes

- This project uses **rule-based heuristics only** — no ML models
- VirusTotal integration is **optional** but improves accuracy
- Domain age via WHOIS uses a free demo key — limited requests
- The extension only sends URLs to `localhost:3000` — nothing leaves your machine without a VT API key

---

## 🛠️ Development

```bash
# Run with auto-restart on file changes
cd backend
npm run dev  # requires: npm install -g nodemon
```

---

## 📦 Dependencies

```
express     — HTTP server
cors        — Cross-origin requests (extension → API)
axios       — HTTP client for VirusTotal API
tldts       — Domain parsing (subdomain detection)
```
