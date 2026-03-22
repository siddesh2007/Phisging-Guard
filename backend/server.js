/**
 * PhishGuard Backend Server
 * Real-Time Phishing URL Detection API
 * Uses rule-based analysis + VirusTotal API integration
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const os = require('os');
const path = require('path');

const checkRoute = require('./routes/check');
const historyRoute = require('./routes/history');
const statsRoute = require('./routes/stats');

const app = express();
const PORT = process.env.PORT || 3000;
const isVercel = Boolean(process.env.VERCEL);

// ── Middleware ──────────────────────────────────────────────
app.use(cors()); // Allow Chrome extension & dashboard to connect
app.use(express.json());
app.use(express.static(path.join(__dirname, '../dashboard'))); // Serve dashboard

// ── Initialize JSON database file if it doesn't exist ──────
const dataDir = isVercel
  ? path.join(os.tmpdir(), 'phishguard-data')
  : path.join(__dirname, 'data');
const DB_PATH = path.join(dataDir, 'scans.json');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
if (!fs.existsSync(DB_PATH)) {
  fs.writeFileSync(DB_PATH, JSON.stringify({ scans: [] }, null, 2));
}

// ── Routes ──────────────────────────────────────────────────
app.use('/check', checkRoute);
app.use('/history', historyRoute);
app.use('/stats', statsRoute);

// ── Health check ────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'PhishGuard API is running' });
});

// ── Dashboard fallback ──────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../dashboard/index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\nPhishGuard API running at http://localhost:${PORT}`);
    console.log(`Dashboard available at http://localhost:${PORT}/`);
    console.log(`Check endpoint: POST http://localhost:${PORT}/check\n`);
  });
}

module.exports = app;
