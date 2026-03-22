/**
 * Simple JSON File Database
 * Stores scan history in data/scans.json
 * Can be swapped for MongoDB without changing routes.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const isVercel = Boolean(process.env.VERCEL);
const dataDir = isVercel
  ? path.join(os.tmpdir(), 'phishguard-data')
  : path.join(__dirname, '../data');
const DB_PATH = path.join(dataDir, 'scans.json');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
if (!fs.existsSync(DB_PATH)) {
  fs.writeFileSync(DB_PATH, JSON.stringify({ scans: [] }, null, 2));
}

/** Read the database */
function readDb() {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { scans: [] };
  }
}

/** Write to the database */
function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

/**
 * Save a scan result
 * @param {object} scan - { url, status, score, reasons, timestamp }
 */
function saveScan(scan) {
  const db = readDb();
  db.scans.unshift({
    id: Date.now().toString(),
    ...scan,
    timestamp: new Date().toISOString()
  });
  // Keep last 500 scans to avoid file bloat
  if (db.scans.length > 500) {
    db.scans = db.scans.slice(0, 500);
  }
  writeDb(db);
}

/** Get recent scans */
function getScans(limit = 50) {
  const db = readDb();
  return db.scans.slice(0, limit);
}

/** Get aggregate statistics */
function getStats() {
  const db = readDb();
  const total      = db.scans.length;
  const dangerous  = db.scans.filter(s => s.status === 'Dangerous').length;
  const suspicious = db.scans.filter(s => s.status === 'Suspicious').length;
  const safe       = db.scans.filter(s => s.status === 'Safe').length;

  return { total, dangerous, suspicious, safe };
}

module.exports = { saveScan, getScans, getStats };
