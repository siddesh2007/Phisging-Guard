/**
 * PhishGuard Popup Script
 * Handles UI interactions, sends URL to background worker,
 * and renders the scan result in the popup.
 */

const API_BASE = 'http://localhost:3000';

// ── DOM References ──────────────────────────────────────────
const urlInput    = document.getElementById('urlInput');
const scanBtn     = document.getElementById('scanBtn');
const loading     = document.getElementById('loading');
const errorEl     = document.getElementById('error');
const emptyEl     = document.getElementById('empty');
const resultEl    = document.getElementById('result');
const statusBanner = document.getElementById('statusBanner');
const statusIcon  = document.getElementById('statusIcon');
const statusLabel = document.getElementById('statusLabel');
const statusSub   = document.getElementById('statusSub');
const scoreNum    = document.getElementById('scoreNum');
const scoreFill   = document.getElementById('scoreFill');
const reasonsList = document.getElementById('reasonsList');
const footerTime  = document.getElementById('footerTime');
const clearBtn    = document.getElementById('clearBtn');
const chipProtocol = document.getElementById('chipProtocol');
const chipDomain   = document.getElementById('chipDomain');
const chipLen      = document.getElementById('chipLen');

// ── Status config ───────────────────────────────────────────
const STATUS_CONFIG = {
  Safe: {
    icon: '✅',
    cssClass: 'safe',
    sub: 'No significant threats detected',
    scoreColor: '#22c55e',
    dotColor: '#22c55e'
  },
  Suspicious: {
    icon: '⚠️',
    cssClass: 'suspicious',
    sub: 'This URL has suspicious characteristics',
    scoreColor: '#f59e0b',
    dotColor: '#f59e0b'
  },
  Dangerous: {
    icon: '🚨',
    cssClass: 'dangerous',
    sub: 'High likelihood of phishing attack',
    scoreColor: '#ef4444',
    dotColor: '#ef4444'
  }
};

// ── Initialize popup ────────────────────────────────────────
async function init() {
  // Get current tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (tab?.url && !tab.url.startsWith('chrome://')) {
    urlInput.value = tab.url;
  }

  // Check if background already has a result for this tab
  chrome.runtime.sendMessage(
    { type: 'GET_RESULT', tabId: tab.id },
    ({ result }) => {
      if (result) {
        renderResult(result);
      } else {
        showEmpty();
      }
    }
  );
}

// ── Scan button handler ─────────────────────────────────────
scanBtn.addEventListener('click', () => {
  const url = urlInput.value.trim();
  if (!url) return;
  startScan(url);
});

// Allow Enter key in input
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') scanBtn.click();
});

// ── Clear button ────────────────────────────────────────────
clearBtn.addEventListener('click', () => {
  showEmpty();
  urlInput.value = '';
});

// ── Main scan function ──────────────────────────────────────
async function startScan(url) {
  showLoading();

  try {
    const response = await fetch(`${API_BASE}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error('API returned error ' + response.status);

    const result = await response.json();
    renderResult(result);

  } catch (err) {
    console.error('Scan failed:', err);
    showError();
  }
}

// ── Render result ───────────────────────────────────────────
function renderResult(data) {
  const cfg = STATUS_CONFIG[data.status] || STATUS_CONFIG.Suspicious;

  // ── Status banner ────────────────────────────
  statusBanner.className = `status-banner ${cfg.cssClass}`;
  statusIcon.textContent  = cfg.icon;
  statusLabel.textContent = data.status.toUpperCase();
  statusSub.textContent   = cfg.sub;

  // ── Score bar ────────────────────────────────
  const score = Math.round(data.score);
  scoreNum.textContent = score + '/100';
  scoreNum.style.color  = cfg.scoreColor;

  // Animate fill width with a tiny delay for visual effect
  scoreFill.style.width = '0%';
  scoreFill.style.background = `linear-gradient(90deg, ${cfg.scoreColor}88, ${cfg.scoreColor})`;
  requestAnimationFrame(() => {
    setTimeout(() => {
      scoreFill.style.width = score + '%';
    }, 50);
  });

  // ── Detail chips ─────────────────────────────
  try {
    const urlObj = new URL(data.url);
    chipProtocol.textContent = urlObj.protocol.replace(':', '').toUpperCase();
    chipDomain.textContent   = (data.details?.registeredDomain || urlObj.hostname).slice(0, 18);
    chipLen.textContent      = data.url.length + ' chars';
  } catch { /* ignore */ }

  // ── Reasons list ─────────────────────────────
  reasonsList.innerHTML = '';
  const reasons = data.reasons || [];

  reasons.forEach(reason => {
    const item = document.createElement('div');
    item.className = 'reason-item';

    const dot = document.createElement('div');
    dot.className = 'dot';
    dot.style.background = cfg.dotColor;

    const text = document.createElement('span');
    text.textContent = reason;

    item.appendChild(dot);
    item.appendChild(text);
    reasonsList.appendChild(item);
  });

  // ── Footer timestamp ──────────────────────────
  footerTime.textContent = 'Scanned ' + new Date().toLocaleTimeString();

  // ── Show result panel ─────────────────────────
  hideAll();
  resultEl.style.display = 'block';
}

// ── UI state helpers ────────────────────────────────────────
function showLoading() {
  hideAll();
  loading.style.display = 'block';
  scanBtn.disabled = true;
  scanBtn.textContent = '...';
}

function showEmpty() {
  hideAll();
  emptyEl.style.display = 'block';
}

function showError() {
  hideAll();
  errorEl.style.display = 'block';
}

function hideAll() {
  loading.style.display  = 'none';
  errorEl.style.display  = 'none';
  emptyEl.style.display  = 'none';
  resultEl.style.display = 'none';
  scanBtn.disabled = false;
  scanBtn.textContent = 'Scan';
}

// ── Boot ────────────────────────────────────────────────────
init();
