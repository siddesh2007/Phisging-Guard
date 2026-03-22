/**
 * PhishGuard Background Service Worker
 * Runs in background, intercepts navigation events,
 * checks URLs against the PhishGuard API, and blocks dangerous ones.
 */

const API_BASE = 'http://localhost:3000';

// ── Cache to avoid re-checking the same URL repeatedly ─────
// Map of url -> { result, timestamp }
const cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Check a URL against the PhishGuard backend API
 * Returns cached result if fresh, otherwise fetches new result.
 */
async function checkUrl(url) {
  // Don't check internal chrome:// or extension pages
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
    return null;
  }

  // Check cache
  const cached = cache.get(url);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
    return cached.result;
  }

  try {
    const response = await fetch(`${API_BASE}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error('API error');
    const result = await response.json();

    // Store in cache
    cache.set(url, { result, timestamp: Date.now() });

    return result;
  } catch (err) {
    console.error('PhishGuard API unreachable:', err.message);
    return null;
  }
}

/**
 * Update the extension badge to reflect security status
 */
function updateBadge(tabId, status) {
  const config = {
    'Safe':       { text: '✓',  color: '#22c55e' },
    'Suspicious': { text: '!',  color: '#f59e0b' },
    'Dangerous':  { text: '✕',  color: '#ef4444' },
    'Checking':   { text: '…',  color: '#6366f1' }
  };

  const { text, color } = config[status] || config['Checking'];

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

/**
 * Store latest result for a tab (retrieved by popup)
 */
const tabResults = new Map();

/**
 * Main URL check flow — called on tab navigation
 */
async function handleNavigation(tabId, url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

  // Show "checking" state immediately
  updateBadge(tabId, 'Checking');

  const result = await checkUrl(url);
  if (!result) {
    updateBadge(tabId, 'Checking');
    return;
  }

  // Store result for popup to read
  tabResults.set(tabId, result);

  // Update badge
  updateBadge(tabId, result.status);

  // Block dangerous URLs — redirect to our warning page
  if (result.status === 'Dangerous') {
    const warningUrl = chrome.runtime.getURL('blocked.html') +
      '?url=' + encodeURIComponent(url) +
      '&score=' + result.score +
      '&reasons=' + encodeURIComponent(JSON.stringify(result.reasons));

    chrome.tabs.update(tabId, { url: warningUrl });
  }
}

// ── Listen for tab URL changes ──────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only trigger when URL is committed (not just loading)
  if (changeInfo.status === 'loading' && changeInfo.url) {
    handleNavigation(tabId, changeInfo.url);
  }
});

// ── Listen for messages from popup ─────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === 'GET_RESULT') {
    // Popup asking for the cached result for current tab
    const result = tabResults.get(message.tabId);
    sendResponse({ result: result || null });
    return true;
  }

  if (message.type === 'CHECK_URL') {
    // Popup manually requesting a check
    checkUrl(message.url).then(result => {
      if (result) {
        tabResults.set(message.tabId, result);
        updateBadge(message.tabId, result.status);
      }
      sendResponse({ result });
    });
    return true; // Keep message channel open for async response
  }

  if (message.type === 'PROCEED_ANYWAY') {
    // User clicked "Proceed Anyway" on blocked page
    // We don't re-block this URL for this session
    cache.set(message.url, {
      result: { status: 'Suspicious', score: 65, reasons: ['User chose to proceed despite warning'] },
      timestamp: Date.now()
    });
    sendResponse({ ok: true });
    return true;
  }
});

// Clean up tab data when tab is closed
chrome.tabs.onRemoved.addListener(tabId => {
  tabResults.delete(tabId);
});

console.log('🛡️ PhishGuard background service worker started');
