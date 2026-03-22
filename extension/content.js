/**
 * PhishGuard Content Script
 * Injected into every page at document_start.
 * Currently used for future expansion (e.g., link hover scanning).
 * Communicates with background worker via chrome.runtime.sendMessage.
 */

// Log that content script is active (visible in page DevTools)
console.debug('[PhishGuard] Content script active on:', window.location.href);

// Listen for messages from background (e.g., show overlay warning)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SHOW_WARNING_OVERLAY') {
    showWarningBanner(message.status, message.score);
  }
  sendResponse({ ok: true });
});

/**
 * Show a slim warning banner at the top of a suspicious page
 * (doesn't replace the page — used for Suspicious status)
 */
function showWarningBanner(status, score) {
  if (status !== 'Suspicious') return;
  if (document.getElementById('phishguard-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'phishguard-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0;
    z-index: 2147483647;
    background: #f59e0b;
    color: #1a1a1a;
    font-family: system-ui, sans-serif;
    font-size: 14px;
    font-weight: 600;
    padding: 10px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
  `;
  banner.innerHTML = `
    <span>⚠️ PhishGuard: This page looks suspicious (Risk Score: ${score}/100). Proceed with caution.</span>
    <button onclick="this.parentElement.remove()" style="
      background: rgba(0,0,0,0.2);
      border: none;
      color: #1a1a1a;
      cursor: pointer;
      padding: 4px 10px;
      border-radius: 4px;
      font-weight: bold;
    ">✕ Dismiss</button>
  `;
  document.body.prepend(banner);
}
