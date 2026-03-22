/**
 * PhishGuard Rule-Based Analysis Engine
 * Analyzes URLs using heuristic rules — NO machine learning.
 * Each rule returns a score delta and a human-readable reason.
 */

const { parse } = require('tldts');

// ── Phishing keyword lists ──────────────────────────────────
const PHISHING_KEYWORDS = [
  'login', 'verify', 'secure', 'update', 'account',
  'banking', 'confirm', 'password', 'credential', 'signin',
  'authenticate', 'validation', 'billing', 'payment', 'invoice',
  'suspended', 'unusual', 'activity', 'click-here', 'free-gift'
];

// Brands commonly spoofed in phishing attacks
const SPOOFED_BRANDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon',
  'netflix', 'facebook', 'instagram', 'twitter', 'linkedin',
  'dropbox', 'chase', 'bankofamerica', 'wellsfargo', 'citibank',
  'irs', 'ebay', 'walmart', 'steam', 'discord'
];

// Suspicious TLDs often used in phishing (free / obscure domains)
const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.xyz', '.top',
  '.club', '.work', '.date', '.racing', '.faith', '.science'
];

/**
 * Main analysis function
 * @param {string} rawUrl - The URL to analyze
 * @returns {object} - { score, status, reasons, details }
 */
function analyzeUrl(rawUrl) {
  const reasons = [];
  let score = 0;

  // ── Step 1: Parse the URL safely ──────────────────────────
  let urlObj;
  try {
    urlObj = new URL(rawUrl);
  } catch (e) {
    return {
      score: 85,
      status: 'Dangerous',
      reasons: ['URL is malformed or invalid — cannot be parsed'],
      details: { raw: rawUrl }
    };
  }

  const fullUrl   = rawUrl;
  const hostname  = urlObj.hostname.toLowerCase();
  const protocol  = urlObj.protocol;
  const pathname  = urlObj.pathname.toLowerCase();
  const search    = urlObj.search.toLowerCase();
  const parsed    = parse(rawUrl);

  // ── Rule 1: HTTPS check ────────────────────────────────────
  // HTTP sites lack transport encryption — phishing sites often skip SSL
  if (protocol === 'http:') {
    score += 20;
    reasons.push('URL uses insecure HTTP instead of HTTPS');
  }

  // ── Rule 2: URL length ─────────────────────────────────────
  // Long URLs often hide the real destination with obfuscation
  if (fullUrl.length > 100) {
    score += 20;
    reasons.push(`URL is very long (${fullUrl.length} chars > 100) — often used to obfuscate destination`);
  } else if (fullUrl.length > 75) {
    score += 10;
    reasons.push(`URL is suspiciously long (${fullUrl.length} chars > 75)`);
  }

  // ── Rule 3: IP address instead of domain ──────────────────
  // Phishing sites frequently use raw IPs to avoid domain detection
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipRegex.test(hostname)) {
    score += 30;
    reasons.push('Hostname is a raw IP address — legitimate sites use domain names');
  }

  // ── Rule 4: @ symbol in URL ────────────────────────────────
  // The browser ignores everything before @ — used to deceive users
  if (fullUrl.includes('@')) {
    score += 25;
    reasons.push('URL contains "@" symbol — browser ignores everything before it (deceptive)');
  }

  // ── Rule 5: Double slash (//) in path ─────────────────────
  // Redirects via double slashes are a classic obfuscation trick
  if (pathname.includes('//')) {
    score += 15;
    reasons.push('URL path contains double slashes "//" — may indicate redirect obfuscation');
  }

  // ── Rule 6: Hyphen abuse in domain ────────────────────────
  // Legitimate major domains rarely have multiple hyphens
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 15;
    reasons.push(`Domain contains ${hyphenCount} hyphens — often used in fake brand domains (e.g. paypal-secure-login.com)`);
  } else if (hyphenCount >= 2) {
    score += 8;
    reasons.push(`Domain contains multiple hyphens (${hyphenCount}) — mildly suspicious`);
  }

  // ── Rule 7: Phishing keywords in URL ──────────────────────
  const urlLower = fullUrl.toLowerCase();
  const foundKeywords = PHISHING_KEYWORDS.filter(kw => urlLower.includes(kw));
  if (foundKeywords.length > 0) {
    const kwScore = Math.min(foundKeywords.length * 10, 30);
    score += kwScore;
    foundKeywords.forEach(kw => {
      reasons.push(`Contains phishing keyword: "${kw}"`);
    });
  }

  // ── Rule 8: Fake subdomain attack (brand spoofing) ────────
  // Detects "paypal.evil.com" — brand name appears in subdomain not main domain
  const registeredDomain = parsed.domain || '';
  const subdomains = parsed.subdomain || '';

  SPOOFED_BRANDS.forEach(brand => {
    // Brand in subdomain but NOT the registered domain = spoofing
    if (subdomains.includes(brand) && !registeredDomain.startsWith(brand)) {
      score += 35;
      reasons.push(`Brand spoofing detected: "${brand}" appears in subdomain but domain is "${registeredDomain}" — classic phishing tactic`);
    }
    // Brand in domain but with extra words = likely fake
    if (registeredDomain.includes(brand) && registeredDomain !== brand + '.' + parsed.publicSuffix) {
      score += 20;
      reasons.push(`Possible brand impersonation: "${brand}" embedded in domain "${registeredDomain}"`);
    }
  });

  // ── Rule 9: Suspicious TLD ─────────────────────────────────
  const tld = '.' + (parsed.publicSuffix || '');
  const matchedTld = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
  if (matchedTld) {
    score += 15;
    reasons.push(`Domain uses suspicious free/obscure TLD: "${matchedTld}"`);
  }

  // ── Rule 10: Subdomain depth ───────────────────────────────
  // More than 3 subdomain levels is unusual for legitimate sites
  const domainParts = hostname.split('.');
  if (domainParts.length > 5) {
    score += 20;
    reasons.push(`Domain has ${domainParts.length} levels — excessive subdomain nesting is suspicious`);
  } else if (domainParts.length > 4) {
    score += 10;
    reasons.push(`Domain has ${domainParts.length} subdomain levels — slightly unusual`);
  }

  // ── Rule 11: Hex / percent encoding in hostname ───────────
  if (hostname.includes('%') || hostname.includes('0x')) {
    score += 25;
    reasons.push('Hostname contains encoded characters — often used to hide the real destination');
  }

  // ── Rule 12: Suspicious port ──────────────────────────────
  const port = urlObj.port;
  if (port && !['80', '443', '8080', '8443'].includes(port)) {
    score += 10;
    reasons.push(`URL uses non-standard port ${port} — legitimate sites rarely do this`);
  }

  // ── Rule 13: Long query string ────────────────────────────
  if (search.length > 100) {
    score += 10;
    reasons.push(`Query string is very long (${search.length} chars) — may contain obfuscated redirect`);
  }

  // ── Rule 14: URL shorteners ───────────────────────────────
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'];
  if (shorteners.some(s => hostname.includes(s))) {
    score += 15;
    reasons.push('URL uses a shortener service — final destination is hidden');
  }

  // ── Cap score at 100 ──────────────────────────────────────
  score = Math.min(score, 100);

  // ── Determine status ──────────────────────────────────────
  let status;
  if (score <= 30) {
    status = 'Safe';
  } else if (score <= 70) {
    status = 'Suspicious';
  } else {
    status = 'Dangerous';
  }

  // ── If no issues found, add a positive note ───────────────
  if (reasons.length === 0) {
    reasons.push('No suspicious patterns detected');
  }

  return {
    score,
    status,
    reasons,
    details: {
      hostname,
      protocol,
      registeredDomain,
      subdomains,
      urlLength: fullUrl.length,
      tld: parsed.publicSuffix
    }
  };
}

module.exports = { analyzeUrl };
