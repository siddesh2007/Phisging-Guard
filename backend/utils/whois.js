/**
 * Domain Age Checker via WHOIS
 * Newly registered domains are a strong indicator of phishing.
 * Most phishing campaigns register throwaway domains days before attacks.
 */

const https = require('https');

/**
 * Check domain age using the free WHOIS API (whoisjsonapi.com)
 * Falls back gracefully if unavailable.
 * @param {string} domain - e.g. "paypal-secure.tk"
 * @returns {object} - { ageInDays, createdDate, reason, scoreDelta }
 */
async function checkDomainAge(domain) {
  try {
    // Using a free WHOIS JSON API — no key required for basic usage
    const apiUrl = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_demo&domainName=${domain}&outputFormat=JSON`;

    const data = await fetchJson(apiUrl);

    const createdDate = data?.WhoisRecord?.createdDate || data?.WhoisRecord?.registryData?.createdDate;

    if (!createdDate) {
      return { ageInDays: null, reason: 'Domain age could not be determined (WHOIS unavailable)', scoreDelta: 0 };
    }

    const created = new Date(createdDate);
    const now = new Date();
    const ageInDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));

    let scoreDelta = 0;
    let reason = '';

    if (ageInDays < 30) {
      // Domain registered less than 30 days ago — very suspicious
      scoreDelta = 30;
      reason = `Domain is only ${ageInDays} days old — very new domains are often used for phishing`;
    } else if (ageInDays < 180) {
      scoreDelta = 15;
      reason = `Domain is ${ageInDays} days old — relatively new (< 6 months)`;
    } else if (ageInDays > 365 * 3) {
      scoreDelta = -10; // Established domain — slight trust bonus
      reason = `Domain is ${Math.floor(ageInDays / 365)} years old — established domain`;
    } else {
      reason = `Domain age: ${ageInDays} days`;
    }

    return { ageInDays, createdDate, reason, scoreDelta };

  } catch (err) {
    // Silently fail — WHOIS is best-effort
    return { ageInDays: null, reason: 'Domain age check unavailable', scoreDelta: 0 };
  }
}

/**
 * Simple HTTPS JSON fetch helper (no dependencies)
 */
function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

module.exports = { checkDomainAge };
