/**
 * VirusTotal API Integration
 * Checks URL reputation against 70+ security vendors
 * Docs: https://developers.virustotal.com/reference/urls
 *
 * TO USE: Set your VirusTotal API key in config.js or as env variable
 * Free tier: 4 requests/minute, 500/day
 */

const axios = require('axios');

// ── Load API key ───────────────────────────────────────────
// Set VT_API_KEY in your environment or replace the string below
const VT_API_KEY = process.env.VT_API_KEY || 'YOUR_VIRUSTOTAL_API_KEY_HERE';

/**
 * Check a URL against VirusTotal
 * @param {string} url
 * @returns {object|null} - { malicious, suspicious, harmless, undetected, vendors } or null if failed
 */
async function checkVirusTotal(url) {
  // Return mock/null if no key configured
  if (!VT_API_KEY || VT_API_KEY === 'YOUR_VIRUSTOTAL_API_KEY_HERE') {
    console.log('⚠️  VirusTotal API key not configured — skipping VT check');
    return null;
  }

  try {
    // Step 1: Submit URL for analysis
    const submitRes = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      {
        headers: {
          'x-apikey': VT_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 8000
      }
    );

    // Extract the analysis ID from the response
    const analysisId = submitRes.data?.data?.id;
    if (!analysisId) return null;

    // Step 2: Fetch analysis results (with small delay for processing)
    await new Promise(r => setTimeout(r, 2000));

    const resultRes = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { 'x-apikey': VT_API_KEY },
        timeout: 8000
      }
    );

    const stats = resultRes.data?.data?.attributes?.stats;
    const results = resultRes.data?.data?.attributes?.results || {};

    if (!stats) return null;

    // Collect names of vendors that flagged it as malicious
    const flaggedBy = Object.entries(results)
      .filter(([_, v]) => v.category === 'malicious')
      .map(([vendor]) => vendor)
      .slice(0, 5); // Limit to first 5 for display

    return {
      malicious:   stats.malicious   || 0,
      suspicious:  stats.suspicious  || 0,
      harmless:    stats.harmless    || 0,
      undetected:  stats.undetected  || 0,
      flaggedBy
    };

  } catch (err) {
    console.error('VirusTotal API error:', err.message);
    return null; // Gracefully degrade — rule-based check still runs
  }
}

/**
 * Convert VT results into a score delta and reasons
 * @param {object} vtResult - From checkVirusTotal()
 * @returns {{ scoreDelta: number, reasons: string[] }}
 */
function vtResultToScore(vtResult) {
  if (!vtResult) return { scoreDelta: 0, reasons: [] };

  const reasons = [];
  let scoreDelta = 0;

  if (vtResult.malicious > 0) {
    scoreDelta += Math.min(vtResult.malicious * 5, 40);
    reasons.push(
      `VirusTotal: ${vtResult.malicious} security vendors flagged this URL as malicious` +
      (vtResult.flaggedBy.length ? ` (${vtResult.flaggedBy.join(', ')})` : '')
    );
  }

  if (vtResult.suspicious > 0) {
    scoreDelta += Math.min(vtResult.suspicious * 3, 20);
    reasons.push(`VirusTotal: ${vtResult.suspicious} vendors flagged as suspicious`);
  }

  if (vtResult.malicious === 0 && vtResult.suspicious === 0 && vtResult.harmless > 5) {
    reasons.push(`VirusTotal: ${vtResult.harmless} vendors confirmed URL as harmless`);
    scoreDelta -= 10; // Reward for clean VT record
  }

  return { scoreDelta, reasons };
}

module.exports = { checkVirusTotal, vtResultToScore };
