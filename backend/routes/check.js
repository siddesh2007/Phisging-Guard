/**
 * POST /check
 * Main URL analysis endpoint.
 * Combines rule-based analysis + VirusTotal + WHOIS domain age.
 */

const express = require('express');
const router  = express.Router();

const { analyzeUrl }           = require('../utils/analyzer');
const { checkVirusTotal, vtResultToScore } = require('../utils/virustotal');
const { checkDomainAge }       = require('../utils/whois');
const { saveScan }             = require('../utils/db');
const { parse }                = require('tldts');

router.post('/', async (req, res) => {
  const { url } = req.body;

  // ── Validate input ─────────────────────────────────────────
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL is required' });
  }

  // Normalize — add https:// if no protocol given
  let normalizedUrl = url.trim();
  if (!normalizedUrl.match(/^https?:\/\//i)) {
    normalizedUrl = 'https://' + normalizedUrl;
  }

  try {
    // ── 1. Run rule-based analysis (always runs) ──────────────
    const ruleResult = analyzeUrl(normalizedUrl);
    let { score, reasons } = ruleResult;

    // ── 2. VirusTotal check (async, non-blocking if fails) ────
    const vtResult = await checkVirusTotal(normalizedUrl);
    const vtScore  = vtResultToScore(vtResult);
    score   += vtScore.scoreDelta;
    reasons  = [...reasons, ...vtScore.reasons];

    // ── 3. Domain age check via WHOIS ─────────────────────────
    const parsed    = parse(normalizedUrl);
    const domain    = parsed.hostname || parsed.domain || '';
    const whoisData = await checkDomainAge(domain);
    score   += whoisData.scoreDelta;
    if (whoisData.reason) reasons.push(whoisData.reason);

    // ── 4. Recalculate final status ───────────────────────────
    score = Math.max(0, Math.min(score, 100));
    let status;
    if (score <= 30)      status = 'Safe';
    else if (score <= 70) status = 'Suspicious';
    else                  status = 'Dangerous';

    // ── 5. Persist to database ────────────────────────────────
    const scanRecord = {
      url: normalizedUrl,
      status,
      score,
      reasons,
      vtData: vtResult,
      domainAge: whoisData.ageInDays
    };
    saveScan(scanRecord);

    // ── 6. Return result ──────────────────────────────────────
    return res.json({
      url: normalizedUrl,
      status,
      score,
      reasons,
      details: {
        ...ruleResult.details,
        domainAge: whoisData.ageInDays,
        vtData: vtResult
      }
    });

  } catch (err) {
    console.error('Error analyzing URL:', err);
    return res.status(500).json({ error: 'Analysis failed', message: err.message });
  }
});

module.exports = router;
