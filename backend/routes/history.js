/**
 * GET /history
 * Returns recent URL scan history
 */

const express = require('express');
const router  = express.Router();
const { getScans } = require('../utils/db');

router.get('/', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const scans = getScans(limit);
  res.json({ scans });
});

module.exports = router;
