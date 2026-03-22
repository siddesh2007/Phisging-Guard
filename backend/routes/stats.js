/**
 * GET /stats
 * Returns aggregate scan statistics for dashboard
 */

const express = require('express');
const router  = express.Router();
const { getStats } = require('../utils/db');

router.get('/', (req, res) => {
  const stats = getStats();
  res.json(stats);
});

module.exports = router;
