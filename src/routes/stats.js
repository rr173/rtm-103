const express = require('express');

function createStatsRouter(statsLogger) {
  const router = express.Router();

  router.get('/stats', (_req, res) => {
    try {
      res.json(statsLogger.getStats());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/logs', (req, res) => {
    try {
      const limit = parseInt(req.query.limit, 10) || 50;
      res.json(statsLogger.getLogs(limit));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

module.exports = createStatsRouter;
