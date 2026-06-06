const express = require('express');

function createCacheRouter(cacheManager) {
  const router = express.Router();

  router.get('/cache', (_req, res) => {
    try {
      const entries = cacheManager.getAll();
      res.json(entries);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/cache', (_req, res) => {
    try {
      cacheManager.clearAll();
      res.json({ cleared: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/cache/:name', (req, res) => {
    try {
      cacheManager.clearByName(req.params.name);
      res.json({ cleared: true, name: req.params.name });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

module.exports = createCacheRouter;
