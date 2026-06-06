const express = require('express');

function createProtocolRouter(dnsServer) {
  const router = express.Router();

  router.get('/protocol/stats', (_req, res) => {
    try {
      const stats = dnsServer.getStats();
      res.json(stats);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/protocol/config', async (req, res) => {
    try {
      const { port } = req.body || {};
      if (port !== undefined) {
        const p = parseInt(port, 10);
        if (!Number.isFinite(p) || p <= 0 || p > 65535) {
          return res.status(400).json({ error: 'port must be a valid integer between 1 and 65535' });
        }
        const result = await dnsServer.setPortAndRestart(p);
        return res.json({
          port: dnsServer.port,
          restarted: true,
          previousPort: result.oldPort,
        });
      }
      res.json(dnsServer.getConfig());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

module.exports = createProtocolRouter;
