const express = require('express');

function createResolveRouter(resolver) {
  const router = express.Router();

  router.post('/resolve', async (req, res) => {
    try {
      const { name, type, dnssec } = req.body;

      if (!name) {
        return res.status(400).json({ error: 'name is required' });
      }

      const queryType = (type || 'A').toUpperCase();
      const validTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'ANY'];
      if (!validTypes.includes(queryType)) {
        return res.status(400).json({ error: `Invalid type. Must be one of: ${validTypes.join(', ')}` });
      }

      const result = await resolver.resolve(name, queryType, !!dnssec);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message, status: 'SERVFAIL' });
    }
  });

  return router;
}

module.exports = createResolveRouter;
