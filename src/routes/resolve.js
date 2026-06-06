const express = require('express');

function createResolveRouter(resolver, detector) {
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

      if (detector) {
        detector.recordQueryExtended({
          name,
          type: queryType,
          resultCode: result.status,
          hops: result.hops || 0,
          answerSize: result.answer ? result.answer.length : 0,
          cached: result.cached || false,
          elapsedMs: result.elapsedMs || 0,
        });
      }

      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message, status: 'SERVFAIL' });
    }
  });

  return router;
}

module.exports = createResolveRouter;
