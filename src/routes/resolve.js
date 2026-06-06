const express = require('express');

function createResolveRouter(resolver, detector, enforcementManager) {
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

      if (enforcementManager) {
        const check = enforcementManager.checkQuery(name);
        if (check.action === 'block') {
          const blockedResult = {
            status: 'REFUSED',
            reason: 'blocked',
            matchedPattern: check.matchedPattern,
            question: { name, type: queryType },
            answer: [],
            elapsedMs: 0,
          };
          if (detector) {
            detector.recordQueryExtended({
              name,
              type: queryType,
              resultCode: 'REFUSED',
              hops: 0,
              answerSize: 0,
              cached: false,
              elapsedMs: 0,
            });
          }
          return res.json(blockedResult);
        }
        if (check.action === 'ratelimit') {
          const rlResult = {
            status: 'RATE_LIMITED',
            reason: `exceeded ${check.maxRequests} requests in ${check.windowSeconds}s`,
            matchedPattern: check.matchedPattern,
            retryAfter: check.retryAfter,
            question: { name, type: queryType },
            answer: [],
            elapsedMs: 0,
          };
          if (detector) {
            detector.recordQueryExtended({
              name,
              type: queryType,
              resultCode: 'RATE_LIMITED',
              hops: 0,
              answerSize: 0,
              cached: false,
              elapsedMs: 0,
            });
          }
          return res.json(rlResult);
        }
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
