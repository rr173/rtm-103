const express = require('express');
const db = require('../db/database');

function createEnforcementRouter(enforcementManager) {
  const router = express.Router();

  router.post('/blocklist', (req, res) => {
    try {
      const { pattern, reason, expireMinutes } = req.body || {};
      if (!pattern) {
        return res.status(400).json({ error: 'pattern is required' });
      }
      const entry = db.addBlocklistEntry(
        pattern,
        reason || null,
        expireMinutes || 0
      );
      res.json(entry);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/blocklist', (_req, res) => {
    try {
      const entries = db.listBlocklistEntries(false);
      res.json(entries);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/blocklist/:id', (req, res) => {
    try {
      const existing = db.getBlocklistEntryById(req.params.id);
      if (!existing) {
        return res.status(404).json({ error: 'Blocklist entry not found' });
      }
      db.deleteBlocklistEntry(req.params.id);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/allowlist', (req, res) => {
    try {
      const { pattern } = req.body || {};
      if (!pattern) {
        return res.status(400).json({ error: 'pattern is required' });
      }
      const entry = db.addAllowlistEntry(pattern);
      res.json(entry);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/allowlist', (_req, res) => {
    try {
      const entries = db.listAllowlistEntries();
      res.json(entries);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/allowlist/:id', (req, res) => {
    try {
      const existing = db.getAllowlistEntryById(req.params.id);
      if (!existing) {
        return res.status(404).json({ error: 'Allowlist entry not found' });
      }
      db.deleteAllowlistEntry(req.params.id);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/ratelimit', (req, res) => {
    try {
      const { pattern, maxRequests, windowSeconds } = req.body || {};
      if (!pattern) {
        return res.status(400).json({ error: 'pattern is required' });
      }
      if (maxRequests === undefined || maxRequests === null) {
        return res.status(400).json({ error: 'maxRequests is required' });
      }
      const mr = parseInt(maxRequests, 10);
      const ws = windowSeconds !== undefined ? parseInt(windowSeconds, 10) : 60;
      if (!Number.isFinite(mr) || mr <= 0) {
        return res.status(400).json({ error: 'maxRequests must be a positive integer' });
      }
      if (!Number.isFinite(ws) || ws <= 0) {
        return res.status(400).json({ error: 'windowSeconds must be a positive integer' });
      }
      const rule = db.addRatelimitRule(pattern, mr, ws);
      res.json(rule);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/ratelimit', (_req, res) => {
    try {
      const rules = db.listRatelimitRules();
      res.json(rules);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.put('/ratelimit/:id', (req, res) => {
    try {
      const existing = db.getRatelimitRuleById(req.params.id);
      if (!existing) {
        return res.status(404).json({ error: 'Ratelimit rule not found' });
      }
      const { pattern, maxRequests, windowSeconds } = req.body || {};
      const updates = {};
      if (pattern !== undefined) updates.pattern = pattern;
      if (maxRequests !== undefined) {
        const mr = parseInt(maxRequests, 10);
        if (!Number.isFinite(mr) || mr <= 0) {
          return res.status(400).json({ error: 'maxRequests must be a positive integer' });
        }
        updates.maxRequests = mr;
      }
      if (windowSeconds !== undefined) {
        const ws = parseInt(windowSeconds, 10);
        if (!Number.isFinite(ws) || ws <= 0) {
          return res.status(400).json({ error: 'windowSeconds must be a positive integer' });
        }
        updates.windowSeconds = ws;
      }
      const updated = db.updateRatelimitRule(req.params.id, updates);
      res.json(updated);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/ratelimit/:id', (req, res) => {
    try {
      const existing = db.getRatelimitRuleById(req.params.id);
      if (!existing) {
        return res.status(404).json({ error: 'Ratelimit rule not found' });
      }
      db.deleteRatelimitRule(req.params.id);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  function extractDomainFromAlert(alert) {
    if (!alert || !alert.data) return null;
    if (alert.data.domain) return alert.data.domain;
    if (alert.data.parentDomain) return '*.' + alert.data.parentDomain;
    return null;
  }

  router.post('/analysis/alerts/:id/block', (req, res) => {
    try {
      const alert = db.getAlertById(req.params.id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      const domainPattern = extractDomainFromAlert(alert);
      if (!domainPattern) {
        return res.status(400).json({ error: 'Cannot extract domain from alert' });
      }
      const expireMinutes = req.body?.expireMinutes ?? 60;
      const reason = req.body?.reason || `Blocked from alert ${alert.id} (${alert.type})`;
      const entry = db.addBlocklistEntry(domainPattern, reason, expireMinutes);
      res.json({ blocklist: entry, fromAlert: alert.id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/analysis/alerts/:id/ratelimit', (req, res) => {
    try {
      const alert = db.getAlertById(req.params.id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      const domainPattern = extractDomainFromAlert(alert);
      if (!domainPattern) {
        return res.status(400).json({ error: 'Cannot extract domain from alert' });
      }
      const maxRequests = req.body?.maxRequests ?? 5;
      const windowSeconds = req.body?.windowSeconds ?? 60;
      const rule = db.addRatelimitRule(domainPattern, maxRequests, windowSeconds);
      res.json({ ratelimit: rule, fromAlert: alert.id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/enforcement/stats', (_req, res) => {
    try {
      const stats = enforcementManager.getEnforcementStats();
      res.json(stats);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

module.exports = createEnforcementRouter;
