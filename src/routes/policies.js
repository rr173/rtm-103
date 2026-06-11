const express = require('express');
const db = require('../db/database');

const VALID_ACTIONS = ['rewrite', 'redirect', 'nxdomain', 'passthrough'];

function createPoliciesRouter(policyEngine) {
  const router = express.Router();

  router.post('/policies', (req, res) => {
    try {
      const {
        name,
        description,
        priority,
        enabled,
        domainPattern,
        recordType,
        timeWindow,
        responseRegex,
        action,
        actionParams,
      } = req.body;

      if (!name) {
        return res.status(400).json({ error: 'name is required' });
      }

      if (!action || !VALID_ACTIONS.includes(action)) {
        return res.status(400).json({
          error: `action must be one of: ${VALID_ACTIONS.join(', ')}`,
        });
      }

      if (action === 'rewrite' && (!actionParams || !actionParams.template)) {
        return res.status(400).json({
          error: 'actionParams.template is required for rewrite action',
        });
      }

      if (action === 'redirect' && (!actionParams || !actionParams.targetDomain)) {
        return res.status(400).json({
          error: 'actionParams.targetDomain is required for redirect action',
        });
      }

      if (priority !== undefined && (typeof priority !== 'number' || priority < 0)) {
        return res.status(400).json({
          error: 'priority must be a non-negative number',
        });
      }

      const policy = db.addPolicy({
        name,
        description,
        priority,
        enabled,
        domainPattern,
        recordType,
        timeWindow,
        responseRegex,
        action,
        actionParams,
      });

      res.status(201).json(policy);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/policies', (_req, res) => {
    try {
      const policies = db.listPolicies();
      res.json(policies);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/policies/logs', (req, res) => {
    try {
      const limit = parseInt(req.query.limit, 10) || 50;
      const logs = db.listPolicyLogs(Math.min(limit, 500));
      res.json(logs);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/policies/stats', (_req, res) => {
    try {
      const stats = db.getPolicyStats();
      res.json(stats);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/policies/:id', (req, res) => {
    try {
      const policy = db.getPolicyById(req.params.id);
      if (!policy) {
        return res.status(404).json({ error: 'Policy not found' });
      }
      res.json(policy);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.put('/policies/:id', (req, res) => {
    try {
      const { id } = req.params;
      const existing = db.getPolicyById(id);
      if (!existing) {
        return res.status(404).json({ error: 'Policy not found' });
      }

      const { action, actionParams } = req.body;

      if (action && !VALID_ACTIONS.includes(action)) {
        return res.status(400).json({
          error: `action must be one of: ${VALID_ACTIONS.join(', ')}`,
        });
      }

      const finalAction = action || existing.action;

      if (finalAction === 'rewrite' && actionParams && !actionParams.template) {
        return res.status(400).json({
          error: 'actionParams.template is required for rewrite action',
        });
      }

      if (finalAction === 'redirect' && actionParams && !actionParams.targetDomain) {
        return res.status(400).json({
          error: 'actionParams.targetDomain is required for redirect action',
        });
      }

      if (req.body.priority !== undefined && (typeof req.body.priority !== 'number' || req.body.priority < 0)) {
        return res.status(400).json({
          error: 'priority must be a non-negative number',
        });
      }

      const updated = db.updatePolicy(id, req.body);
      res.json(updated);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/policies/:id', (req, res) => {
    try {
      const existing = db.getPolicyById(req.params.id);
      if (!existing) {
        return res.status(404).json({ error: 'Policy not found' });
      }
      db.deletePolicy(req.params.id);
      res.status(204).send();
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/policies/reorder', (req, res) => {
    try {
      const { policyIds } = req.body;
      if (!Array.isArray(policyIds)) {
        return res.status(400).json({ error: 'policyIds must be an array' });
      }

      const existingPolicies = db.listPolicies();
      const existingIds = new Set(existingPolicies.map((p) => p.id));

      for (const id of policyIds) {
        if (!existingIds.has(id)) {
          return res.status(400).json({ error: `Policy ${id} does not exist` });
        }
      }

      const reordered = db.reorderPolicies(policyIds);
      res.json(reordered);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

module.exports = createPoliciesRouter;
