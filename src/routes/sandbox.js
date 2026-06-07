const express = require('express');
const db = require('../db/database');

function createSandboxRouter(sandbox) {
  const router = express.Router();

  router.get('/sandbox/stats', (_req, res) => {
    res.json(sandbox.getStats());
  });

  router.post('/sandbox/execute', async (req, res) => {
    try {
      const { code, scriptId, timeoutMs } = req.body;

      if (!code || typeof code !== 'string') {
        return res.status(400).json({ error: 'code is required and must be a string' });
      }

      if (code.length > 100000) {
        return res.status(400).json({ error: 'code exceeds maximum length of 100000 characters' });
      }

      let scriptRecord = null;
      if (scriptId) {
        scriptRecord = db.getSavedScriptById(scriptId);
      }

      const result = await sandbox.execute(code, { timeoutMs });

      const executionRecord = {
        scriptName: scriptRecord ? scriptRecord.name : null,
        scriptId: scriptRecord ? scriptRecord.id : null,
        code,
        success: result.success,
        result: result.result,
        error: result.error,
        logs: result.logs,
        durationMs: result.durationMs,
        startedAt: result.startedAt,
        finishedAt: result.finishedAt,
      };

      try {
        db.recordExecution(executionRecord);
      } catch (e) {
        console.error('[Sandbox] Failed to record execution:', e.message);
      }

      if (!result.success && result.error && result.error.type === 'PermissionError') {
        return res.status(403).json(result);
      }

      res.json(result);
    } catch (err) {
      if (err.code === 'ERR_CONCURRENCY_LIMIT') {
        return res.status(429).json({
          success: false,
          error: {
            type: 'ConcurrencyLimitError',
            message: err.message,
          },
        });
      }
      res.status(500).json({
        success: false,
        error: {
          type: 'ServerError',
          message: err.message,
        },
      });
    }
  });

  router.post('/sandbox/scripts', (req, res) => {
    try {
      const { name, code, description } = req.body;

      if (!name || typeof name !== 'string') {
        return res.status(400).json({ error: 'name is required and must be a string' });
      }
      if (name.length > 100) {
        return res.status(400).json({ error: 'name exceeds maximum length of 100 characters' });
      }
      if (!code || typeof code !== 'string') {
        return res.status(400).json({ error: 'code is required and must be a string' });
      }
      if (code.length > 100000) {
        return res.status(400).json({ error: 'code exceeds maximum length of 100000 characters' });
      }

      const saved = db.saveScript(name, code, description);
      res.json(saved);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/sandbox/scripts', (_req, res) => {
    try {
      res.json(db.listSavedScripts());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/sandbox/scripts/:id', (req, res) => {
    try {
      const script = db.getSavedScriptById(req.params.id);
      if (!script) {
        return res.status(404).json({ error: 'Script not found' });
      }
      res.json(script);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/sandbox/scripts/:id', (req, res) => {
    try {
      const script = db.getSavedScriptById(req.params.id);
      if (!script) {
        return res.status(404).json({ error: 'Script not found' });
      }
      db.deleteSavedScript(req.params.id);
      res.json({ deleted: true, id: req.params.id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/sandbox/executions', (req, res) => {
    try {
      const limit = parseInt(req.query.limit, 10) || 50;
      const scriptId = req.query.scriptId || null;
      const safeLimit = Math.min(Math.max(limit, 1), 200);
      res.json(db.listExecutions(safeLimit, scriptId));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/sandbox/executions/:id', (req, res) => {
    try {
      const execution = db.getExecutionById(req.params.id);
      if (!execution) {
        return res.status(404).json({ error: 'Execution not found' });
      }
      res.json(execution);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

module.exports = createSandboxRouter;
