const express = require('express');
const db = require('../db/database');

function createAnalysisRouter(detector) {
  const router = express.Router();

  router.post('/analysis/scan', (req, res) => {
    try {
      const windowMinutes = parseInt(req.body?.windowMinutes, 10) || 5;
      const result = detector.runScan(windowMinutes);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/analysis/stats', (req, res) => {
    try {
      const windowMinutes = parseInt(req.query.windowMinutes, 10) || 5;
      const stats = detector.computeWindowStats(windowMinutes);
      res.json({
        windowMinutes: stats.windowMinutes,
        totalQueries: stats.totalQueries,
        uniqueDomains: stats.uniqueDomains,
        nxdomainRatio: Number(stats.nxdomainRatio.toFixed(4)),
        avgHops: Number(stats.avgHops.toFixed(2)),
        top5Domains: stats.topDomains.map((d) => ({
          domain: d.domain,
          queryCount: d.queryCount,
          nxdomainCount: d.nxdomainCount,
          avgHops: Number(d.avgHops.toFixed(2)),
          avgResponseSize: Number(d.avgAnswerSize.toFixed(2)),
        })),
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/analysis/alerts', (req, res) => {
    try {
      const filters = {};
      if (req.query.type) filters.type = req.query.type;
      if (req.query.severity) filters.severity = req.query.severity;
      if (req.query.status) filters.status = req.query.status;
      if (req.query.fromTime) filters.fromTime = parseInt(req.query.fromTime, 10);
      if (req.query.toTime) filters.toTime = parseInt(req.query.toTime, 10);
      const alerts = db.listAlerts(filters);
      res.json(alerts);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/analysis/alerts/summary', (_req, res) => {
    try {
      const summary = db.getAlertSummary();
      res.json(summary);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/analysis/alerts/:id', (req, res) => {
    try {
      const alert = db.getAlertById(req.params.id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      res.json(alert);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.put('/analysis/alerts/:id/dismiss', (req, res) => {
    try {
      const existing = db.getAlertById(req.params.id);
      if (!existing) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      const updated = db.dismissAlert(req.params.id);
      res.json(updated);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/analysis/thresholds', (_req, res) => {
    try {
      const thresholds = db.getThresholds();
      res.json(thresholds);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.put('/analysis/thresholds', (req, res) => {
    try {
      const updates = {};
      const body = req.body || {};

      if (body.amplification_count !== undefined || body.amplificationCount !== undefined) {
        updates.amplificationCount = body.amplification_count ?? body.amplificationCount;
      }
      if (body.amplification_response_size !== undefined || body.amplificationResponseSize !== undefined) {
        updates.amplificationResponseSize = body.amplification_response_size ?? body.amplificationResponseSize;
      }
      if (body.probe_nxdomain_ratio !== undefined || body.probeNxdomainRatio !== undefined) {
        updates.probeNxdomainRatio = body.probe_nxdomain_ratio ?? body.probeNxdomainRatio;
      }
      if (body.probe_subdomain_count !== undefined || body.probeSubdomainCount !== undefined) {
        updates.probeSubdomainCount = body.probe_subdomain_count ?? body.probeSubdomainCount;
      }
      if (body.tunnel_label_length !== undefined || body.tunnelLabelLength !== undefined) {
        updates.tunnelLabelLength = body.tunnel_label_length ?? body.tunnelLabelLength;
      }
      if (body.tunnel_entropy !== undefined || body.tunnelEntropy !== undefined) {
        updates.tunnelEntropy = body.tunnel_entropy ?? body.tunnelEntropy;
      }

      const updated = db.updateThresholds(updates);
      res.json(updated);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

module.exports = createAnalysisRouter;
