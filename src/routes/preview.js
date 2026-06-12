const express = require('express');
const db = require('../db/database');
const { runPlayback, checkPublishConflict, publishDraftChanges } = require('../preview/previewEngine');

function createPreviewRouter() {
  const router = express.Router();

  router.get('/drafts', (req, res) => {
    try {
      const drafts = db.listDrafts();
      res.json(drafts);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/drafts/:id', (req, res) => {
    try {
      const draft = db.getDraftById(req.params.id);
      if (!draft) {
        return res.status(404).json({ error: 'Draft not found' });
      }
      const changes = db.listDraftChanges(req.params.id);
      const operations = db.listDraftOperations(req.params.id);
      res.json({ ...draft, changes, operations });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/drafts', (req, res) => {
    try {
      const { name, description } = req.body;
      if (!name) {
        return res.status(400).json({ error: 'name is required' });
      }
      const draft = db.createDraft(name, description);
      res.json(draft);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.put('/drafts/:id', (req, res) => {
    try {
      const draft = db.updateDraft(req.params.id, req.body);
      if (!draft) {
        return res.status(404).json({ error: 'Draft not found' });
      }
      res.json(draft);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/drafts/:id/changes', (req, res) => {
    try {
      const { changeType, targetId, zoneId, oldData, newData } = req.body;
      if (!changeType) {
        return res.status(400).json({ error: 'changeType is required' });
      }
      const change = db.addDraftChange(req.params.id, {
        changeType,
        targetId,
        zoneId,
        oldData,
        newData,
      });
      res.json(change);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/drafts/:id/changes/:changeId', (req, res) => {
    try {
      const success = db.deleteDraftChange(req.params.changeId);
      if (!success) {
        return res.status(404).json({ error: 'Change not found' });
      }
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/drafts/:id/playback', async (req, res) => {
    try {
      const { sampleSetId } = req.body;
      if (!sampleSetId) {
        return res.status(400).json({ error: 'sampleSetId is required' });
      }
      const result = await runPlayback(req.params.id, sampleSetId);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/drafts/:id/conflict', (req, res) => {
    try {
      const conflict = checkPublishConflict(req.params.id);
      res.json(conflict);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/drafts/:id/publish', async (req, res) => {
    try {
      const force = req.body.force === true;
      if (!force) {
        const conflict = checkPublishConflict(req.params.id);
        if (conflict.conflict) {
          return res.status(409).json(conflict);
        }
      }
      const draft = await publishDraftChanges(req.params.id);
      res.json(draft);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/drafts/:id/abandon', (req, res) => {
    try {
      const draft = db.abandonDraft(req.params.id);
      if (!draft) {
        return res.status(404).json({ error: 'Draft not found' });
      }
      res.json(draft);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/drafts/:id/reports', (req, res) => {
    try {
      const reports = db.listPlaybackReports(req.params.id);
      res.json(reports);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/reports/:id', (req, res) => {
    try {
      const report = db.getPlaybackReportById(req.params.id);
      if (!report) {
        return res.status(404).json({ error: 'Report not found' });
      }
      const summary = db.getPlaybackSummary(req.params.id);
      res.json({ ...report, summary });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/reports/:id/results', (req, res) => {
    try {
      const { changedOnly, failedOnly, blockedOnly, changeType } = req.query;
      const filters = {
        changedOnly: changedOnly === 'true',
        failedOnly: failedOnly === 'true',
        blockedOnly: blockedOnly === 'true',
        changeType,
      };
      const results = db.listPlaybackResults(req.params.id, filters);
      res.json(results);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/sample-sets', (req, res) => {
    try {
      const sets = db.listSampleSets();
      const result = sets.map((set) => {
        const samples = db.listSamples(set.id);
        return { ...set, sampleCount: samples.length };
      });
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/sample-sets/:id', (req, res) => {
    try {
      const set = db.getSampleSetById(req.params.id);
      if (!set) {
        return res.status(404).json({ error: 'Sample set not found' });
      }
      const samples = db.listSamples(req.params.id);
      res.json({ ...set, samples });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/sample-sets', (req, res) => {
    try {
      const { name, description } = req.body;
      if (!name) {
        return res.status(400).json({ error: 'name is required' });
      }
      const set = db.createSampleSet(name, description);
      res.json(set);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.put('/sample-sets/:id', (req, res) => {
    try {
      const set = db.updateSampleSet(req.params.id, req.body);
      if (!set) {
        return res.status(404).json({ error: 'Sample set not found' });
      }
      res.json(set);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/sample-sets/:id', (req, res) => {
    try {
      const success = db.deleteSampleSet(req.params.id);
      res.json({ success });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/sample-sets/:id/samples', (req, res) => {
    try {
      const { name, type, remark } = req.body;
      if (!name) {
        return res.status(400).json({ error: 'name is required' });
      }
      const sample = db.addSample(req.params.id, name, type || 'A', remark);
      res.json(sample);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.put('/samples/:id', (req, res) => {
    try {
      const sample = db.updateSample(req.params.id, req.body);
      if (!sample) {
        return res.status(404).json({ error: 'Sample not found' });
      }
      res.json(sample);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.delete('/samples/:id', (req, res) => {
    try {
      const success = db.deleteSample(req.params.id);
      res.json({ success });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/snapshots/latest', (req, res) => {
    try {
      const snapshot = db.getLatestConfigSnapshot();
      res.json(snapshot || { version: 0 });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/zones', (req, res) => {
    try {
      const zones = db.getAllZones();
      res.json(zones);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/policies', (req, res) => {
    try {
      const policies = db.listPolicies();
      res.json(policies);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/enforcement', (req, res) => {
    try {
      const blocklist = db.listBlocklistEntries(true);
      const allowlist = db.listAllowlistEntries();
      const ratelimit = db.listRatelimitRules();
      res.json({ blocklist, allowlist, ratelimit });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

module.exports = createPreviewRouter;
