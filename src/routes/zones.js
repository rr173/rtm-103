const express = require('express');
const db = require('../db/database');

const router = express.Router();

router.post('/zones', (req, res) => {
  try {
    const { name, parentId, nsRecords } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Zone name is required' });
    }

    if (name !== '.') {
      if (!parentId) {
        return res.status(400).json({ error: 'parentId is required for non-root zones' });
      }
      const parent = db.getZoneById(parentId);
      if (!parent) {
        return res.status(404).json({ error: 'Parent zone not found' });
      }
    }

    const existing = db.getZoneByName(name);
    if (existing) {
      return res.status(409).json({ error: 'Zone already exists' });
    }

    const zone = db.createZone(name, name === '.' ? null : parentId, nsRecords || []);
    const records = db.getRecordsByZone(zone.id);
    res.status(201).json({ ...zone, records });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/zones', (_req, res) => {
  try {
    const zones = db.getAllZones();
    res.json(zones);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/zones/:zoneId', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });
    const records = db.getRecordsByZone(zone.id);
    res.json({ ...zone, records });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/zones/:zoneId/records', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    const { name, type, value, ttl } = req.body;

    if (!name || !type || !value) {
      return res.status(400).json({ error: 'name, type, and value are required' });
    }

    const validTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR'];
    if (!validTypes.includes(type.toUpperCase())) {
      return res.status(400).json({ error: `Invalid record type. Must be one of: ${validTypes.join(', ')}` });
    }

    const record = db.addRecord(zone.id, name, type.toUpperCase(), value, ttl || 3600);
    res.status(201).json(record);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/zones/:zoneId/records', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });
    const records = db.getRecordsByZone(zone.id);
    res.json(records);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
