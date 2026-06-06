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

router.get('/zones/:zoneId/soa', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });
    const soa = db.getZoneSoa(zone.id);
    res.json(soa);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/zones/:zoneId/changelog', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    const fromSerial = req.query.fromSerial !== undefined ? parseInt(req.query.fromSerial, 10) : null;
    const toSerial = req.query.toSerial !== undefined ? parseInt(req.query.toSerial, 10) : null;

    if (fromSerial !== null && isNaN(fromSerial)) {
      return res.status(400).json({ error: 'fromSerial must be a valid integer' });
    }
    if (toSerial !== null && isNaN(toSerial)) {
      return res.status(400).json({ error: 'toSerial must be a valid integer' });
    }

    const changelog = db.getChangelog(zone.id, fromSerial, toSerial);
    res.json(changelog);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/zones/:zoneId/transfer/full', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    const records = db.getRecordsByZoneForTransfer(zone.id);
    res.json({
      zone_name: zone.name,
      serial: zone.serial,
      records,
      timestamp: Date.now(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/zones/:zoneId/transfer/incremental', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    if (req.query.fromSerial === undefined) {
      return res.status(400).json({ error: 'fromSerial query parameter is required' });
    }

    const fromSerial = parseInt(req.query.fromSerial, 10);
    if (isNaN(fromSerial)) {
      return res.status(400).json({ error: 'fromSerial must be a valid integer' });
    }

    const range = db.getChangelogRange(zone.id);
    if (range && range.minSerial !== null && fromSerial < range.minSerial - 1) {
      return res.status(409).json({ error: '序列号过旧,请使用全量传输' });
    }

    const changes = db.getChangelog(zone.id, fromSerial, zone.serial);

    res.json({
      zone_name: zone.name,
      fromSerial,
      toSerial: zone.serial,
      changes,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/zones/:zoneId/sync', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    const { currentSerial } = req.body;
    if (currentSerial === undefined || currentSerial === null) {
      return res.status(400).json({ error: 'currentSerial is required' });
    }

    const cs = parseInt(currentSerial, 10);
    if (isNaN(cs)) {
      return res.status(400).json({ error: 'currentSerial must be a valid integer' });
    }

    if (cs >= zone.serial) {
      db.recordSync(zone.id, 'noop');
      return res.json({ upToDate: true, syncType: 'none' });
    }

    const range = db.getChangelogRange(zone.id);
    const canDoIncremental = range && range.minSerial !== null && cs >= range.minSerial - 1;

    if (canDoIncremental) {
      const changes = db.getChangelog(zone.id, cs, zone.serial);
      db.recordSync(zone.id, 'incremental');
      return res.json({
        upToDate: false,
        syncType: 'incremental',
        zone_name: zone.name,
        fromSerial: cs,
        toSerial: zone.serial,
        changes,
      });
    } else {
      const records = db.getRecordsByZoneForTransfer(zone.id);
      db.recordSync(zone.id, 'full');
      return res.json({
        upToDate: false,
        syncType: 'full',
        zone_name: zone.name,
        serial: zone.serial,
        records,
        timestamp: Date.now(),
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/zones/:zoneId/sync/status', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });
    const stats = db.getSyncStats(zone.id);
    res.json(stats);
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

    const validTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'DS'];
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

router.put('/zones/:zoneId/records/:recordId', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    const record = db.getRecordById(req.params.recordId);
    if (!record) return res.status(404).json({ error: 'Record not found' });

    if (record.zone_id !== zone.id) {
      return res.status(400).json({ error: 'Record does not belong to this zone' });
    }

    const updates = {};
    if (req.body.value !== undefined) updates.value = req.body.value;
    if (req.body.ttl !== undefined) {
      const ttl = parseInt(req.body.ttl, 10);
      if (isNaN(ttl) || ttl < 0) {
        return res.status(400).json({ error: 'ttl must be a non-negative integer' });
      }
      updates.ttl = ttl;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'At least one of value or ttl must be provided' });
    }

    const updated = db.updateRecord(zone.id, record.id, updates);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/zones/:zoneId/records/:recordId', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    const record = db.getRecordById(req.params.recordId);
    if (!record) return res.status(404).json({ error: 'Record not found' });

    if (record.zone_id !== zone.id) {
      return res.status(400).json({ error: 'Record does not belong to this zone' });
    }

    const deleted = db.deleteRecord(zone.id, record.id);
    if (!deleted) {
      return res.status(404).json({ error: 'Record not found' });
    }
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/zones/:zoneId/dnssec/enable', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    const result = db.enableDnssec(zone.id);
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/zones/:zoneId/dnssec', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    const status = db.getDnssecStatus(zone.id);
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/zones/:zoneId/dnssec/disable', (req, res) => {
  try {
    const zone = db.getZoneById(req.params.zoneId);
    if (!zone) return res.status(404).json({ error: 'Zone not found' });

    db.disableDnssec(zone.id);
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/dnssec/trust-anchor', (req, res) => {
  try {
    const { keyTag } = req.body;
    if (!keyTag) {
      return res.status(400).json({ error: 'keyTag is required' });
    }
    const result = db.setTrustAnchor(String(keyTag));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/dnssec/trust-anchor', (_req, res) => {
  try {
    const anchor = db.getTrustAnchor();
    if (!anchor) {
      return res.json({ set: false });
    }
    res.json({ set: true, keyTag: anchor.key_tag, setAt: anchor.set_at });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
