const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

let SQL;
let db;

const dataDir = path.join(__dirname, '..', '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = process.env.DB_PATH || path.join(dataDir, 'dns.db');

const MAX_CHANGELOG_PER_ZONE = 500;

function saveDatabase() {
  if (!db) return;
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(dbPath, buffer);
}

async function initDatabase() {
  if (SQL && db) return;

  SQL = await initSqlJs();

  if (fs.existsSync(dbPath)) {
    const fileBuffer = fs.readFileSync(dbPath);
    db = new SQL.Database(fileBuffer);
    migrateSchema();
  } else {
    db = new SQL.Database();
    initSchema();
  }

  saveDatabase();

  setInterval(saveDatabase, 5000);

  process.on('beforeExit', saveDatabase);
  process.on('SIGINT', () => {
    saveDatabase();
    process.exit();
  });
}

function columnExists(tableName, columnName) {
  const results = queryAll(`PRAGMA table_info(${tableName})`);
  return results.some((col) => col.name === columnName);
}

function tableExists(tableName) {
  const result = queryOne(
    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
    [tableName]
  );
  return !!result;
}

function migrateSchema() {
  if (!columnExists('zones', 'serial')) {
    run('ALTER TABLE zones ADD COLUMN serial INTEGER NOT NULL DEFAULT 1');
  }
  if (!columnExists('zones', 'last_change_at')) {
    run('ALTER TABLE zones ADD COLUMN last_change_at INTEGER');
  }
  if (!columnExists('zones', 'sync_total')) {
    run('ALTER TABLE zones ADD COLUMN sync_total INTEGER NOT NULL DEFAULT 0');
  }
  if (!columnExists('zones', 'sync_incremental')) {
    run(
      'ALTER TABLE zones ADD COLUMN sync_incremental INTEGER NOT NULL DEFAULT 0'
    );
  }
  if (!columnExists('zones', 'sync_full')) {
    run('ALTER TABLE zones ADD COLUMN sync_full INTEGER NOT NULL DEFAULT 0');
  }
  if (!columnExists('zones', 'last_sync_at')) {
    run('ALTER TABLE zones ADD COLUMN last_sync_at INTEGER');
  }
  if (!tableExists('zone_changelog')) {
    initChangelogTable();
  }
}

function initChangelogTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS zone_changelog (
      id TEXT PRIMARY KEY,
      zone_id TEXT NOT NULL,
      serial INTEGER NOT NULL,
      op TEXT NOT NULL,
      old_record TEXT,
      new_record TEXT,
      timestamp INTEGER NOT NULL
    );
  `);
  db.run(
    'CREATE INDEX IF NOT EXISTS idx_changelog_zone_serial ON zone_changelog(zone_id, serial);'
  );
}

function initSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS zones (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      parent_id TEXT,
      serial INTEGER NOT NULL DEFAULT 1,
      last_change_at INTEGER,
      sync_total INTEGER NOT NULL DEFAULT 0,
      sync_incremental INTEGER NOT NULL DEFAULT 0,
      sync_full INTEGER NOT NULL DEFAULT 0,
      last_sync_at INTEGER,
      created_at INTEGER NOT NULL
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS records (
      id TEXT PRIMARY KEY,
      zone_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      value TEXT NOT NULL,
      ttl INTEGER NOT NULL DEFAULT 3600,
      created_at INTEGER NOT NULL
    );
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_records_zone ON records(zone_id);');
  db.run(
    'CREATE INDEX IF NOT EXISTS idx_records_name_type ON records(name, type);'
  );
  db.run('CREATE INDEX IF NOT EXISTS idx_zones_parent ON zones(parent_id);');
  initChangelogTable();
}

function beginTransaction() {
  run('BEGIN TRANSACTION');
}

function commitTransaction() {
  run('COMMIT');
}

function rollbackTransaction() {
  run('ROLLBACK');
}

function run(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.run(params);
  stmt.free();
}

function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

function queryOne(sql, params = []) {
  const results = queryAll(sql, params);
  return results.length > 0 ? results[0] : null;
}

function incrementZoneSerial(zoneId, now) {
  run(
    'UPDATE zones SET serial = serial + 1, last_change_at = ? WHERE id = ?',
    [now, zoneId]
  );
  const zone = queryOne('SELECT serial FROM zones WHERE id = ?', [zoneId]);
  return zone ? zone.serial : null;
}

function addChangelogEntry(zoneId, serial, op, oldRecord, newRecord, now) {
  const id = uuidv4();
  const oldJson = oldRecord ? JSON.stringify(oldRecord) : null;
  const newJson = newRecord ? JSON.stringify(newRecord) : null;
  run(
    'INSERT INTO zone_changelog (id, zone_id, serial, op, old_record, new_record, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, zoneId, serial, op, oldJson, newJson, now]
  );
}

function trimChangelog(zoneId) {
  const countRow = queryOne(
    'SELECT COUNT(*) as cnt FROM zone_changelog WHERE zone_id = ?',
    [zoneId]
  );
  const count = countRow ? countRow.cnt : 0;
  if (count > MAX_CHANGELOG_PER_ZONE) {
    const toDelete = count - MAX_CHANGELOG_PER_ZONE;
    run(
      'DELETE FROM zone_changelog WHERE id IN (SELECT id FROM zone_changelog WHERE zone_id = ? ORDER BY serial ASC LIMIT ?)',
      [zoneId, toDelete]
    );
  }
}

function createZone(name, parentId, nsRecords) {
  const id = uuidv4();
  const now = Date.now();

  beginTransaction();
  try {
    run(
      'INSERT INTO zones (id, name, parent_id, serial, last_change_at, created_at) VALUES (?, ?, ?, 1, ?, ?)',
      [id, name, parentId, now, now]
    );

    if (nsRecords && nsRecords.length > 0) {
      nsRecords.forEach((ns) => {
        const recordId = uuidv4();
        run(
          'INSERT INTO records (id, zone_id, name, type, value, ttl, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [recordId, id, name, 'NS', ns.nameserver, ns.ttl || 3600, now]
        );
        if (ns.glueIp) {
          const glueId = uuidv4();
          run(
            'INSERT INTO records (id, zone_id, name, type, value, ttl, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [glueId, id, ns.nameserver, 'A', ns.glueIp, ns.ttl || 3600, now]
          );
        }
      });
    }

    commitTransaction();
  } catch (err) {
    rollbackTransaction();
    throw err;
  }

  saveDatabase();
  return getZoneById(id);
}

function getZoneById(id) {
  return queryOne('SELECT * FROM zones WHERE id = ?', [id]);
}

function getZoneByName(name) {
  return queryOne('SELECT * FROM zones WHERE name = ?', [name]);
}

function getAllZones() {
  const zones = queryAll('SELECT * FROM zones ORDER BY name');
  return zones.map((z) => {
    const records = queryAll(
      'SELECT id, name, type, value, ttl FROM records WHERE zone_id = ? ORDER BY name, type',
      [z.id]
    );
    return { ...z, records };
  });
}

function deleteZone(id) {
  beginTransaction();
  try {
    run('DELETE FROM records WHERE zone_id = ?', [id]);
    run('DELETE FROM zone_changelog WHERE zone_id = ?', [id]);
    run('DELETE FROM zones WHERE id = ?', [id]);
    commitTransaction();
  } catch (err) {
    rollbackTransaction();
    throw err;
  }
  saveDatabase();
}

function addRecord(zoneId, name, type, value, ttl) {
  const id = uuidv4();
  const now = Date.now();

  beginTransaction();
  try {
    run(
      'INSERT INTO records (id, zone_id, name, type, value, ttl, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, zoneId, name, type, value, ttl, now]
    );

    const newSerial = incrementZoneSerial(zoneId, now);

    const newRecord = { id, zone_id: zoneId, name, type, value, ttl };
    addChangelogEntry(zoneId, newSerial, 'add', null, newRecord, now);

    trimChangelog(zoneId);

    commitTransaction();
  } catch (err) {
    rollbackTransaction();
    throw err;
  }

  saveDatabase();
  return getRecordById(id);
}

function updateRecord(zoneId, recordId, updates) {
  const now = Date.now();

  beginTransaction();
  try {
    const oldRecord = queryOne(
      'SELECT id, zone_id, name, type, value, ttl FROM records WHERE id = ?',
      [recordId]
    );
    if (!oldRecord) {
      commitTransaction();
      return null;
    }

    const newValue = updates.value !== undefined ? updates.value : oldRecord.value;
    const newTtl = updates.ttl !== undefined ? updates.ttl : oldRecord.ttl;

    run('UPDATE records SET value = ?, ttl = ? WHERE id = ?', [
      newValue,
      newTtl,
      recordId,
    ]);

    const newSerial = incrementZoneSerial(zoneId, now);

    const newRecord = {
      id: oldRecord.id,
      zone_id: oldRecord.zone_id,
      name: oldRecord.name,
      type: oldRecord.type,
      value: newValue,
      ttl: newTtl,
    };
    addChangelogEntry(zoneId, newSerial, 'modify', oldRecord, newRecord, now);

    trimChangelog(zoneId);

    commitTransaction();
  } catch (err) {
    rollbackTransaction();
    throw err;
  }

  saveDatabase();
  return getRecordById(recordId);
}

function deleteRecord(zoneId, recordId) {
  const now = Date.now();

  beginTransaction();
  try {
    const oldRecord = queryOne(
      'SELECT id, zone_id, name, type, value, ttl FROM records WHERE id = ?',
      [recordId]
    );
    if (!oldRecord) {
      commitTransaction();
      return false;
    }

    run('DELETE FROM records WHERE id = ?', [recordId]);

    const newSerial = incrementZoneSerial(zoneId, now);

    addChangelogEntry(zoneId, newSerial, 'delete', oldRecord, null, now);

    trimChangelog(zoneId);

    commitTransaction();
  } catch (err) {
    rollbackTransaction();
    throw err;
  }

  saveDatabase();
  return true;
}

function getRecordById(id) {
  return queryOne(
    'SELECT id, zone_id, name, type, value, ttl FROM records WHERE id = ?',
    [id]
  );
}

function getRecordsByZone(zoneId) {
  return queryAll(
    'SELECT id, zone_id, name, type, value, ttl FROM records WHERE zone_id = ? ORDER BY name, type',
    [zoneId]
  );
}

function getRecordsByZoneForTransfer(zoneId) {
  return queryAll(
    'SELECT name, type, value, ttl FROM records WHERE zone_id = ? ORDER BY name, type',
    [zoneId]
  );
}

function getZoneSoa(zoneId) {
  const zone = getZoneById(zoneId);
  if (!zone) return null;
  const countRow = queryOne(
    'SELECT COUNT(*) as cnt FROM records WHERE zone_id = ?',
    [zoneId]
  );
  return {
    serial: zone.serial,
    lastChangeAt: zone.last_change_at,
    recordCount: countRow ? countRow.cnt : 0,
  };
}

function getChangelog(zoneId, fromSerial, toSerial) {
  let sql =
    'SELECT id, zone_id, serial, op, old_record, new_record, timestamp FROM zone_changelog WHERE zone_id = ?';
  const params = [zoneId];

  const conditions = [];
  if (fromSerial !== undefined && fromSerial !== null) {
    conditions.push('serial > ?');
    params.push(fromSerial);
  }
  if (toSerial !== undefined && toSerial !== null) {
    conditions.push('serial <= ?');
    params.push(toSerial);
  }
  if (conditions.length > 0) {
    sql += ' AND ' + conditions.join(' AND ');
  }
  sql += ' ORDER BY serial ASC';

  const rows = queryAll(sql, params);
  return rows.map((row) => ({
    serial: row.serial,
    op: row.op,
    oldRecord: row.old_record ? JSON.parse(row.old_record) : null,
    newRecord: row.new_record ? JSON.parse(row.new_record) : null,
    timestamp: row.timestamp,
  }));
}

function getChangelogRange(zoneId) {
  return queryOne(
    'SELECT MIN(serial) as minSerial, MAX(serial) as maxSerial FROM zone_changelog WHERE zone_id = ?',
    [zoneId]
  );
}

function recordSync(zoneId, syncType) {
  const now = Date.now();
  if (syncType === 'incremental') {
    run(
      'UPDATE zones SET sync_total = sync_total + 1, sync_incremental = sync_incremental + 1, last_sync_at = ? WHERE id = ?',
      [now, zoneId]
    );
  } else if (syncType === 'full') {
    run(
      'UPDATE zones SET sync_total = sync_total + 1, sync_full = sync_full + 1, last_sync_at = ? WHERE id = ?',
      [now, zoneId]
    );
  }
  saveDatabase();
}

function getSyncStats(zoneId) {
  const zone = getZoneById(zoneId);
  if (!zone) return null;
  return {
    totalSyncs: zone.sync_total || 0,
    incrementalSyncs: zone.sync_incremental || 0,
    fullSyncs: zone.sync_full || 0,
    lastSyncAt: zone.last_sync_at || null,
  };
}

function findRecords(name, type) {
  if (type) {
    return queryAll(
      'SELECT id, zone_id, name, type, value, ttl FROM records WHERE name = ? AND type = ?',
      [name, type]
    );
  }
  return queryAll(
    'SELECT id, zone_id, name, type, value, ttl FROM records WHERE name = ?',
    [name]
  );
}

function findDelegationNs(zoneName) {
  const parent = getParentZone(zoneName);
  if (!parent) return [];
  return queryAll(
    "SELECT id, zone_id, name, type, value, ttl FROM records WHERE zone_id = ? AND type = 'NS' AND name = ?",
    [parent.id, zoneName]
  );
}

function getParentZone(zoneName) {
  if (zoneName === '.') return null;
  const parts = zoneName.split('.');
  if (parts[0] === '') parts.shift();
  parts.shift();
  const parentName = parts.length === 0 ? '.' : parts.join('.');
  return getZoneByName(parentName);
}

function findBestMatchingZone(domainName) {
  if (domainName === '.') return getZoneByName('.');

  let name = domainName;
  if (name.endsWith('.')) name = name.slice(0, -1);

  const parts = name.split('.');
  for (let i = 0; i < parts.length; i++) {
    const candidate = parts.slice(i).join('.');
    const zone = getZoneByName(candidate);
    if (zone) return zone;
  }
  return getZoneByName('.');
}

module.exports = {
  initDatabase,
  createZone,
  getZoneById,
  getZoneByName,
  getAllZones,
  deleteZone,
  addRecord,
  updateRecord,
  deleteRecord,
  getRecordById,
  getRecordsByZone,
  getRecordsByZoneForTransfer,
  getZoneSoa,
  getChangelog,
  getChangelogRange,
  recordSync,
  getSyncStats,
  findRecords,
  findDelegationNs,
  getParentZone,
  findBestMatchingZone,
};
