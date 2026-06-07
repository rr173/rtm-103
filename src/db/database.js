const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
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
  if (!tableExists('zone_dnssec')) {
    initDnssecTable();
  }
  if (!tableExists('trust_anchor')) {
    initTrustAnchorTable();
  }
  if (!tableExists('analysis_alerts')) {
    initAnalysisAlertsTable();
  }
  if (!tableExists('analysis_thresholds')) {
    initAnalysisThresholdsTable();
  }
  if (!tableExists('blocklist')) {
    initBlocklistTable();
  }
  if (!tableExists('allowlist')) {
    initAllowlistTable();
  }
  if (!tableExists('ratelimit_rules')) {
    initRatelimitRulesTable();
  }
  if (!tableExists('saved_scripts')) {
    initSavedScriptsTable();
  }
  if (!tableExists('script_executions')) {
    initScriptExecutionsTable();
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

function initDnssecTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS zone_dnssec (
      zone_id TEXT PRIMARY KEY,
      enabled INTEGER NOT NULL DEFAULT 0,
      key_tag TEXT NOT NULL,
      algorithm TEXT NOT NULL,
      secret TEXT NOT NULL,
      enabled_at INTEGER,
      FOREIGN KEY (zone_id) REFERENCES zones(id)
    );
  `);
}

function initTrustAnchorTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS trust_anchor (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      key_tag TEXT NOT NULL,
      set_at INTEGER NOT NULL
    );
  `);
}

function initAnalysisAlertsTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS analysis_alerts (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      data TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      dismissed_at INTEGER
    );
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_alerts_type ON analysis_alerts(type);');
  db.run('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON analysis_alerts(severity);');
  db.run('CREATE INDEX IF NOT EXISTS idx_alerts_status ON analysis_alerts(status);');
  db.run('CREATE INDEX IF NOT EXISTS idx_alerts_created ON analysis_alerts(created_at);');
}

function initAnalysisThresholdsTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS analysis_thresholds (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      amplification_count INTEGER NOT NULL DEFAULT 20,
      amplification_response_size INTEGER NOT NULL DEFAULT 3,
      probe_nxdomain_ratio REAL NOT NULL DEFAULT 0.4,
      probe_subdomain_count INTEGER NOT NULL DEFAULT 10,
      tunnel_label_length INTEGER NOT NULL DEFAULT 30,
      tunnel_entropy REAL NOT NULL DEFAULT 3.5
    );
  `);
  const existing = queryOne('SELECT id FROM analysis_thresholds WHERE id = 1');
  if (!existing) {
    run(
      'INSERT INTO analysis_thresholds (id, amplification_count, amplification_response_size, probe_nxdomain_ratio, probe_subdomain_count, tunnel_label_length, tunnel_entropy) VALUES (1, 20, 3, 0.4, 10, 30, 3.5)'
    );
  }
}

function initBlocklistTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS blocklist (
      id TEXT PRIMARY KEY,
      pattern TEXT NOT NULL,
      reason TEXT,
      expire_minutes INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_blocklist_pattern ON blocklist(pattern);');
}

function initAllowlistTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS allowlist (
      id TEXT PRIMARY KEY,
      pattern TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_allowlist_pattern ON allowlist(pattern);');
}

function initRatelimitRulesTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS ratelimit_rules (
      id TEXT PRIMARY KEY,
      pattern TEXT NOT NULL,
      max_requests INTEGER NOT NULL,
      window_seconds INTEGER NOT NULL DEFAULT 60,
      created_at INTEGER NOT NULL
    );
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_ratelimit_pattern ON ratelimit_rules(pattern);');
}

function initSavedScriptsTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS saved_scripts (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      description TEXT,
      code TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_saved_scripts_name ON saved_scripts(name);');
}

function initScriptExecutionsTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS script_executions (
      id TEXT PRIMARY KEY,
      script_name TEXT,
      script_id TEXT,
      code TEXT NOT NULL,
      success INTEGER NOT NULL,
      result TEXT,
      error TEXT,
      logs TEXT,
      duration_ms INTEGER NOT NULL,
      started_at INTEGER NOT NULL,
      finished_at INTEGER NOT NULL
    );
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_executions_started ON script_executions(started_at DESC);');
  db.run('CREATE INDEX IF NOT EXISTS idx_executions_script_id ON script_executions(script_id);');
}

function addBlocklistEntry(pattern, reason, expireMinutes) {
  const id = uuidv4();
  const now = Date.now();
  run(
    'INSERT INTO blocklist (id, pattern, reason, expire_minutes, created_at) VALUES (?, ?, ?, ?, ?)',
    [id, pattern, reason || null, expireMinutes || 0, now]
  );
  saveDatabase();
  return getBlocklistEntryById(id);
}

function getBlocklistEntryById(id) {
  return queryOne('SELECT * FROM blocklist WHERE id = ?', [id]);
}

function listBlocklistEntries(includeExpired = false) {
  const rows = queryAll('SELECT * FROM blocklist ORDER BY created_at DESC');
  const now = Date.now();
  return rows.filter((row) => {
    if (includeExpired) return true;
    if (row.expire_minutes === 0) return true;
    const expireAt = row.created_at + row.expire_minutes * 60 * 1000;
    return expireAt > now;
  });
}

function deleteBlocklistEntry(id) {
  run('DELETE FROM blocklist WHERE id = ?', [id]);
  saveDatabase();
}

function addAllowlistEntry(pattern) {
  const id = uuidv4();
  const now = Date.now();
  run(
    'INSERT INTO allowlist (id, pattern, created_at) VALUES (?, ?, ?)',
    [id, pattern, now]
  );
  saveDatabase();
  return getAllowlistEntryById(id);
}

function getAllowlistEntryById(id) {
  return queryOne('SELECT * FROM allowlist WHERE id = ?', [id]);
}

function listAllowlistEntries() {
  return queryAll('SELECT * FROM allowlist ORDER BY created_at DESC');
}

function deleteAllowlistEntry(id) {
  run('DELETE FROM allowlist WHERE id = ?', [id]);
  saveDatabase();
}

function addRatelimitRule(pattern, maxRequests, windowSeconds = 60) {
  const id = uuidv4();
  const now = Date.now();
  run(
    'INSERT INTO ratelimit_rules (id, pattern, max_requests, window_seconds, created_at) VALUES (?, ?, ?, ?, ?)',
    [id, pattern, maxRequests, windowSeconds, now]
  );
  saveDatabase();
  return getRatelimitRuleById(id);
}

function getRatelimitRuleById(id) {
  return queryOne('SELECT * FROM ratelimit_rules WHERE id = ?', [id]);
}

function listRatelimitRules() {
  return queryAll('SELECT * FROM ratelimit_rules ORDER BY created_at DESC');
}

function updateRatelimitRule(id, updates) {
  const current = getRatelimitRuleById(id);
  if (!current) return null;
  const maxRequests = updates.maxRequests !== undefined ? updates.maxRequests : current.max_requests;
  const windowSeconds = updates.windowSeconds !== undefined ? updates.windowSeconds : current.window_seconds;
  const pattern = updates.pattern !== undefined ? updates.pattern : current.pattern;
  run(
    'UPDATE ratelimit_rules SET pattern = ?, max_requests = ?, window_seconds = ? WHERE id = ?',
    [pattern, maxRequests, windowSeconds, id]
  );
  saveDatabase();
  return getRatelimitRuleById(id);
}

function deleteRatelimitRule(id) {
  run('DELETE FROM ratelimit_rules WHERE id = ?', [id]);
  saveDatabase();
}

function saveScript(name, code, description) {
  const existing = queryOne('SELECT id FROM saved_scripts WHERE name = ?', [name]);
  const now = Date.now();
  if (existing) {
    run(
      'UPDATE saved_scripts SET code = ?, description = ?, updated_at = ? WHERE id = ?',
      [code, description || null, now, existing.id]
    );
    saveDatabase();
    return getSavedScriptById(existing.id);
  } else {
    const id = uuidv4();
    run(
      'INSERT INTO saved_scripts (id, name, description, code, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
      [id, name, description || null, code, now, now]
    );
    saveDatabase();
    return getSavedScriptById(id);
  }
}

function getSavedScriptById(id) {
  return queryOne('SELECT * FROM saved_scripts WHERE id = ?', [id]);
}

function getSavedScriptByName(name) {
  return queryOne('SELECT * FROM saved_scripts WHERE name = ?', [name]);
}

function listSavedScripts() {
  return queryAll('SELECT id, name, description, created_at, updated_at FROM saved_scripts ORDER BY updated_at DESC');
}

function deleteSavedScript(id) {
  run('DELETE FROM saved_scripts WHERE id = ?', [id]);
  saveDatabase();
}

function recordExecution(execution) {
  const id = execution.id || uuidv4();
  run(
    'INSERT INTO script_executions (id, script_name, script_id, code, success, result, error, logs, duration_ms, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
      id,
      execution.scriptName || null,
      execution.scriptId || null,
      execution.code,
      execution.success ? 1 : 0,
      execution.result !== undefined ? JSON.stringify(execution.result) : null,
      execution.error ? JSON.stringify(execution.error) : null,
      execution.logs ? JSON.stringify(execution.logs) : null,
      execution.durationMs,
      execution.startedAt,
      execution.finishedAt,
    ]
  );
  saveDatabase();
  return getExecutionById(id);
}

function getExecutionById(id) {
  const row = queryOne('SELECT * FROM script_executions WHERE id = ?', [id]);
  if (!row) return null;
  return {
    id: row.id,
    scriptName: row.script_name,
    scriptId: row.script_id,
    code: row.code,
    success: row.success === 1,
    result: row.result ? JSON.parse(row.result) : null,
    error: row.error ? JSON.parse(row.error) : null,
    logs: row.logs ? JSON.parse(row.logs) : [],
    durationMs: row.duration_ms,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
  };
}

function listExecutions(limit = 50, scriptId = null) {
  let sql = 'SELECT * FROM script_executions';
  const params = [];
  if (scriptId) {
    sql += ' WHERE script_id = ?';
    params.push(scriptId);
  }
  sql += ' ORDER BY started_at DESC LIMIT ?';
  params.push(limit);
  const rows = queryAll(sql, params);
  return rows.map((row) => ({
    id: row.id,
    scriptName: row.script_name,
    scriptId: row.script_id,
    code: row.code,
    success: row.success === 1,
    result: row.result ? JSON.parse(row.result) : null,
    error: row.error ? JSON.parse(row.error) : null,
    logs: row.logs ? JSON.parse(row.logs) : [],
    durationMs: row.duration_ms,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
  }));
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
  initDnssecTable();
  initTrustAnchorTable();
  initAnalysisAlertsTable();
  initAnalysisThresholdsTable();
  initBlocklistTable();
  initAllowlistTable();
  initRatelimitRulesTable();
  initSavedScriptsTable();
  initScriptExecutionsTable();
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

    if (type !== 'RRSIG') {
      const dnssec = getZoneDnssec(zoneId);
      if (dnssec && dnssec.enabled) {
        const newRecord = { id, zone_id: zoneId, name, type, value, ttl };
        generateRrsigForRecord(zoneId, newRecord, dnssec);
      }
    }

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

    if (oldRecord.type !== 'RRSIG') {
      const dnssec = getZoneDnssec(zoneId);
      const newRecord = {
        id: oldRecord.id,
        zone_id: oldRecord.zone_id,
        name: oldRecord.name,
        type: oldRecord.type,
        value: newValue,
        ttl: newTtl,
      };
      regenerateRrsigForRecord(zoneId, oldRecord.name, oldRecord.type, newRecord, dnssec);
    }

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

    if (oldRecord.type !== 'RRSIG') {
      removeRrsigForRecord(zoneId, oldRecord.name, oldRecord.type);
    }

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
  } else if (syncType === 'noop') {
    run(
      'UPDATE zones SET sync_total = sync_total + 1, last_sync_at = ? WHERE id = ?',
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

function generateKeyTag() {
  return String(Math.floor(1000 + Math.random() * 9000));
}

function generateSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function hmacSign(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex').slice(0, 16);
}

function buildRrsigValue(coveredType, keyTag, secret, name, value, ttl) {
  const signature = hmacSign(secret, `${name}${coveredType}${value}${ttl}`);
  return `${coveredType}/${keyTag}/${signature}`;
}

function verifyRrsig(secret, name, type, value, ttl, signaturePart) {
  const expected = hmacSign(secret, `${name}${type}${value}${ttl}`);
  return expected === signaturePart;
}

function getZoneDnssec(zoneId) {
  return queryOne('SELECT * FROM zone_dnssec WHERE zone_id = ?', [zoneId]);
}

function getDnssecStatus(zoneId) {
  const dnssec = getZoneDnssec(zoneId);
  if (!dnssec || !dnssec.enabled) {
    return { enabled: false };
  }
  return {
    enabled: true,
    keyTag: dnssec.key_tag,
    algorithm: dnssec.algorithm,
    enabledAt: dnssec.enabled_at,
  };
}

function enableDnssec(zoneId) {
  const now = Date.now();
  const keyTag = generateKeyTag();
  const algorithm = 'HMAC-SHA256';
  const secret = generateSecret();

  beginTransaction();
  try {
    const existing = getZoneDnssec(zoneId);
    if (existing) {
      run(
        'UPDATE zone_dnssec SET enabled = 1, key_tag = ?, algorithm = ?, secret = ?, enabled_at = ? WHERE zone_id = ?',
        [keyTag, algorithm, secret, now, zoneId]
      );
    } else {
      run(
        'INSERT INTO zone_dnssec (zone_id, enabled, key_tag, algorithm, secret, enabled_at) VALUES (?, 1, ?, ?, ?, ?)',
        [zoneId, keyTag, algorithm, secret, now]
      );
    }

    const records = queryAll(
      "SELECT id, name, type, value, ttl FROM records WHERE zone_id = ? AND type != 'RRSIG'",
      [zoneId]
    );

    for (const rec of records) {
      const rrsigValue = buildRrsigValue(rec.type, keyTag, secret, rec.name, rec.value, rec.ttl);
      const rrsigId = uuidv4();
      run(
        'INSERT INTO records (id, zone_id, name, type, value, ttl, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [rrsigId, zoneId, rec.name, 'RRSIG', rrsigValue, rec.ttl, now]
      );
    }

    commitTransaction();
  } catch (err) {
    rollbackTransaction();
    throw err;
  }

  saveDatabase();
  return {
    enabled: true,
    keyTag,
    algorithm,
    enabledAt: now,
  };
}

function disableDnssec(zoneId) {
  beginTransaction();
  try {
    run('DELETE FROM zone_dnssec WHERE zone_id = ?', [zoneId]);
    run("DELETE FROM records WHERE zone_id = ? AND type = 'RRSIG'", [zoneId]);
    commitTransaction();
  } catch (err) {
    rollbackTransaction();
    throw err;
  }
  saveDatabase();
  return true;
}

function getTrustAnchor() {
  return queryOne('SELECT key_tag, set_at FROM trust_anchor WHERE id = 1');
}

function setTrustAnchor(keyTag) {
  const now = Date.now();
  const existing = queryOne('SELECT id FROM trust_anchor WHERE id = 1');
  if (existing) {
    run('UPDATE trust_anchor SET key_tag = ?, set_at = ? WHERE id = 1', [keyTag, now]);
  } else {
    run('INSERT INTO trust_anchor (id, key_tag, set_at) VALUES (1, ?, ?)', [keyTag, now]);
  }
  saveDatabase();
  return { keyTag, setAt: now };
}

function generateRrsigForRecord(zoneId, record, dnssec) {
  if (!dnssec || !dnssec.enabled) return;
  const rrsigValue = buildRrsigValue(
    record.type,
    dnssec.key_tag,
    dnssec.secret,
    record.name,
    record.value,
    record.ttl
  );
  const rrsigId = uuidv4();
  const now = Date.now();
  run(
    'INSERT INTO records (id, zone_id, name, type, value, ttl, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [rrsigId, zoneId, record.name, 'RRSIG', rrsigValue, record.ttl, now]
  );
}

function removeRrsigForRecord(zoneId, name, type) {
  const sigPrefix = `${type}/`;
  const rrsigs = queryAll(
    "SELECT id FROM records WHERE zone_id = ? AND type = 'RRSIG' AND name = ? AND value LIKE ?",
    [zoneId, name, `${sigPrefix}%`]
  );
  for (const r of rrsigs) {
    run('DELETE FROM records WHERE id = ?', [r.id]);
  }
}

function regenerateRrsigForRecord(zoneId, oldName, oldType, newRecord, dnssec) {
  removeRrsigForRecord(zoneId, oldName, oldType);
  if (dnssec && dnssec.enabled) {
    generateRrsigForRecord(zoneId, newRecord, dnssec);
  }
}

function findRrsigForRecord(zoneId, name, type) {
  const sigPrefix = `${type}/`;
  return queryAll(
    "SELECT id, name, type, value, ttl FROM records WHERE zone_id = ? AND type = 'RRSIG' AND name = ? AND value LIKE ?",
    [zoneId, name, `${sigPrefix}%`]
  );
}

function findDsRecords(parentZoneId, childZoneName) {
  return queryAll(
    "SELECT id, name, type, value, ttl FROM records WHERE zone_id = ? AND type = 'DS' AND name = ?",
    [parentZoneId, childZoneName]
  );
}

function createAlert(type, severity, data) {
  const id = uuidv4();
  const now = Date.now();
  run(
    'INSERT INTO analysis_alerts (id, type, severity, status, data, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    [id, type, severity, 'active', JSON.stringify(data), now]
  );
  saveDatabase();
  return getAlertById(id);
}

function getAlertById(id) {
  const row = queryOne('SELECT * FROM analysis_alerts WHERE id = ?', [id]);
  if (!row) return null;
  return {
    id: row.id,
    type: row.type,
    severity: row.severity,
    status: row.status,
    data: JSON.parse(row.data),
    createdAt: row.created_at,
    dismissedAt: row.dismissed_at,
  };
}

function listAlerts(filters = {}) {
  let sql = 'SELECT * FROM analysis_alerts WHERE 1=1';
  const params = [];

  if (filters.type) {
    sql += ' AND type = ?';
    params.push(filters.type);
  }
  if (filters.severity) {
    sql += ' AND severity = ?';
    params.push(filters.severity);
  }
  if (filters.status) {
    sql += ' AND status = ?';
    params.push(filters.status);
  }
  if (filters.fromTime) {
    sql += ' AND created_at >= ?';
    params.push(filters.fromTime);
  }
  if (filters.toTime) {
    sql += ' AND created_at <= ?';
    params.push(filters.toTime);
  }

  sql += ' ORDER BY created_at DESC';

  const rows = queryAll(sql, params);
  return rows.map((row) => ({
    id: row.id,
    type: row.type,
    severity: row.severity,
    status: row.status,
    data: JSON.parse(row.data),
    createdAt: row.created_at,
    dismissedAt: row.dismissed_at,
  }));
}

function dismissAlert(id) {
  const now = Date.now();
  run(
    "UPDATE analysis_alerts SET status = 'dismissed', dismissed_at = ? WHERE id = ?",
    [now, id]
  );
  saveDatabase();
  return getAlertById(id);
}

function getAlertSummary() {
  const activeByType = queryAll(
    "SELECT type, COUNT(*) as cnt FROM analysis_alerts WHERE status = 'active' GROUP BY type"
  );
  const activeBySeverity = queryAll(
    "SELECT severity, COUNT(*) as cnt FROM analysis_alerts WHERE status = 'active' GROUP BY severity"
  );
  const last24h = Date.now() - 24 * 60 * 60 * 1000;
  const newLast24h = queryOne(
    'SELECT COUNT(*) as cnt FROM analysis_alerts WHERE created_at >= ?',
    [last24h]
  );

  const hourAgo = Date.now() - 24 * 60 * 60 * 1000;
  const allRecent = queryAll(
    'SELECT created_at FROM analysis_alerts WHERE created_at >= ? ORDER BY created_at',
    [hourAgo]
  );

  const trend = {};
  for (let i = 23; i >= 0; i--) {
    const bucketStart = Date.now() - i * 60 * 60 * 1000;
    const bucketEnd = bucketStart + 60 * 60 * 1000;
    const hourKey = new Date(bucketStart).toISOString().slice(0, 13) + ':00:00';
    trend[hourKey] = allRecent.filter(
      (r) => r.created_at >= bucketStart && r.created_at < bucketEnd
    ).length;
  }

  return {
    activeByType: Object.fromEntries(activeByType.map((r) => [r.type, r.cnt])),
    activeBySeverity: Object.fromEntries(activeBySeverity.map((r) => [r.severity, r.cnt])),
    newLast24h: newLast24h ? newLast24h.cnt : 0,
    trend,
  };
}

function getThresholds() {
  const row = queryOne('SELECT * FROM analysis_thresholds WHERE id = 1');
  if (!row) return null;
  return {
    amplificationCount: row.amplification_count,
    amplificationResponseSize: row.amplification_response_size,
    probeNxdomainRatio: row.probe_nxdomain_ratio,
    probeSubdomainCount: row.probe_subdomain_count,
    tunnelLabelLength: row.tunnel_label_length,
    tunnelEntropy: row.tunnel_entropy,
  };
}

function updateThresholds(updates) {
  const current = getThresholds() || {};
  const fields = [];
  const params = [];

  if (updates.amplificationCount !== undefined) {
    fields.push('amplification_count = ?');
    params.push(updates.amplificationCount);
  }
  if (updates.amplificationResponseSize !== undefined) {
    fields.push('amplification_response_size = ?');
    params.push(updates.amplificationResponseSize);
  }
  if (updates.probeNxdomainRatio !== undefined) {
    fields.push('probe_nxdomain_ratio = ?');
    params.push(updates.probeNxdomainRatio);
  }
  if (updates.probeSubdomainCount !== undefined) {
    fields.push('probe_subdomain_count = ?');
    params.push(updates.probeSubdomainCount);
  }
  if (updates.tunnelLabelLength !== undefined) {
    fields.push('tunnel_label_length = ?');
    params.push(updates.tunnelLabelLength);
  }
  if (updates.tunnelEntropy !== undefined) {
    fields.push('tunnel_entropy = ?');
    params.push(updates.tunnelEntropy);
  }

  if (fields.length > 0) {
    params.push(1);
    run(`UPDATE analysis_thresholds SET ${fields.join(', ')} WHERE id = ?`, params);
    saveDatabase();
  }

  return getThresholds();
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
  getDnssecStatus,
  enableDnssec,
  disableDnssec,
  getTrustAnchor,
  setTrustAnchor,
  getZoneDnssec,
  verifyRrsig,
  findRrsigForRecord,
  findDsRecords,
  buildRrsigValue,
  hmacSign,
  createAlert,
  getAlertById,
  listAlerts,
  dismissAlert,
  getAlertSummary,
  getThresholds,
  updateThresholds,
  addBlocklistEntry,
  getBlocklistEntryById,
  listBlocklistEntries,
  deleteBlocklistEntry,
  addAllowlistEntry,
  getAllowlistEntryById,
  listAllowlistEntries,
  deleteAllowlistEntry,
  addRatelimitRule,
  getRatelimitRuleById,
  listRatelimitRules,
  updateRatelimitRule,
  deleteRatelimitRule,
  saveScript,
  getSavedScriptById,
  getSavedScriptByName,
  listSavedScripts,
  deleteSavedScript,
  recordExecution,
  getExecutionById,
  listExecutions,
};
