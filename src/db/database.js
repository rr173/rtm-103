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
  } else {
    db = new SQL.Database();
    initSchema();
    saveDatabase();
  }

  setInterval(saveDatabase, 5000);

  process.on('beforeExit', saveDatabase);
  process.on('SIGINT', () => {
    saveDatabase();
    process.exit();
  });
}

function initSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS zones (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      parent_id TEXT,
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
  db.run(`CREATE INDEX IF NOT EXISTS idx_records_zone ON records(zone_id);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_records_name_type ON records(name, type);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_zones_parent ON zones(parent_id);`);
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

function createZone(name, parentId, nsRecords) {
  const id = uuidv4();
  const now = Date.now();

  run(
    'INSERT INTO zones (id, name, parent_id, created_at) VALUES (?, ?, ?, ?)',
    [id, name, parentId, now]
  );

  if (nsRecords && nsRecords.length > 0) {
    nsRecords.forEach((ns) => {
      run(
        'INSERT INTO records (id, zone_id, name, type, value, ttl, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [uuidv4(), id, name, 'NS', ns.nameserver, ns.ttl || 3600, now]
      );
      if (ns.glueIp) {
        run(
          'INSERT INTO records (id, zone_id, name, type, value, ttl, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [uuidv4(), id, ns.nameserver, 'A', ns.glueIp, ns.ttl || 3600, now]
        );
      }
    });
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
  run('DELETE FROM records WHERE zone_id = ?', [id]);
  run('DELETE FROM zones WHERE id = ?', [id]);
  saveDatabase();
}

function addRecord(zoneId, name, type, value, ttl) {
  const id = uuidv4();
  const now = Date.now();
  run(
    'INSERT INTO records (id, zone_id, name, type, value, ttl, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, zoneId, name, type, value, ttl, now]
  );
  saveDatabase();
  return getRecordById(id);
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
  getRecordById,
  getRecordsByZone,
  findRecords,
  findDelegationNs,
  getParentZone,
  findBestMatchingZone,
};
