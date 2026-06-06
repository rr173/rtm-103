const db = require('../db/database');

function seedDemoData() {
  const existingRoot = db.getZoneByName('.');
  if (existingRoot) {
    console.log('[Seed] Demo data already exists, skipping.');
    return;
  }

  console.log('[Seed] Initializing demo DNS namespace...');

  const rootZone = db.createZone('.', null, [
    { nameserver: 'a.root-servers.net', glueIp: '198.41.0.4', ttl: 86400 },
    { nameserver: 'b.root-servers.net', glueIp: '199.9.14.201', ttl: 86400 },
  ]);

  const comZone = db.createZone('com', rootZone.id, [
    { nameserver: 'a.gtld-servers.net', glueIp: '192.5.6.30', ttl: 86400 },
    { nameserver: 'b.gtld-servers.net', glueIp: '192.33.14.30', ttl: 86400 },
  ]);

  const netZone = db.createZone('net', rootZone.id, [
    { nameserver: 'a.gtld-servers.net', glueIp: '192.5.6.30', ttl: 86400 },
    { nameserver: 'b.gtld-servers.net', glueIp: '192.33.14.30', ttl: 86400 },
  ]);

  const orgZone = db.createZone('org', rootZone.id, [
    { nameserver: 'a0.org.afilias-nst.info', glueIp: '199.19.56.1', ttl: 86400 },
    { nameserver: 'b0.org.afilias-nst.org', glueIp: '199.19.54.1', ttl: 86400 },
  ]);

  db.addRecord(
    rootZone.id,
    'com',
    'NS',
    'a.gtld-servers.net',
    86400
  );
  db.addRecord(
    rootZone.id,
    'com',
    'NS',
    'b.gtld-servers.net',
    86400
  );
  db.addRecord(
    rootZone.id,
    'net',
    'NS',
    'a.gtld-servers.net',
    86400
  );
  db.addRecord(
    rootZone.id,
    'net',
    'NS',
    'b.gtld-servers.net',
    86400
  );
  db.addRecord(
    rootZone.id,
    'org',
    'NS',
    'a0.org.afilias-nst.info',
    86400
  );
  db.addRecord(
    rootZone.id,
    'org',
    'NS',
    'b0.org.afilias-nst.org',
    86400
  );

  const exampleZone = db.createZone('example.com', comZone.id, [
    { nameserver: 'ns1.example.com', glueIp: '192.0.2.1', ttl: 86400 },
    { nameserver: 'ns2.example.com', glueIp: '192.0.2.2', ttl: 86400 },
  ]);

  db.addRecord(
    comZone.id,
    'example.com',
    'NS',
    'ns1.example.com',
    86400
  );
  db.addRecord(
    comZone.id,
    'example.com',
    'NS',
    'ns2.example.com',
    86400
  );

  const mysiteZone = db.createZone('mysite.com', comZone.id, [
    { nameserver: 'ns1.mysite.com', glueIp: '198.51.100.1', ttl: 86400 },
    { nameserver: 'ns2.mysite.com', glueIp: '198.51.100.2', ttl: 86400 },
  ]);

  db.addRecord(
    comZone.id,
    'mysite.com',
    'NS',
    'ns1.mysite.com',
    86400
  );
  db.addRecord(
    comZone.id,
    'mysite.com',
    'NS',
    'ns2.mysite.com',
    86400
  );

  const providerZone = db.createZone('provider.net', netZone.id, [
    { nameserver: 'ns1.provider.net', glueIp: '203.0.113.1', ttl: 86400 },
  ]);

  db.addRecord(
    netZone.id,
    'provider.net',
    'NS',
    'ns1.provider.net',
    86400
  );

  db.addRecord(
    exampleZone.id,
    'www.example.com',
    'A',
    '93.184.216.34',
    3600
  );
  db.addRecord(
    exampleZone.id,
    'example.com',
    'A',
    '93.184.216.34',
    3600
  );

  db.addRecord(
    exampleZone.id,
    'mail.example.com',
    'A',
    '93.184.216.35',
    3600
  );
  db.addRecord(
    exampleZone.id,
    'mail.example.com',
    'CNAME',
    'mail.example.com',
    3600
  );

  db.addRecord(
    exampleZone.id,
    'cdn.example.com',
    'CNAME',
    'cdn.provider.net',
    3600
  );

  db.addRecord(
    providerZone.id,
    'cdn.provider.net',
    'A',
    '203.0.113.10',
    3600
  );

  db.addRecord(
    exampleZone.id,
    'example.com',
    'MX',
    '10 mail.example.com',
    3600
  );

  db.addRecord(
    exampleZone.id,
    'example.com',
    'TXT',
    'v=spf1 include:_spf.example.com ~all',
    3600
  );

  db.addRecord(
    exampleZone.id,
    'api.example.com',
    'AAAA',
    '2606:2800:220:1:248:1893:25c8:1946',
    3600
  );

  db.addRecord(
    exampleZone.id,
    'ns1.example.com',
    'A',
    '192.0.2.1',
    86400
  );
  db.addRecord(
    exampleZone.id,
    'ns2.example.com',
    'A',
    '192.0.2.2',
    86400
  );

  db.addRecord(
    mysiteZone.id,
    'www.mysite.com',
    'A',
    '198.51.100.10',
    3600
  );

  db.addRecord(
    providerZone.id,
    'ns1.provider.net',
    'A',
    '203.0.113.1',
    86400
  );

  console.log('[Seed] Demo data initialized successfully.');
  console.log('[Seed] Zones: ., com, net, org, example.com, mysite.com, provider.net');
  console.log('[Seed] Test queries:');
  console.log('  POST /api/resolve { "name": "www.example.com", "type": "A" }');
  console.log('  POST /api/resolve { "name": "cdn.example.com", "type": "A" }');
  console.log('  POST /api/resolve { "name": "mail.example.com", "type": "A" }');
}

module.exports = { seedDemoData };
