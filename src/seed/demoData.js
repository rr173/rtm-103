const db = require('../db/database');

function seedDemoData() {
  const existingRoot = db.getZoneByName('.');
  let rootZone;

  if (existingRoot) {
    console.log('[Seed] Demo data already exists, skipping zone creation.');
    rootZone = existingRoot;
  } else {
    console.log('[Seed] Initializing demo DNS namespace...');

    rootZone = db.createZone('.', null, [
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
      'CNAME',
      'smtp.example.com',
      3600
    );
    db.addRecord(
      exampleZone.id,
      'smtp.example.com',
      'A',
      '93.184.216.35',
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

    db.addRecord(
      exampleZone.id,
      'internal.example.com',
      'A',
      '10.0.0.1',
      3600
    );
    db.addRecord(
      exampleZone.id,
      'app.internal.example.com',
      'A',
      '10.0.0.10',
      3600
    );
    db.addRecord(
      exampleZone.id,
      'db.internal.example.com',
      'A',
      '10.0.0.20',
      3600
    );
    db.addRecord(
      exampleZone.id,
      'fallback.example.com',
      'A',
      '203.0.113.100',
      3600
    );
    db.addRecord(
      exampleZone.id,
      'evil-redirect.example.com',
      'A',
      '192.0.2.100',
      3600
    );
    db.addRecord(
      exampleZone.id,
      'evil-redirect.example.com',
      'CNAME',
      'malware.evil.com',
      3600
    );
    db.addRecord(
      exampleZone.id,
      'private-resource.example.com',
      'A',
      '10.1.0.50',
      3600
    );
    db.addRecord(
      exampleZone.id,
      'internal-api.example.com',
      'A',
      '10.2.0.100',
      3600
    );
  }

  console.log('[Seed] Applying demo record changes to populate changelog...');

  const rootRecords = db.getRecordsByZone(rootZone.id);
  const firstNsRecord = rootRecords.find((r) => r.type === 'NS');
  if (firstNsRecord) {
    db.updateRecord(rootZone.id, firstNsRecord.id, { ttl: firstNsRecord.ttl + 1 });
  }

  db.addRecord(rootZone.id, 'demo', 'TXT', 'demo-changelog-entry', 3600);
  const demoRecords = db.getRecordsByZone(rootZone.id).filter(
    (r) => r.name === 'demo' && r.type === 'TXT' && r.value === 'demo-changelog-entry'
  );
  if (demoRecords.length > 0) {
    db.deleteRecord(rootZone.id, demoRecords[0].id);
  }

  const comZone = db.getZoneByName('com');
  if (comZone) {
    db.addRecord(comZone.id, 'status.com', 'TXT', 'seeded', 3600);
    const statusRecords = db.getRecordsByZone(comZone.id).filter(
      (r) => r.name === 'status.com' && r.type === 'TXT'
    );
    if (statusRecords.length > 0) {
      db.updateRecord(comZone.id, statusRecords[0].id, { value: 'seeded-and-updated' });
    }
  }

  const finalRoot = db.getZoneById(rootZone.id);
  console.log(`[Seed] Demo changelog populated. Root zone serial: ${finalRoot ? finalRoot.serial : 'N/A'}`);

  console.log('[Seed] Demo data initialized successfully.');
  console.log('[Seed] Zones: ., com, net, org, example.com, mysite.com, provider.net');

  setupDnssecChain();

  console.log('[Seed] Test queries:');
  console.log('  POST /api/resolve { "name": "www.example.com", "type": "A" }');
  console.log('  POST /api/resolve { "name": "cdn.example.com", "type": "A" }');
  console.log('  POST /api/resolve { "name": "mail.example.com", "type": "A" }');
  console.log('[Seed] DNSSEC test queries:');
  console.log('  POST /api/resolve { "name": "www.example.com", "type": "A", "dnssec": true }');
  console.log('[Seed] Sync tests:');
  console.log('  GET  /api/zones/:zoneId/soa');
  console.log('  GET  /api/zones/:zoneId/changelog');
  console.log('  GET  /api/zones/:zoneId/transfer/full');
  console.log('  GET  /api/zones/:zoneId/transfer/incremental?fromSerial=N');
  console.log('  POST /api/zones/:zoneId/sync');
}

function setupDnssecChain() {
  const rootZone = db.getZoneByName('.');
  const comZone = db.getZoneByName('com');
  const exampleZone = db.getZoneByName('example.com');

  if (!rootZone || !comZone || !exampleZone) {
    console.log('[Seed-DNSSEC] Required zones not found, skipping DNSSEC setup.');
    return;
  }

  const rootDnssec = db.getDnssecStatus(rootZone.id);
  if (!rootDnssec.enabled) {
    console.log('[Seed-DNSSEC] Enabling DNSSEC for root zone...');
    db.enableDnssec(rootZone.id);
  }

  const comDnssec = db.getDnssecStatus(comZone.id);
  if (!comDnssec.enabled) {
    console.log('[Seed-DNSSEC] Enabling DNSSEC for com zone...');
    db.enableDnssec(comZone.id);
  }

  const exampleDnssec = db.getDnssecStatus(exampleZone.id);
  if (!exampleDnssec.enabled) {
    console.log('[Seed-DNSSEC] Enabling DNSSEC for example.com zone...');
    db.enableDnssec(exampleZone.id);
  }

  const rootStatus = db.getDnssecStatus(rootZone.id);
  const comStatus = db.getDnssecStatus(comZone.id);
  const exampleStatus = db.getDnssecStatus(exampleZone.id);

  const trustAnchor = db.getTrustAnchor();
  if (!trustAnchor || trustAnchor.key_tag !== rootStatus.keyTag) {
    console.log('[Seed-DNSSEC] Setting trust anchor for root zone...');
    db.setTrustAnchor(rootStatus.keyTag);
  }

  const existingRootDsForCom = db.findDsRecords(rootZone.id, 'com');
  if (!existingRootDsForCom.some((ds) => ds.value === comStatus.keyTag)) {
    console.log('[Seed-DNSSEC] Adding DS record for com in root zone...');
    db.addRecord(rootZone.id, 'com', 'DS', comStatus.keyTag, 86400);
  }

  const existingComDsForExample = db.findDsRecords(comZone.id, 'example.com');
  if (!existingComDsForExample.some((ds) => ds.value === exampleStatus.keyTag)) {
    console.log('[Seed-DNSSEC] Adding DS record for example.com in com zone...');
    db.addRecord(comZone.id, 'example.com', 'DS', exampleStatus.keyTag, 86400);
  }

  console.log('[Seed-DNSSEC] DNSSEC chain setup complete:');
  console.log(`  Root (.): keyTag=${rootStatus.keyTag}`);
  console.log(`  com:      keyTag=${comStatus.keyTag}`);
  console.log(`  example.com: keyTag=${exampleStatus.keyTag}`);
  console.log(`  Trust anchor set to root keyTag.`);
}

module.exports = { seedDemoData };
