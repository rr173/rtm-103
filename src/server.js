const express = require('express');
const path = require('path');
const fs = require('fs');

const db = require('./db/database');
const { CacheManager } = require('./cache/cacheManager');
const { StatsLogger } = require('./stats/statsLogger');
const { RecursiveResolver } = require('./resolver/recursiveResolver');
const { seedDemoData } = require('./seed/demoData');
const { AnalysisDetector } = require('./analysis/detector');
const { EnforcementManager } = require('./enforcement/enforcementManager');
const { DnsUdpServer } = require('./dns/dnsServer');

const zonesRouter = require('./routes/zones');
const createResolveRouter = require('./routes/resolve');
const createCacheRouter = require('./routes/cache');
const createStatsRouter = require('./routes/stats');
const createAnalysisRouter = require('./routes/analysis');
const createEnforcementRouter = require('./routes/enforcement');
const createProtocolRouter = require('./routes/protocol');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const PORT = process.env.PORT || 3000;

function randomString(len) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < len; i++) {
    s += chars[Math.floor(Math.random() * chars.length)];
  }
  return s;
}

function seedAnalysisData(detector) {
  console.log('[Seed] Injecting analysis test data...');
  const now = Date.now();

  const normalDomains = [
    'www.example.com', 'example.com', 'mail.example.com', 'api.example.com',
    'www.mysite.com', 'cdn.provider.net', 'ns1.example.com', 'ns2.example.com',
  ];
  for (let i = 0; i < 10; i++) {
    const d = normalDomains[i % normalDomains.length];
    detector.extendedLogs.unshift({
      timestamp: now - Math.floor(Math.random() * 60000),
      name: d,
      type: 'A',
      resultCode: 'SUCCESS',
      hops: 2 + Math.floor(Math.random() * 3),
      answerSize: 1 + Math.floor(Math.random() * 2),
      cached: Math.random() > 0.5,
      elapsedMs: 5 + Math.floor(Math.random() * 20),
    });
  }

  const ampDomain = 'amp-target.example.com';
  for (let i = 0; i < 25; i++) {
    detector.extendedLogs.unshift({
      timestamp: now - Math.floor(Math.random() * 60000),
      name: ampDomain,
      type: 'TXT',
      resultCode: 'SUCCESS',
      hops: 3,
      answerSize: 5 + Math.floor(Math.random() * 5),
      cached: false,
      elapsedMs: 10 + Math.floor(Math.random() * 30),
    });
  }

  for (let i = 0; i < 30; i++) {
    const randomSub = randomString(8) + '.probe-target.com';
    detector.extendedLogs.unshift({
      timestamp: now - Math.floor(Math.random() * 60000),
      name: randomSub,
      type: 'A',
      resultCode: 'NXDOMAIN',
      hops: 2,
      answerSize: 0,
      cached: false,
      elapsedMs: 8 + Math.floor(Math.random() * 15),
    });
  }

  const tunnelPayloads = [
    'VGhpcyBpcyBhIHRlc3Qgb2YgRE5TIHR1bm5lbGluZw0K.dnstunnel.example.com',
    randomString(40) + '.data.exfil.com',
    'aGVsbG8gd29ybGQgdGhpcyBpcyBhIGRhdGEgcGF5bG9hZQ.tunnel.malware.io',
    randomString(35) + '.c2.evil.net',
    randomString(38) + '.covert-channel.org',
  ];
  for (let i = 0; i < 5; i++) {
    detector.extendedLogs.unshift({
      timestamp: now - Math.floor(Math.random() * 60000),
      name: tunnelPayloads[i],
      type: 'TXT',
      resultCode: 'NXDOMAIN',
      hops: 1,
      answerSize: 0,
      cached: false,
      elapsedMs: 5 + Math.floor(Math.random() * 10),
    });
  }

  console.log('[Seed] Analysis test data injected: 10 normal + 25 amplification + 30 probe NXDOMAIN + 5 tunnel');
}

function seedEnforcementData() {
  console.log('[Seed] Injecting enforcement default rules...');

  const existingBlocklist = db.listBlocklistEntries(true);
  const blocklistPatterns = new Set(existingBlocklist.map((e) => e.pattern));

  if (!blocklistPatterns.has('*.evil.com')) {
    db.addBlocklistEntry('*.evil.com', 'Known malicious domain pattern', 0);
  }
  if (!blocklistPatterns.has('amp-target.example.com')) {
    db.addBlocklistEntry(
      'amp-target.example.com',
      'Amplification attack target',
      60
    );
  }

  const existingAllowlist = db.listAllowlistEntries();
  const allowlistPatterns = new Set(existingAllowlist.map((e) => e.pattern));
  if (!allowlistPatterns.has('www.example.com')) {
    db.addAllowlistEntry('www.example.com');
  }

  const existingRatelimit = db.listRatelimitRules();
  const ratelimitPatterns = new Set(existingRatelimit.map((r) => r.pattern));
  if (!ratelimitPatterns.has('*.example.com')) {
    db.addRatelimitRule('*.example.com', 30, 60);
  }

  console.log('[Seed] Enforcement defaults injected.');
}

async function bootstrap() {
  await db.initDatabase();

  const cacheManager = new CacheManager();
  const statsLogger = new StatsLogger();
  const resolver = new RecursiveResolver(cacheManager, statsLogger);
  const detector = new AnalysisDetector(statsLogger);
  const enforcementManager = new EnforcementManager();
  const dnsServer = new DnsUdpServer(resolver, enforcementManager);

  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.use((req, _res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
  });

  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'dns-recursive-resolver-simulator',
      timestamp: Date.now(),
    });
  });

  app.use('/api', zonesRouter);
  app.use('/api', createResolveRouter(resolver, detector, enforcementManager));
  app.use('/api', createCacheRouter(cacheManager));
  app.use('/api', createStatsRouter(statsLogger));
  app.use('/api', createAnalysisRouter(detector));
  app.use('/api', createEnforcementRouter(enforcementManager));
  app.use('/api', createProtocolRouter(dnsServer));

  app.use((err, _req, res, _next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error', message: err.message });
  });

  seedDemoData();
  seedAnalysisData(detector);
  seedEnforcementData();

  await dnsServer.start();

  app.listen(PORT, () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║   DNS Recursive Resolver Simulator                             ║');
    console.log('╠════════════════════════════════════════════════════════════════╣');
    console.log(`║   Server running on http://localhost:${PORT}                     ║`);
    console.log(`║   DNS UDP listening on port ${dnsServer.port}                                 ║`);
    console.log('╠════════════════════════════════════════════════════════════════╣');
    console.log('║   API Endpoints:                                                ║');
    console.log('║   GET    /api/health                                            ║');
    console.log('║   GET    /api/zones                                             ║');
    console.log('║   POST   /api/zones                                             ║');
    console.log('║   GET    /api/zones/:zoneId                                     ║');
    console.log('║   GET    /api/zones/:zoneId/soa                                 ║');
    console.log('║   GET    /api/zones/:zoneId/changelog                           ║');
    console.log('║   GET    /api/zones/:zoneId/records                             ║');
    console.log('║   POST   /api/zones/:zoneId/records                             ║');
    console.log('║   PUT    /api/zones/:zoneId/records/:recordId                   ║');
    console.log('║   DELETE /api/zones/:zoneId/records/:recordId                   ║');
    console.log('║   GET    /api/zones/:zoneId/transfer/full                       ║');
    console.log('║   GET    /api/zones/:zoneId/transfer/incremental                ║');
    console.log('║   POST   /api/zones/:zoneId/sync                                ║');
    console.log('║   GET    /api/zones/:zoneId/sync/status                         ║');
    console.log('║   POST   /api/resolve                                           ║');
    console.log('║   GET    /api/cache                                             ║');
    console.log('║   DELETE /api/cache                                             ║');
    console.log('║   DELETE /api/cache/:name                                       ║');
    console.log('║   GET    /api/stats                                             ║');
    console.log('║   GET    /api/logs?limit=50                                     ║');
    console.log('║   Analysis:                                                     ║');
    console.log('║   POST   /api/analysis/scan                                     ║');
    console.log('║   GET    /api/analysis/stats?windowMinutes=5                    ║');
    console.log('║   GET    /api/analysis/alerts                                   ║');
    console.log('║   GET    /api/analysis/alerts/summary                           ║');
    console.log('║   GET    /api/analysis/alerts/:id                               ║');
    console.log('║   PUT    /api/analysis/alerts/:id/dismiss                       ║');
    console.log('║   GET    /api/analysis/thresholds                               ║');
    console.log('║   PUT    /api/analysis/thresholds                               ║');
    console.log('║   DNSSEC:                                                       ║');
    console.log('║   POST   /api/zones/:zoneId/dnssec/enable                       ║');
    console.log('║   GET    /api/zones/:zoneId/dnssec                              ║');
    console.log('║   DELETE /api/zones/:zoneId/dnssec/disable                      ║');
    console.log('║   POST   /api/dnssec/trust-anchor                               ║');
    console.log('║   GET    /api/dnssec/trust-anchor                               ║');
    console.log('║   POST   /api/resolve  { ..., dnssec: true }                    ║');
    console.log('║   Enforcement:                                                  ║');
    console.log('║   POST   /api/blocklist                                         ║');
    console.log('║   GET    /api/blocklist                                         ║');
    console.log('║   DELETE /api/blocklist/:id                                     ║');
    console.log('║   POST   /api/allowlist                                         ║');
    console.log('║   GET    /api/allowlist                                         ║');
    console.log('║   DELETE /api/allowlist/:id                                     ║');
    console.log('║   POST   /api/ratelimit                                         ║');
    console.log('║   GET    /api/ratelimit                                         ║');
    console.log('║   PUT    /api/ratelimit/:id                                     ║');
    console.log('║   DELETE /api/ratelimit/:id                                     ║');
    console.log('║   POST   /api/analysis/alerts/:id/block                         ║');
    console.log('║   POST   /api/analysis/alerts/:id/ratelimit                     ║');
    console.log('║   GET    /api/enforcement/stats                                 ║');
    console.log('║   DNS Protocol:                                                 ║');
    console.log('║   GET    /api/protocol/stats                                    ║');
    console.log('║   POST   /api/protocol/config  { port }                         ║');
    console.log('║   dig @127.0.0.1 -p 5353 www.example.com A                      ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
  });
}

bootstrap().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
