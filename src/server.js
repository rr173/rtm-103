const express = require('express');
const path = require('path');
const fs = require('fs');

const db = require('./db/database');
const { CacheManager } = require('./cache/cacheManager');
const { StatsLogger } = require('./stats/statsLogger');
const { RecursiveResolver } = require('./resolver/recursiveResolver');
const { seedDemoData } = require('./seed/demoData');

const zonesRouter = require('./routes/zones');
const createResolveRouter = require('./routes/resolve');
const createCacheRouter = require('./routes/cache');
const createStatsRouter = require('./routes/stats');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const PORT = process.env.PORT || 3000;

async function bootstrap() {
  await db.initDatabase();

  const cacheManager = new CacheManager();
  const statsLogger = new StatsLogger();
  const resolver = new RecursiveResolver(cacheManager, statsLogger);

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
  app.use('/api', createResolveRouter(resolver));
  app.use('/api', createCacheRouter(cacheManager));
  app.use('/api', createStatsRouter(statsLogger));

  app.use((err, _req, res, _next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error', message: err.message });
  });

  seedDemoData();

  app.listen(PORT, () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║   DNS Recursive Resolver Simulator                             ║');
    console.log('╠════════════════════════════════════════════════════════════════╣');
    console.log(`║   Server running on http://localhost:${PORT}                     ║`);
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
    console.log('║   DNSSEC:                                                       ║');
    console.log('║   POST   /api/zones/:zoneId/dnssec/enable                       ║');
    console.log('║   GET    /api/zones/:zoneId/dnssec                              ║');
    console.log('║   DELETE /api/zones/:zoneId/dnssec/disable                      ║');
    console.log('║   POST   /api/dnssec/trust-anchor                               ║');
    console.log('║   GET    /api/dnssec/trust-anchor                               ║');
    console.log('║   POST   /api/resolve  { ..., dnssec: true }                    ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
  });
}

bootstrap().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
