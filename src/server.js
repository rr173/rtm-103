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
const { DnsServer } = require('./dns/dnsServer');
const { ScriptSandbox } = require('./sandbox/scriptSandbox');
const { PolicyEngine } = require('./policy/policyEngine');

const zonesRouter = require('./routes/zones');
const createResolveRouter = require('./routes/resolve');
const createCacheRouter = require('./routes/cache');
const createStatsRouter = require('./routes/stats');
const createAnalysisRouter = require('./routes/analysis');
const createEnforcementRouter = require('./routes/enforcement');
const createProtocolRouter = require('./routes/protocol');
const createSandboxRouter = require('./routes/sandbox');
const createPoliciesRouter = require('./routes/policies');

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

function seedPolicyData() {
  console.log('[Seed] Injecting policy demo rules...');

  const existingPolicies = db.listPolicies();
  const policyNames = new Set(existingPolicies.map((p) => p.name));

  if (!policyNames.has('non-work-hours-internal-rewrite')) {
    db.addPolicy({
      name: 'non-work-hours-internal-rewrite',
      description: '非工作时间将*.internal.example.com解析到公网IP',
      priority: 10,
      enabled: true,
      domainPattern: '*.internal.example.com',
      recordType: 'A',
      timeWindow: '* 0-8,19-23 *',
      responseRegex: null,
      action: 'rewrite',
      actionParams: { template: '203.0.113.50' },
    });
  }

  if (!policyNames.has('redirect-10-0-0-8-to-fallback')) {
    db.addPolicy({
      name: 'redirect-10-0-0-8-to-fallback',
      description: '将指向10.0.0.0/8网段的A记录重定向到fallback.example.com',
      priority: 20,
      enabled: true,
      domainPattern: null,
      recordType: 'A',
      timeWindow: null,
      responseRegex: '^10\\.',
      action: 'redirect',
      actionParams: { targetDomain: 'fallback.example.com' },
    });
  }

  if (!policyNames.has('nxdomain-evil-redirect')) {
    db.addPolicy({
      name: 'nxdomain-evil-redirect',
      description: '强制evil-redirect.example.com返回NXDOMAIN',
      priority: 30,
      enabled: true,
      domainPattern: 'evil-redirect.example.com',
      recordType: null,
      timeWindow: null,
      responseRegex: null,
      action: 'nxdomain',
      actionParams: null,
    });
  }

  console.log('[Seed] Policy demo rules injected.');
  console.log('[Seed] Policy demo test queries:');
  console.log('  POST /api/resolve { "name": "app.internal.example.com", "type": "A" }');
  console.log('    -> 工作时间返回10.0.0.10, 非工作时间返回203.0.113.50');
  console.log('  POST /api/resolve { "name": "private-resource.example.com", "type": "A" }');
  console.log('    -> 包含10.x.x.x地址,被redirect到fallback.example.com(203.0.113.100)');
  console.log('  POST /api/resolve { "name": "evil-redirect.example.com", "type": "A" }');
  console.log('    -> 强制返回NXDOMAIN');
}

function seedSandboxData() {
  console.log('[Seed] Injecting sandbox demo scripts...');

  const demoScript = `// DNS 批量域名解析批量查询演示
// 这个脚本演示了如何批量查询多个域名并格式化结果

const domains = [
  { name: 'www.example.com', type: 'A' },
  { name: 'example.com', type: 'NS' },
  { name: 'example.com', type: 'MX' },
  { name: 'mail.example.com', type: 'A' },
  { name: 'api.example.com', type: 'A' },
];

console.log('开始批量 DNS 查询...');

const results = await dns.resolveBatch(domains);

const summary = results.map((r) => ({
  name: r.query.name,
  type: r.query.type,
  status: r.result ? r.result.status : 'ERROR',
  answers: r.result ? r.result.answer.length : 0,
  elapsedMs: r.result ? r.result.elapsedMs : 0,
}));

console.log('查询完成!');

return {
  total: results.length,
  summary,
  raw: results,
};
`;

  const nxdomainTest = `// NXDOMAIN 检测脚本
// 测试一些不存在的域名验证返回 NXDOMAIN

const testDomains = [
  'nonexistent.example.com',
  'ghost.mysite.com',
  'random-xyz-123.invalid',
];

console.log('测试 NXDOMAIN 检测...');

const results = await dns.resolveBatch(testDomains);

const nxdomainCount = results.filter((r) => r.result && r.result.status === 'NXDOMAIN').length;

console.log(\`测试完成: \${nxdomainCount}/\${results.length} 个域名返回 NXDOMAIN\`);

return {
  total: results.length,
  nxdomainCount,
  details: results.map((r) => ({
    name: typeof r.query === 'string' ? r.query : (r.query.name || r.query),
    status: r.result ? r.result.status : 'ERROR',
  })),
};
`;

  const dnstypeExplorer = `// 多记录类型探索
// 对同一域名查询不同记录类型

const target = 'example.com';
const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA'];

console.log(\`探索 \${target} 的各类记录查询\`);

const queries = types.map((t) => ({ name: target, type: t }));
const results = await dns.resolveBatch(queries);

const found = results.filter((r) => r.result && r.result.status === 'SUCCESS' && r.result.answer.length > 0);

console.log(\`找到 \${found.length}/\${types.length} 种记录类型\`);

return {
  target,
  found: found.map((f) => ({
    type: f.query.type,
    answers: f.result.answer,
  })),
  all: results,
};
`;

  const existing = db.listSavedScripts();
  const existingNames = new Set(existing.map((s) => s.name));

  if (!existingNames.has('demo-batch-query')) {
    db.saveScript(
      'demo-batch-query',
      demoScript,
      '批量域名解析演示：查询多个域名并展示结果汇总'
    );
  }
  if (!existingNames.has('demo-nxdomain-test')) {
    db.saveScript(
      'demo-nxdomain-test',
      nxdomainTest,
      'NXDOMAIN 检测：验证不存在域名的返回结果'
    );
  }
  if (!existingNames.has('demo-type-explorer')) {
    db.saveScript(
      'demo-type-explorer',
      dnstypeExplorer,
      '多记录类型探索：查询同一域名的不同 DNS 记录类型'
    );
  }

  console.log('[Seed] Sandbox demo scripts injected.');
}

async function bootstrap() {
  await db.initDatabase();

  const cacheManager = new CacheManager();
  const statsLogger = new StatsLogger();
  const resolver = new RecursiveResolver(cacheManager, statsLogger);
  const detector = new AnalysisDetector(statsLogger);
  const enforcementManager = new EnforcementManager();
  const policyEngine = new PolicyEngine(resolver);
  const dnsServer = new DnsServer(resolver, enforcementManager, policyEngine);
  const sandbox = new ScriptSandbox(resolver, {
    timeoutMs: parseInt(process.env.SANDBOX_TIMEOUT_MS, 10) || 5000,
    maxConcurrent: parseInt(process.env.SANDBOX_MAX_CONCURRENT, 10) || 5,
  });

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
  app.use('/api', createResolveRouter(resolver, detector, enforcementManager, policyEngine));
  app.use('/api', createCacheRouter(cacheManager));
  app.use('/api', createStatsRouter(statsLogger));
  app.use('/api', createAnalysisRouter(detector));
  app.use('/api', createEnforcementRouter(enforcementManager));
  app.use('/api', createProtocolRouter(dnsServer));
  app.use('/api', createSandboxRouter(sandbox));
  app.use('/api', createPoliciesRouter(policyEngine));

  app.use((err, _req, res, _next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error', message: err.message });
  });

  seedDemoData();
  seedAnalysisData(detector);
  seedEnforcementData();
  seedSandboxData();
  seedPolicyData();

  await dnsServer.start();

  app.listen(PORT, () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║   DNS Recursive Resolver Simulator                             ║');
    console.log('╠════════════════════════════════════════════════════════════════╣');
    console.log(`║   Server running on http://localhost:${PORT}                     ║`);
    console.log(`║   DNS UDP/TCP listening on port ${dnsServer.port}                             ║`);
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
    console.log('║   dig @127.0.0.1 -p 5353 +tcp www.example.com A                 ║');
    console.log('╠════════════════════════════════════════════════════════════════╣');
    console.log('║   Script Sandbox:                                               ║');
    console.log('║   GET    /api/sandbox/stats                                     ║');
    console.log('║   POST   /api/sandbox/execute   { code, timeoutMs? }            ║');
    console.log('║   GET    /api/sandbox/scripts                                   ║');
    console.log('║   POST   /api/sandbox/scripts   { name, code, description? }    ║');
    console.log('║   GET    /api/sandbox/scripts/:id                               ║');
    console.log('║   DELETE /api/sandbox/scripts/:id                               ║');
    console.log('║   GET    /api/sandbox/executions?limit=50                       ║');
    console.log('║   GET    /api/sandbox/executions/:id                            ║');
    console.log('║   Sandbox available APIs: dns.resolve(), dns.resolveBatch()     ║');
    console.log('╠════════════════════════════════════════════════════════════════╣');
    console.log('║   Response Policies:                                             ║');
    console.log('║   POST   /api/policies                                          ║');
    console.log('║   GET    /api/policies                                          ║');
    console.log('║   GET    /api/policies/:id                                      ║');
    console.log('║   PUT    /api/policies/:id                                      ║');
    console.log('║   DELETE /api/policies/:id                                      ║');
    console.log('║   POST   /api/policies/reorder                                  ║');
    console.log('║   GET    /api/policies/logs?limit=50                            ║');
    console.log('║   GET    /api/policies/stats                                    ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
  });
}

bootstrap().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
