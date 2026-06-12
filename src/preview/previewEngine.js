const db = require('../db/database');
const { CacheManager } = require('../cache/cacheManager');
const { StatsLogger } = require('../stats/statsLogger');
const { RecursiveResolver } = require('../resolver/recursiveResolver');
const { PolicyEngine, matchDomainPattern, matchTimeWindow, matchPolicy, executeRewrite, executeNxdomain } = require('../policy/policyEngine');
const { EnforcementManager } = require('../enforcement/enforcementManager');

function normalizeName(name) {
  let n = name.toLowerCase();
  if (n !== '.' && n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

function createPreviewDb(snapshot, draftChanges) {
  let zones = JSON.parse(JSON.stringify(snapshot.zones));
  let policies = JSON.parse(JSON.stringify(snapshot.policies));
  let blocklist = JSON.parse(JSON.stringify(snapshot.blocklist));
  let allowlist = JSON.parse(JSON.stringify(snapshot.allowlist));
  let ratelimit = JSON.parse(JSON.stringify(snapshot.ratelimit));

  for (const change of draftChanges) {
    switch (change.changeType) {
      case 'record_add': {
        const zone = zones.find((z) => z.id === change.zoneId);
        if (zone && change.newData) {
          zone.records.push({ ...change.newData, id: change.targetId || `preview-${Date.now()}` });
        }
        break;
      }
      case 'record_modify': {
        const zone = zones.find((z) => z.id === change.zoneId);
        if (zone && change.newData) {
          const idx = zone.records.findIndex((r) => r.id === change.targetId);
          if (idx >= 0) {
            zone.records[idx] = { ...zone.records[idx], ...change.newData };
          }
        }
        break;
      }
      case 'record_delete': {
        const zone = zones.find((z) => z.id === change.zoneId);
        if (zone) {
          zone.records = zone.records.filter((r) => r.id !== change.targetId);
        }
        break;
      }
      case 'policy_add': {
        if (change.newData) {
          policies.push({ ...change.newData, id: change.targetId || `preview-${Date.now()}` });
        }
        break;
      }
      case 'policy_modify': {
        const idx = policies.findIndex((p) => p.id === change.targetId);
        if (idx >= 0 && change.newData) {
          policies[idx] = { ...policies[idx], ...change.newData };
        }
        break;
      }
      case 'policy_delete': {
        policies = policies.filter((p) => p.id !== change.targetId);
        break;
      }
      case 'blocklist_add': {
        if (change.newData) {
          blocklist.push({ ...change.newData, id: change.targetId || `preview-${Date.now()}` });
        }
        break;
      }
      case 'blocklist_delete': {
        blocklist = blocklist.filter((b) => b.id !== change.targetId);
        break;
      }
      case 'allowlist_add': {
        if (change.newData) {
          allowlist.push({ ...change.newData, id: change.targetId || `preview-${Date.now()}` });
        }
        break;
      }
      case 'allowlist_delete': {
        allowlist = allowlist.filter((a) => a.id !== change.targetId);
        break;
      }
      case 'ratelimit_add': {
        if (change.newData) {
          ratelimit.push({ ...change.newData, id: change.targetId || `preview-${Date.now()}` });
        }
        break;
      }
      case 'ratelimit_modify': {
        const idx = ratelimit.findIndex((r) => r.id === change.targetId);
        if (idx >= 0 && change.newData) {
          ratelimit[idx] = { ...ratelimit[idx], ...change.newData };
        }
        break;
      }
      case 'ratelimit_delete': {
        ratelimit = ratelimit.filter((r) => r.id !== change.targetId);
        break;
      }
    }
  }

  const zoneMap = new Map(zones.map((z) => [z.id, z]));
  const zoneNameMap = new Map(zones.map((z) => [z.name, z]));
  const allRecords = [];
  for (const zone of zones) {
    for (const rec of zone.records || []) {
      allRecords.push({ ...rec, zone_id: zone.id });
    }
  }

  const previewDb = {
    getZoneByName: (name) => zoneNameMap.get(normalizeName(name)) || null,
    getZoneById: (id) => zoneMap.get(id) || null,
    getAllZones: () => zones,
    findRecords: (name, type) => {
      const n = normalizeName(name);
      let results = allRecords.filter((r) => normalizeName(r.name) === n);
      if (type) {
        results = results.filter((r) => r.type === type.toUpperCase());
      }
      return results;
    },
    findBestMatchingZone: (domainName) => {
      let name = normalizeName(domainName);
      if (name === '.') return zoneNameMap.get('.') || null;
      const parts = name.split('.');
      for (let i = 0; i < parts.length; i++) {
        const candidate = parts.slice(i).join('.');
        const zone = zoneNameMap.get(candidate);
        if (zone) return zone;
      }
      return zoneNameMap.get('.') || null;
    },
    findDelegationNs: (zoneName) => {
      const parent = previewDb.findBestMatchingZone(zoneName);
      if (!parent) return [];
      return allRecords.filter(
        (r) => r.zone_id === parent.id && r.type === 'NS' && normalizeName(r.name) === normalizeName(zoneName)
      );
    },
    getParentZone: (zoneName) => {
      const name = normalizeName(zoneName);
      if (name === '.') return null;
      const parts = name.split('.');
      parts.shift();
      const parentName = parts.length === 0 ? '.' : parts.join('.');
      return zoneNameMap.get(parentName) || null;
    },
    getZoneDnssec: () => ({ enabled: false }),
    findRrsigForRecord: () => [],
    findDsRecords: () => [],
    listPolicies: () => policies,
    incrementPolicyHit: () => {},
    listBlocklistEntries: (includeExpired = false) => {
      if (includeExpired) return blocklist;
      const now = Date.now();
      return blocklist.filter((row) => {
        if (row.expire_minutes === 0) return true;
        const expireAt = row.created_at + row.expire_minutes * 60 * 1000;
        return expireAt > now;
      });
    },
    listAllowlistEntries: () => allowlist,
    listRatelimitRules: () => ratelimit,
    addPolicyLog: () => {},
    trimPolicyLogs: () => {},
    getZoneSoa: (zoneId) => {
      const zone = zoneMap.get(zoneId);
      if (!zone) return null;
      return {
        serial: zone.serial || 1,
        lastChangeAt: zone.last_change_at,
        recordCount: (zone.records || []).length,
      };
    },
    getDnssecStatus: () => ({ enabled: false }),
    verifyRrsig: () => true,
  };

  return previewDb;
}

function createPreviewResolver(previewDb) {
  const cacheManager = new CacheManager();
  const statsLogger = new StatsLogger();
  const resolver = new RecursiveResolver(cacheManager, statsLogger);

  const originalFindRecords = db.findRecords;
  const originalGetZoneByName = db.getZoneByName;
  const originalGetZoneById = db.getZoneById;
  const originalFindBestMatchingZone = db.findBestMatchingZone;
  const originalFindDelegationNs = db.findDelegationNs;
  const originalGetParentZone = db.getParentZone;
  const originalGetZoneDnssec = db.getZoneDnssec;
  const originalFindRrsigForRecord = db.findRrsigForRecord;
  const originalFindDsRecords = db.findDsRecords;
  const originalGetZoneSoa = db.getZoneSoa;
  const originalGetDnssecStatus = db.getDnssecStatus;
  const originalVerifyRrsig = db.verifyRrsig;

  try {
    db.findRecords = previewDb.findRecords;
    db.getZoneByName = previewDb.getZoneByName;
    db.getZoneById = previewDb.getZoneById;
    db.findBestMatchingZone = previewDb.findBestMatchingZone;
    db.findDelegationNs = previewDb.findDelegationNs;
    db.getParentZone = previewDb.getParentZone;
    db.getZoneDnssec = previewDb.getZoneDnssec;
    db.findRrsigForRecord = previewDb.findRrsigForRecord;
    db.findDsRecords = previewDb.findDsRecords;
    db.getZoneSoa = previewDb.getZoneSoa;
    db.getDnssecStatus = previewDb.getDnssecStatus;
    db.verifyRrsig = previewDb.verifyRrsig;

    return {
      resolver,
      cleanup: () => {
        db.findRecords = originalFindRecords;
        db.getZoneByName = originalGetZoneByName;
        db.getZoneById = originalGetZoneById;
        db.findBestMatchingZone = originalFindBestMatchingZone;
        db.findDelegationNs = originalFindDelegationNs;
        db.getParentZone = originalGetParentZone;
        db.getZoneDnssec = originalGetZoneDnssec;
        db.findRrsigForRecord = originalFindRrsigForRecord;
        db.findDsRecords = originalFindDsRecords;
        db.getZoneSoa = originalGetZoneSoa;
        db.getDnssecStatus = originalGetDnssecStatus;
        db.verifyRrsig = originalVerifyRrsig;
      },
    };
  } catch (e) {
    db.findRecords = originalFindRecords;
    db.getZoneByName = originalGetZoneByName;
    db.getZoneById = originalGetZoneById;
    db.findBestMatchingZone = originalFindBestMatchingZone;
    db.findDelegationNs = originalFindDelegationNs;
    db.getParentZone = originalGetParentZone;
    db.getZoneDnssec = originalGetZoneDnssec;
    db.findRrsigForRecord = originalFindRrsigForRecord;
    db.findDsRecords = originalFindDsRecords;
    db.getZoneSoa = originalGetZoneSoa;
    db.getDnssecStatus = originalGetDnssecStatus;
    db.verifyRrsig = originalVerifyRrsig;
    throw e;
  }
}

function createPreviewEnforcement(previewDb) {
  const enforcement = new EnforcementManager();

  enforcement.findMatchingAllowlist = (domain) => {
    const entries = previewDb.listAllowlistEntries();
    for (const e of entries) {
      if (EnforcementManager.matchPattern(domain, e.pattern)) {
        return e;
      }
    }
    return null;
  };

  enforcement.findMatchingBlocklist = (domain) => {
    const entries = previewDb.listBlocklistEntries(false);
    for (const e of entries) {
      if (EnforcementManager.matchPattern(domain, e.pattern)) {
        return e;
      }
    }
    return null;
  };

  enforcement.findMatchingRatelimit = (domain) => {
    const rules = previewDb.listRatelimitRules();
    for (const r of rules) {
      if (EnforcementManager.matchPattern(domain, r.pattern)) {
        return r;
      }
    }
    return null;
  };

  return enforcement;
}

function createPreviewPolicyEngine(previewDb, resolver) {
  const policyEngine = new PolicyEngine(resolver);

  policyEngine.applyPolicies = async function (queryName, queryType, result, _redirectDepth = 0) {
    const originalAnswer = result.answer ? [...result.answer] : [];
    const originalStatus = result.status;
    const policies = previewDb.listPolicies();
    const enabledPolicies = policies.filter((p) => p.enabled);

    let matchedPolicyId = null;
    let matchedPolicyName = null;
    let executedAction = 'none';
    let modifiedAnswer = originalAnswer;
    let modifiedStatus = originalStatus;
    let modifiedAuthority = result.authority ? [...result.authority] : [];
    let passthrough = false;
    let redirectChain = [];

    for (const policy of enabledPolicies) {
      if (passthrough) break;

      const matches = matchPolicy(policy, queryName, queryType, modifiedAnswer);
      if (!matches) continue;

      matchedPolicyId = policy.id;
      matchedPolicyName = policy.name;
      executedAction = policy.action;

      switch (policy.action) {
        case 'rewrite':
          modifiedAnswer = executeRewrite(modifiedAnswer, policy);
          break;
        case 'redirect':
          if (_redirectDepth >= 3) {
            executedAction = 'redirect_limit_exceeded';
            break;
          }
          const params = policy.actionParams || {};
          const targetDomain = params.targetDomain;
          if (targetDomain) {
            const redirectResolveResult = await resolver.resolve(targetDomain, queryType, false);
            const policyAppliedResult = await this.applyPolicies(
              targetDomain,
              queryType,
              redirectResolveResult,
              _redirectDepth + 1
            );
            modifiedAnswer = policyAppliedResult.answer || [];
            modifiedAuthority = policyAppliedResult.authority || [];
            modifiedStatus = policyAppliedResult.status;
            redirectChain = [policy.id, ...(policyAppliedResult.redirectChain || [])];
          }
          break;
        case 'nxdomain':
          const nxResult = executeNxdomain();
          modifiedAnswer = nxResult.answer;
          modifiedAuthority = nxResult.authority;
          modifiedStatus = nxResult.status;
          break;
        case 'passthrough':
          passthrough = true;
          break;
      }
      break;
    }

    return {
      ...result,
      status: modifiedStatus,
      answer: modifiedAnswer,
      authority: modifiedAuthority,
      policyApplied: matchedPolicyId !== null,
      matchedPolicyId,
      matchedPolicyName,
      executedAction,
      redirectChain,
    };
  };

  return policyEngine;
}

async function resolveWithPreview(previewDb, name, type) {
  const { resolver, cleanup } = createPreviewResolver(previewDb);
  const enforcement = createPreviewEnforcement(previewDb);
  const policyEngine = createPreviewPolicyEngine(previewDb, resolver);

  try {
    const queryType = (type || 'A').toUpperCase();
    const queryName = normalizeName(name);

    const check = enforcement.checkQuery(queryName);
    if (check.action === 'block') {
      return {
        status: 'REFUSED',
        reason: 'blocked',
        matchedPattern: check.matchedPattern,
        question: { name: queryName, type: queryType },
        answer: [],
        elapsedMs: 0,
        enforcementAction: 'block',
      };
    }
    if (check.action === 'ratelimit') {
      return {
        status: 'RATE_LIMITED',
        reason: `exceeded ${check.maxRequests} requests in ${check.windowSeconds}s`,
        matchedPattern: check.matchedPattern,
        retryAfter: check.retryAfter,
        question: { name: queryName, type: queryType },
        answer: [],
        elapsedMs: 0,
        enforcementAction: 'ratelimit',
      };
    }

    let result = await resolver.resolve(queryName, queryType, false);
    result = await policyEngine.applyPolicies(queryName, queryType, result);

    return result;
  } finally {
    cleanup();
  }
}

function detectChangeType(onlineResult, draftResult) {
  const onlineStatus = onlineResult?.status || 'UNKNOWN';
  const draftStatus = draftResult?.status || 'UNKNOWN';

  if (onlineStatus !== draftStatus) {
    if (draftStatus === 'NXDOMAIN') return 'to_nxdomain';
    if (draftStatus === 'REFUSED') return 'to_refused';
    if (draftStatus === 'RATE_LIMITED') return 'to_ratelimited';
    if (onlineStatus === 'NXDOMAIN' && draftStatus === 'SUCCESS') return 'to_success';
    return 'status_change';
  }

  const onlineAnswer = onlineResult?.answer || [];
  const draftAnswer = draftResult?.answer || [];

  if (onlineAnswer.length !== draftAnswer.length) {
    return 'content_change';
  }

  const onlineStr = JSON.stringify(onlineAnswer.map((a) => ({ name: a.name, type: a.type, value: a.value })));
  const draftStr = JSON.stringify(draftAnswer.map((a) => ({ name: a.name, type: a.type, value: a.value })));

  if (onlineStr !== draftStr) {
    if (draftResult?.policyApplied || onlineResult?.policyApplied) {
      return 'policy_rewritten';
    }
    return 'content_change';
  }

  if ((onlineResult?.matchedPolicyId) !== (draftResult?.matchedPolicyId)) {
    return 'policy_match_change';
  }

  if ((onlineResult?.enforcementAction) !== (draftResult?.enforcementAction)) {
    return 'enforcement_change';
  }

  return 'none';
}

function extractHitRules(result) {
  const rules = [];
  if (result?.matchedPolicyId) {
    rules.push({
      type: 'policy',
      id: result.matchedPolicyId,
      name: result.matchedPolicyName,
      action: result.executedAction,
    });
  }
  if (result?.matchedPattern) {
    rules.push({
      type: result.enforcementAction === 'block' ? 'blocklist' : 'ratelimit',
      pattern: result.matchedPattern,
    });
  }
  return rules;
}

async function runPlayback(draftId, sampleSetId) {
  const draft = db.getDraftById(draftId);
  if (!draft) {
    throw new Error('Draft not found');
  }

  const snapshot = db.getConfigSnapshotById(draft.snapshotId);
  if (!snapshot) {
    throw new Error('Snapshot not found');
  }

  const draftChanges = db.listDraftChanges(draftId);
  const samples = db.listSamples(sampleSetId);

  const previewDb = createPreviewDb(snapshot, draftChanges);

  const results = [];
  let changedCount = 0;
  let failedCount = 0;
  let blockedCount = 0;

  for (const sample of samples) {
    const onlineResult = await resolveOnline(sample.name, sample.type);
    const draftResult = await resolveWithPreview(previewDb, sample.name, sample.type);

    const statusChanged = onlineResult.status !== draftResult.status;
    const changeType = detectChangeType(onlineResult, draftResult);
    const contentChanged = changeType !== 'none' && changeType !== 'status_change';

    if (changeType !== 'none') changedCount++;
    if (draftResult.status === 'NXDOMAIN' || draftResult.status === 'REFUSED' || draftResult.status === 'SERVFAIL') {
      failedCount++;
    }
    if (changeType === 'to_refused' || changeType === 'to_ratelimited' || changeType === 'to_nxdomain') {
      blockedCount++;
    }

    results.push({
      sampleId: sample.id,
      queryName: sample.name,
      queryType: sample.type,
      onlineResult,
      draftResult,
      statusChanged,
      contentChanged,
      changeType,
      rulesHitOnline: extractHitRules(onlineResult),
      rulesHitDraft: extractHitRules(draftResult),
    });
  }

  const report = db.createPlaybackReport(
    draftId,
    sampleSetId,
    samples.length,
    changedCount,
    failedCount,
    blockedCount
  );

  for (const result of results) {
    db.addPlaybackResult({
      reportId: report.id,
      ...result,
    });
  }

  return {
    report,
    results,
    summary: db.getPlaybackSummary(report.id),
  };
}

async function resolveOnline(name, type) {
  const queryType = (type || 'A').toUpperCase();
  const queryName = normalizeName(name);

  try {
    const response = await new Promise((resolve, reject) => {
      const http = require('http');
      const postData = JSON.stringify({ name: queryName, type: queryType });
      const options = {
        hostname: '127.0.0.1',
        port: process.env.PORT || 3000,
        path: '/api/resolve',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
      };
      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(e);
          }
        });
      });
      req.on('error', reject);
      req.write(postData);
      req.end();
    });
    return response;
  } catch (e) {
    const enforcementManager = new EnforcementManager();
    const check = enforcementManager.checkQuery(queryName);
    if (check.action === 'block') {
      return {
        status: 'REFUSED',
        reason: 'blocked',
        matchedPattern: check.matchedPattern,
        question: { name: queryName, type: queryType },
        answer: [],
        elapsedMs: 0,
        enforcementAction: 'block',
      };
    }

    const cacheManager = new CacheManager();
    const statsLogger = new StatsLogger();
    const resolver = new RecursiveResolver(cacheManager, statsLogger);
    const policyEngine = new PolicyEngine(resolver);

    let result = await resolver.resolve(queryName, queryType, false);
    result = await policyEngine.applyPolicies(queryName, queryType, result);
    return result;
  }
}

function checkPublishConflict(draftId) {
  const draft = db.getDraftById(draftId);
  if (!draft) {
    return { conflict: true, reason: 'Draft not found' };
  }
  if (draft.status !== 'draft') {
    return { conflict: true, reason: `Draft is already ${draft.status}` };
  }

  const currentVersion = db.getCurrentConfigVersion();
  if (currentVersion > draft.snapshotVersion) {
    return {
      conflict: true,
      reason: `Configuration has changed since draft was created. Snapshot version: ${draft.snapshotVersion}, Current version: ${currentVersion}`,
      snapshotVersion: draft.snapshotVersion,
      currentVersion,
    };
  }

  return { conflict: false };
}

async function publishDraftChanges(draftId) {
  const conflictCheck = checkPublishConflict(draftId);
  if (conflictCheck.conflict) {
    throw new Error(conflictCheck.reason);
  }

  const draft = db.getDraftById(draftId);
  const changes = db.listDraftChanges(draftId);

  db.beginTransaction();
  try {
    for (const change of changes) {
      switch (change.changeType) {
        case 'record_add':
          if (change.zoneId && change.newData) {
            db.addRecord(
              change.zoneId,
              change.newData.name,
              change.newData.type,
              change.newData.value,
              change.newData.ttl || 3600
            );
          }
          break;
        case 'record_modify':
          if (change.zoneId && change.targetId && change.newData) {
            db.updateRecord(change.zoneId, change.targetId, {
              value: change.newData.value,
              ttl: change.newData.ttl,
            });
          }
          break;
        case 'record_delete':
          if (change.zoneId && change.targetId) {
            db.deleteRecord(change.zoneId, change.targetId);
          }
          break;
        case 'policy_add':
          if (change.newData) {
            db.addPolicy(change.newData);
          }
          break;
        case 'policy_modify':
          if (change.targetId && change.newData) {
            db.updatePolicy(change.targetId, change.newData);
          }
          break;
        case 'policy_delete':
          if (change.targetId) {
            db.deletePolicy(change.targetId);
          }
          break;
        case 'blocklist_add':
          if (change.newData) {
            db.addBlocklistEntry(
              change.newData.pattern,
              change.newData.reason,
              change.newData.expireMinutes || 0
            );
          }
          break;
        case 'blocklist_delete':
          if (change.targetId) {
            db.deleteBlocklistEntry(change.targetId);
          }
          break;
        case 'allowlist_add':
          if (change.newData) {
            db.addAllowlistEntry(change.newData.pattern);
          }
          break;
        case 'allowlist_delete':
          if (change.targetId) {
            db.deleteAllowlistEntry(change.targetId);
          }
          break;
        case 'ratelimit_add':
          if (change.newData) {
            db.addRatelimitRule(
              change.newData.pattern,
              change.newData.maxRequests,
              change.newData.windowSeconds || 60
            );
          }
          break;
        case 'ratelimit_modify':
          if (change.targetId && change.newData) {
            db.updateRatelimitRule(change.targetId, change.newData);
          }
          break;
        case 'ratelimit_delete':
          if (change.targetId) {
            db.deleteRatelimitRule(change.targetId);
          }
          break;
      }
    }

    db.publishDraft(draftId);
    db.commitTransaction();
  } catch (err) {
    db.rollbackTransaction();
    throw err;
  }

  return db.getDraftById(draftId);
}

module.exports = {
  createPreviewDb,
  createPreviewResolver,
  resolveWithPreview,
  runPlayback,
  detectChangeType,
  checkPublishConflict,
  publishDraftChanges,
  resolveOnline,
};
