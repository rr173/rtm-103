const db = require('../db/database');
const { DEFAULT_NEGATIVE_TTL } = require('../cache/cacheManager');

const HOP_DELAY_MS = 2;
const MAX_DELEGATION_HOPS = 12;
const MAX_CNAME_DEPTH = 8;
const MAX_TOTAL_DELAY_MS = 500;
const MAX_ZONE_VISITS = 2;

function normalizeName(name) {
  let n = name.toLowerCase();
  if (n !== '.' && n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

function isChildOf(child, parent) {
  if (parent === '.') return true;
  if (child === parent) return false;
  return child === parent || child.endsWith('.' + parent);
}

function findSoaMinimum(zone) {
  if (!zone) return DEFAULT_NEGATIVE_TTL;
  const soaRecords = db.findRecords(zone.name, 'SOA');
  if (soaRecords.length === 0) return DEFAULT_NEGATIVE_TTL;
  try {
    const parts = soaRecords[0].value.split(/\s+/);
    if (parts.length >= 7) return parseInt(parts[6], 10) || DEFAULT_NEGATIVE_TTL;
  } catch (e) {}
  return DEFAULT_NEGATIVE_TTL;
}

class RecursiveResolver {
  constructor(cacheManager, statsLogger) {
    this.cache = cacheManager;
    this.stats = statsLogger;
  }

  async resolve(name, type) {
    const startTime = Date.now();
    const targetName = normalizeName(name);
    const targetType = type.toUpperCase();

    const cached = this.cache.get(targetName, targetType);
    if (cached) {
      const elapsed = Date.now() - startTime;
      const isNxdomain = cached.value && cached.value.nxdomain;

      this.stats.recordQuery({
        name: targetName,
        type: targetType,
        resultCode: isNxdomain ? 'NXDOMAIN' : 'SUCCESS',
        hops: 0,
        cached: true,
        elapsedMs: elapsed,
      });

      if (isNxdomain) {
        return {
          status: 'NXDOMAIN',
          answer: [],
          authority: cached.value.authority || [],
          trace: [],
          cached: true,
          elapsedMs: elapsed,
          hops: 0,
        };
      }

      return {
        status: 'SUCCESS',
        answer: cached.value.answer,
        authority: cached.value.authority || [],
        trace: cached.value.trace || [],
        cached: true,
        elapsedMs: elapsed,
        hops: 0,
      };
    }

    const state = {
      trace: [],
      visitedZones: new Map(),
      delegationHops: 0,
      cnameDepth: 0,
      totalDelay: 0,
      authority: [],
    };

    try {
      const result = this._resolveName(targetName, targetType, state);
      const elapsed = Date.now() - startTime;

      if (result.status === 'SUCCESS') {
        const minTtl = result.answer.length > 0
          ? Math.min(...result.answer.map((r) => r.ttl || 3600))
          : 3600;
        this.cache.set(targetName, targetType, {
          answer: result.answer,
          authority: result.authority,
          trace: state.trace,
        }, minTtl);
      } else if (result.status === 'NXDOMAIN') {
        this.cache.set(targetName, targetType, {
          nxdomain: true,
          authority: result.authority,
        }, result.negativeTtl || DEFAULT_NEGATIVE_TTL);
      }

      this.stats.recordQuery({
        name: targetName,
        type: targetType,
        resultCode: result.status,
        hops: state.delegationHops,
        cached: false,
        elapsedMs: elapsed,
      });

      return {
        status: result.status,
        message: result.message,
        answer: result.answer || [],
        authority: result.authority || [],
        trace: state.trace,
        cached: false,
        elapsedMs: elapsed,
        hops: state.delegationHops,
      };
    } catch (err) {
      const elapsed = Date.now() - startTime;
      this.stats.recordQuery({
        name: targetName,
        type: targetType,
        resultCode: err.status || 'SERVFAIL',
        hops: state.delegationHops,
        cached: false,
        elapsedMs: elapsed,
      });
      return {
        status: err.status || 'SERVFAIL',
        message: err.message,
        answer: [],
        authority: state.authority,
        trace: state.trace,
        cached: false,
        elapsedMs: elapsed,
        hops: state.delegationHops,
      };
    }
  }

  _resolveName(qname, qtype, state) {
    let currentName = qname;
    let currentType = qtype;
    let answer = [];
    let cnameFollowed = [];
    let currentZone = db.getZoneByName('.');

    if (!currentZone) {
      throw { status: 'SERVFAIL', message: 'Root zone not configured' };
    }

    while (true) {
      const visitKey = `${currentZone.name}|${currentName}`;
      const visitCount = (state.visitedZones.get(visitKey) || 0) + 1;
      state.visitedZones.set(visitKey, visitCount);
      if (visitCount > MAX_ZONE_VISITS) {
        throw { status: 'LOOP', message: `Delegation loop detected at ${currentZone.name} for ${currentName}` };
      }

      if (state.delegationHops > 0 || state.cnameDepth > 0) {
        state.totalDelay += HOP_DELAY_MS;
        if (state.totalDelay > MAX_TOTAL_DELAY_MS) {
          throw { status: 'TIMEOUT', message: 'Resolution timeout exceeded' };
        }
      }

      const recordsInZone = db.findRecords(currentName, null).filter((r) => r.zone_id === currentZone.id);
      const directAnswer = recordsInZone.filter((r) => r.type === currentType);
      const cnameRecords = recordsInZone.filter((r) => r.type === 'CNAME');

      if (directAnswer.length > 0) {
        state.trace.push({
          zone: currentZone.name,
          query: { name: currentName, type: currentType },
          records: directAnswer.map((r) => ({
            name: r.name,
            type: r.type,
            value: r.value,
            ttl: r.ttl,
          })),
          delayMs: HOP_DELAY_MS,
        });

        const authorityNs = db.findRecords(currentZone.name, 'NS')
          .filter((r) => r.zone_id === currentZone.id)
          .map((r) => ({ name: r.name, type: r.type, value: r.value, ttl: r.ttl }));

        answer.push(...directAnswer.map((r) => ({
          name: r.name,
          type: r.type,
          value: r.value,
          ttl: r.ttl,
        })));

        return {
          status: 'SUCCESS',
          answer,
          authority: authorityNs,
        };
      }

      if (cnameRecords.length > 0 && currentType !== 'CNAME') {
        const cname = cnameRecords[0];
        state.trace.push({
          zone: currentZone.name,
          query: { name: currentName, type: currentType },
          records: [{ name: cname.name, type: cname.type, value: cname.value, ttl: cname.ttl }],
          delayMs: HOP_DELAY_MS,
        });

        answer.push({ name: cname.name, type: cname.type, value: cname.value, ttl: cname.ttl });
        state.cnameDepth += 1;

        if (state.cnameDepth > MAX_CNAME_DEPTH) {
          throw { status: 'CNAME_LOOP', message: 'Max CNAME chain depth exceeded (8)' };
        }

        const cnameTarget = normalizeName(cname.value);
        if (cnameFollowed.includes(cnameTarget)) {
          throw { status: 'CNAME_LOOP', message: 'CNAME loop detected' };
        }
        cnameFollowed.push(cnameTarget);

        currentName = cnameTarget;
        currentZone = db.getZoneByName('.');
        state.delegationHops = 0;
        continue;
      }

      const delegation = this._findLongestDelegation(currentName, currentZone);
      if (delegation) {
        state.trace.push({
          zone: currentZone.name,
          query: { name: currentName, type: currentType },
          records: delegation.nsRecords.map((r) => ({
            name: r.name,
            type: r.type,
            value: r.value,
            ttl: r.ttl,
          })),
          delayMs: HOP_DELAY_MS,
          delegationTo: delegation.zoneName,
        });

        state.delegationHops += 1;
        if (state.delegationHops > MAX_DELEGATION_HOPS) {
          throw { status: 'MAX_DEPTH', message: 'Max delegation hops exceeded (12)' };
        }

        const nextZone = db.getZoneByName(delegation.zoneName);
        if (!nextZone) {
          throw {
            status: 'SERVFAIL',
            message: `Delegated zone '${delegation.zoneName}' does not exist in the virtual namespace`,
          };
        }

        state.authority = delegation.nsRecords.map((r) => ({
          name: r.name,
          type: r.type,
          value: r.value,
          ttl: r.ttl,
        }));

        currentZone = nextZone;
        continue;
      }

      state.trace.push({
        zone: currentZone.name,
        query: { name: currentName, type: currentType },
        records: [],
        delayMs: HOP_DELAY_MS,
      });

      const authorityNs = db.findRecords(currentZone.name, 'NS')
        .filter((r) => r.zone_id === currentZone.id)
        .map((r) => ({ name: r.name, type: r.type, value: r.value, ttl: r.ttl }));

      if (this._isAuthoritativeFor(currentZone, currentName)) {
        return {
          status: 'NXDOMAIN',
          answer: [],
          authority: authorityNs.length > 0 ? authorityNs : state.authority,
          negativeTtl: findSoaMinimum(currentZone),
        };
      }

      return {
        status: 'NXDOMAIN',
        answer: [],
        authority: state.authority,
        negativeTtl: DEFAULT_NEGATIVE_TTL,
      };
    }
  }

  _isAuthoritativeFor(zone, name) {
    if (zone.name === '.') return true;
    if (name === zone.name) return true;
    return name.endsWith('.' + zone.name);
  }

  _findLongestDelegation(name, fromZone) {
    if (name === '.' || name === fromZone.name) return null;

    const allParts = name.split('.');
    let bestMatch = null;

    for (let i = 0; i < allParts.length; i++) {
      const candidate = allParts.slice(i).join('.');
      if (!candidate || candidate === fromZone.name) continue;
      if (!this._isChildOrEqual(candidate, fromZone.name)) continue;

      const nsRecords = db.findRecords(candidate, 'NS')
        .filter((r) => r.zone_id === fromZone.id);

      if (nsRecords.length > 0) {
        if (!bestMatch || candidate.length > bestMatch.zoneName.length) {
          bestMatch = { zoneName: candidate, nsRecords };
        }
      }
    }

    return bestMatch;
  }

  _isChildOrEqual(child, parent) {
    if (parent === '.') return true;
    if (child === parent) return true;
    return child.endsWith('.' + parent);
  }
}

module.exports = {
  RecursiveResolver,
  HOP_DELAY_MS,
  MAX_DELEGATION_HOPS,
  MAX_CNAME_DEPTH,
  MAX_TOTAL_DELAY_MS,
};
