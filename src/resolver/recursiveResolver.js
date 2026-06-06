const db = require('../db/database');
const { DEFAULT_NEGATIVE_TTL } = require('../cache/cacheManager');

function normalizeZoneName(name) {
  let n = name.toLowerCase();
  if (n !== '.' && n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

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

  async resolve(name, type, dnssec = false) {
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

      let response;
      if (isNxdomain) {
        response = {
          status: 'NXDOMAIN',
          answer: [],
          authority: cached.value.authority || [],
          trace: [],
          cached: true,
          elapsedMs: elapsed,
          hops: 0,
        };
      } else {
        response = {
          status: 'SUCCESS',
          answer: cached.value.answer,
          authority: cached.value.authority || [],
          trace: cached.value.trace || [],
          cached: true,
          elapsedMs: elapsed,
          hops: 0,
        };
      }

      if (dnssec) {
        const dnssecResult = this._validateDnssec(targetName, targetType, response.answer);
        Object.assign(response, dnssecResult);
      }

      return response;
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

      const response = {
        status: result.status,
        message: result.message,
        answer: result.answer || [],
        authority: result.authority || [],
        trace: state.trace,
        cached: false,
        elapsedMs: elapsed,
        hops: state.delegationHops,
      };

      if (dnssec) {
        const dnssecResult = this._validateDnssec(targetName, targetType, response.answer);
        Object.assign(response, dnssecResult);
      }

      return response;
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
      const response = {
        status: err.status || 'SERVFAIL',
        message: err.message,
        answer: [],
        authority: state.authority,
        trace: state.trace,
        cached: false,
        elapsedMs: elapsed,
        hops: state.delegationHops,
      };
      if (dnssec) {
        const dnssecResult = this._validateDnssec(targetName, targetType, response.answer);
        Object.assign(response, dnssecResult);
      }
      return response;
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

  _validateDnssec(qname, qtype, answers) {
    const validationChain = [];
    const trustAnchor = db.getTrustAnchor();

    if (!trustAnchor) {
      return {
        dnssecStatus: 'BOGUS',
        failureReason: 'No trust anchor configured for root zone',
        failureAt: '.',
        validationChain: [{ zone: '.', result: 'BOGUS', reason: 'Trust anchor not set' }],
      };
    }

    if (!answers || answers.length === 0) {
      return {
        dnssecStatus: 'INSECURE',
        validationChain: [{ zone: '.', result: 'INSECURE', reason: 'No answers to validate' }],
      };
    }

    const firstAnswer = answers[0];
    const recordZone = db.findBestMatchingZone(firstAnswer.name);
    if (!recordZone) {
      return {
        dnssecStatus: 'BOGUS',
        failureReason: 'No authoritative zone found for record',
        failureAt: firstAnswer.name,
        validationChain: [{ zone: firstAnswer.name, result: 'BOGUS', reason: 'No authoritative zone' }],
      };
    }

    let currentZone = recordZone;
    let allSecure = true;

    while (currentZone) {
      const zoneDnssec = db.getZoneDnssec(currentZone.id);

      if (!zoneDnssec || !zoneDnssec.enabled) {
        validationChain.push({
          zone: currentZone.name,
          result: 'INSECURE',
          reason: 'DNSSEC not enabled for this zone',
        });
        allSecure = false;
        break;
      }

      if (currentZone.id === recordZone.id) {
        for (const answer of answers) {
          if (answer.type === 'RRSIG') continue;
          const rrsigs = db.findRrsigForRecord(recordZone.id, answer.name, answer.type);
          if (!rrsigs || rrsigs.length === 0) {
            validationChain.push({
              zone: currentZone.name,
              result: 'BOGUS',
              reason: `No RRSIG found for ${answer.name} ${answer.type}`,
            });
            return {
              dnssecStatus: 'BOGUS',
              failureReason: `Missing RRSIG for ${answer.name} ${answer.type}`,
              failureAt: currentZone.name,
              validationChain,
            };
          }

          let sigValid = false;
          for (const rrsig of rrsigs) {
            const parts = rrsig.value.split('/');
            if (parts.length < 3) continue;
            const [coveredType, sigKeyTag, signature] = parts;
            if (coveredType !== answer.type) continue;
            if (sigKeyTag !== zoneDnssec.key_tag) continue;
            if (db.verifyRrsig(zoneDnssec.secret, answer.name, answer.type, answer.value, answer.ttl, signature)) {
              sigValid = true;
              break;
            }
          }

          if (!sigValid) {
            validationChain.push({
              zone: currentZone.name,
              result: 'BOGUS',
              reason: `Invalid signature for ${answer.name} ${answer.type}`,
            });
            return {
              dnssecStatus: 'BOGUS',
              failureReason: `Invalid RRSIG signature for ${answer.name} ${answer.type}`,
              failureAt: currentZone.name,
              validationChain,
            };
          }
        }
        validationChain.push({
          zone: currentZone.name,
          result: 'SECURE',
          reason: 'Record signatures verified',
        });
      } else {
        validationChain.push({
          zone: currentZone.name,
          result: 'SECURE',
          reason: 'Zone DNSSEC enabled',
        });
      }

      if (currentZone.name === '.') {
        if (zoneDnssec.key_tag !== trustAnchor.key_tag) {
          validationChain[validationChain.length - 1].result = 'BOGUS';
          validationChain[validationChain.length - 1].reason = `Root keyTag ${zoneDnssec.key_tag} does not match trust anchor ${trustAnchor.key_tag}`;
          return {
            dnssecStatus: 'BOGUS',
            failureReason: `Root zone keyTag does not match configured trust anchor`,
            failureAt: '.',
            validationChain,
          };
        }
        break;
      }

      const parentZone = db.getParentZone(currentZone.name);
      if (!parentZone) {
        validationChain.push({
          zone: '(missing parent)',
          result: 'BOGUS',
          reason: `Parent zone of ${currentZone.name} not found`,
        });
        return {
          dnssecStatus: 'BOGUS',
          failureReason: `Parent zone not found for ${currentZone.name}`,
          failureAt: currentZone.name,
          validationChain,
        };
      }

      const dsRecords = db.findDsRecords(parentZone.id, currentZone.name);
      if (!dsRecords || dsRecords.length === 0) {
        validationChain.push({
          zone: parentZone.name,
          result: 'BOGUS',
          reason: `No DS record found for ${currentZone.name} in parent zone ${parentZone.name}`,
        });
        return {
          dnssecStatus: 'BOGUS',
          failureReason: `Missing DS record for ${currentZone.name} in parent zone`,
          failureAt: parentZone.name,
          validationChain,
        };
      }

      const dsMatches = dsRecords.some((ds) => ds.value === zoneDnssec.key_tag);
      if (!dsMatches) {
        validationChain.push({
          zone: parentZone.name,
          result: 'BOGUS',
          reason: `DS record for ${currentZone.name} does not match zone keyTag`,
        });
        return {
          dnssecStatus: 'BOGUS',
          failureReason: `DS record does not match zone keyTag for ${currentZone.name}`,
          failureAt: parentZone.name,
          validationChain,
        };
      }

      currentZone = parentZone;
    }

    if (allSecure) {
      return {
        dnssecStatus: 'SECURE',
        validationChain,
      };
    } else {
      return {
        dnssecStatus: 'INSECURE',
        validationChain,
      };
    }
  }
}

module.exports = {
  RecursiveResolver,
  HOP_DELAY_MS,
  MAX_DELEGATION_HOPS,
  MAX_CNAME_DEPTH,
  MAX_TOTAL_DELAY_MS,
};
