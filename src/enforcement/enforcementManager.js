const db = require('../db/database');

class EnforcementManager {
  constructor() {
    this.rateLimitCounters = new Map();
    this.stats = {
      blockCount: 0,
      rateLimitCount: 0,
      allowCount: 0,
      perDomainBlockCount: new Map(),
      perDomainRateLimitCount: new Map(),
      perDomainAllowCount: new Map(),
      recentIntercepts: [],
    };
    this.startCleanupInterval();
  }

  startCleanupInterval() {
    setInterval(() => {
      this.cleanupExpiredCounters();
      this.trimRecentIntercepts();
    }, 10000);
  }

  cleanupExpiredCounters() {
    const rules = db.listRatelimitRules();
    const now = Date.now();
    const rulesByPattern = new Map();
    for (const r of rules) {
      rulesByPattern.set(r.pattern, r);
    }
    for (const [domain, entry] of this.rateLimitCounters.entries()) {
      const rule = rulesByPattern.get(entry.matchedPattern);
      const windowMs = rule ? rule.window_seconds * 1000 : 60000;
      entry.timestamps = entry.timestamps.filter((t) => now - t < windowMs);
      if (entry.timestamps.length === 0) {
        this.rateLimitCounters.delete(domain);
      }
    }
  }

  trimRecentIntercepts() {
    const cutoff = Date.now() - 60 * 60 * 1000;
    this.stats.recentIntercepts = this.stats.recentIntercepts.filter(
      (i) => i.timestamp >= cutoff
    );
  }

  static matchPattern(domain, pattern) {
    if (!domain || !pattern) return false;
    const d = domain.toLowerCase();
    const p = pattern.toLowerCase();
    if (p === d) return true;
    if (p.startsWith('*.')) {
      const suffix = p.slice(2);
      return d.endsWith('.' + suffix) || d === suffix;
    }
    return false;
  }

  findMatchingAllowlist(domain) {
    const entries = db.listAllowlistEntries();
    for (const e of entries) {
      if (EnforcementManager.matchPattern(domain, e.pattern)) {
        return e;
      }
    }
    return null;
  }

  findMatchingBlocklist(domain) {
    const entries = db.listBlocklistEntries(false);
    for (const e of entries) {
      if (EnforcementManager.matchPattern(domain, e.pattern)) {
        return e;
      }
    }
    return null;
  }

  findMatchingRatelimit(domain) {
    const rules = db.listRatelimitRules();
    for (const r of rules) {
      if (EnforcementManager.matchPattern(domain, r.pattern)) {
        return r;
      }
    }
    return null;
  }

  recordIntercept(type, domain, pattern) {
    if (type === 'block') {
      this.stats.blockCount += 1;
      this.stats.perDomainBlockCount.set(
        domain,
        (this.stats.perDomainBlockCount.get(domain) || 0) + 1
      );
    } else if (type === 'ratelimit') {
      this.stats.rateLimitCount += 1;
      this.stats.perDomainRateLimitCount.set(
        domain,
        (this.stats.perDomainRateLimitCount.get(domain) || 0) + 1
      );
    } else if (type === 'allow') {
      this.stats.allowCount += 1;
      this.stats.perDomainAllowCount.set(
        domain,
        (this.stats.perDomainAllowCount.get(domain) || 0) + 1
      );
    }
    this.stats.recentIntercepts.push({
      type,
      domain,
      pattern,
      timestamp: Date.now(),
    });
  }

  checkRatelimitAndRecord(domain, rule) {
    const now = Date.now();
    const windowMs = rule.window_seconds * 1000;
    let entry = this.rateLimitCounters.get(domain);
    if (!entry || entry.matchedPattern !== rule.pattern) {
      entry = { matchedPattern: rule.pattern, timestamps: [] };
      this.rateLimitCounters.set(domain, entry);
    }
    entry.timestamps = entry.timestamps.filter((t) => now - t < windowMs);
    if (entry.timestamps.length >= rule.max_requests) {
      const earliestInWindow = entry.timestamps[0];
      const retryAfterSeconds = Math.ceil(
        (earliestInWindow + windowMs - now) / 1000
      );
      return {
        blocked: true,
        retryAfter: Math.max(1, retryAfterSeconds),
        maxRequests: rule.max_requests,
        windowSeconds: rule.window_seconds,
      };
    }
    entry.timestamps.push(now);
    return { blocked: false };
  }

  checkQuery(domain) {
    if (!domain) return { action: 'pass' };

    const allowMatch = this.findMatchingAllowlist(domain);
    if (allowMatch) {
      this.recordIntercept('allow', domain, allowMatch.pattern);
      return { action: 'allow', matchedPattern: allowMatch.pattern };
    }

    const blockMatch = this.findMatchingBlocklist(domain);
    if (blockMatch) {
      this.recordIntercept('block', domain, blockMatch.pattern);
      return {
        action: 'block',
        matchedPattern: blockMatch.pattern,
        reason: blockMatch.reason || 'blocked',
      };
    }

    const rateMatch = this.findMatchingRatelimit(domain);
    if (rateMatch) {
      const rlResult = this.checkRatelimitAndRecord(domain, rateMatch);
      if (rlResult.blocked) {
        this.recordIntercept('ratelimit', domain, rateMatch.pattern);
        return {
          action: 'ratelimit',
          matchedPattern: rateMatch.pattern,
          maxRequests: rlResult.maxRequests,
          windowSeconds: rlResult.windowSeconds,
          retryAfter: rlResult.retryAfter,
        };
      }
    }

    return { action: 'pass' };
  }

  getEnforcementStats() {
    const now = Date.now();
    const topBlocked = Array.from(this.stats.perDomainBlockCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([domain, count]) => ({ domain, count }));

    const topRateLimited = Array.from(
      this.stats.perDomainRateLimitCount.entries()
    )
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([domain, count]) => ({ domain, count }));

    const minuteBuckets = {};
    for (let i = 59; i >= 0; i--) {
      const bucketTime = now - i * 60 * 1000;
      const key = new Date(bucketTime).toISOString().slice(0, 16) + ':00';
      minuteBuckets[key] = { block: 0, ratelimit: 0, allow: 0 };
    }

    for (const intercept of this.stats.recentIntercepts) {
      const key = new Date(intercept.timestamp).toISOString().slice(0, 16) + ':00';
      if (minuteBuckets[key]) {
        minuteBuckets[key][intercept.type] =
          (minuteBuckets[key][intercept.type] || 0) + 1;
      }
    }

    const trend = Object.entries(minuteBuckets).map(([minute, counts]) => ({
      minute,
      ...counts,
    }));

    return {
      totals: {
        blockCount: this.stats.blockCount,
        rateLimitCount: this.stats.rateLimitCount,
        allowCount: this.stats.allowCount,
      },
      topBlocked,
      topRateLimited,
      trend,
    };
  }
}

module.exports = { EnforcementManager };
