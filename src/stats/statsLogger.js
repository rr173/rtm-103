const RESULT_CODES = ['SUCCESS', 'NXDOMAIN', 'SERVFAIL', 'LOOP', 'TIMEOUT', 'CNAME_LOOP', 'MAX_DEPTH'];

class StatsLogger {
  constructor() {
    this.totalQueries = 0;
    this.cacheHits = 0;
    this.resultCounts = Object.fromEntries(RESULT_CODES.map((c) => [c, 0]));
    this.totalHops = 0;
    this.queryCounts = new Map();
    this.logs = [];
    this.maxLogs = 1000;
  }

  recordQuery({ name, type, resultCode, hops, cached, elapsedMs }) {
    this.totalQueries += 1;
    if (cached) this.cacheHits += 1;
    if (this.resultCounts[resultCode] !== undefined) {
      this.resultCounts[resultCode] += 1;
    }
    this.totalHops += hops;

    const qkey = `${name.toLowerCase()}:${type.toUpperCase()}`;
    this.queryCounts.set(qkey, (this.queryCounts.get(qkey) || 0) + 1);

    this.logs.unshift({
      timestamp: Date.now(),
      name,
      type,
      resultCode,
      hops,
      cached,
      elapsedMs,
    });
    if (this.logs.length > this.maxLogs) {
      this.logs.pop();
    }
  }

  getStats() {
    const topQueries = [...this.queryCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([key, count]) => {
        const [name, type] = key.split(':');
        return { name, type, count };
      });

    return {
      totalQueries: this.totalQueries,
      cacheHitRate: this.totalQueries > 0 ? (this.cacheHits / this.totalQueries).toFixed(4) : 0,
      cacheHits: this.cacheHits,
      resultCounts: { ...this.resultCounts },
      avgHops: this.totalQueries > 0 ? (this.totalHops / this.totalQueries).toFixed(2) : 0,
      topQueries,
    };
  }

  getLogs(limit = 50) {
    return this.logs.slice(0, Math.min(limit, this.logs.length));
  }
}

module.exports = { StatsLogger, RESULT_CODES };
