const db = require('../db/database');

class AnalysisDetector {
  constructor(statsLogger) {
    this.statsLogger = statsLogger;
    this.extendedLogs = [];
    this.maxLogs = 2000;
  }

  recordQueryExtended(info) {
    this.extendedLogs.unshift({
      timestamp: Date.now(),
      name: info.name,
      type: info.type,
      resultCode: info.resultCode,
      hops: info.hops || 0,
      answerSize: info.answerSize || 0,
      cached: info.cached || false,
      elapsedMs: info.elapsedMs || 0,
    });
    if (this.extendedLogs.length > this.maxLogs) {
      this.extendedLogs.length = this.maxLogs;
    }
  }

  static shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      freq[c] = (freq[c] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  static getLongestLabel(domain) {
    if (!domain) return { label: '', length: 0, entropy: 0 };
    const labels = domain.split('.').filter((l) => l.length > 0);
    if (labels.length === 0) return { label: '', length: 0, entropy: 0 };
    let longest = labels[0];
    for (const l of labels) {
      if (l.length > longest.length) longest = l;
    }
    return {
      label: longest,
      length: longest.length,
      entropy: AnalysisDetector.shannonEntropy(longest),
    };
  }

  static getParentDomain(domain) {
    if (!domain) return '';
    const labels = domain.split('.').filter((l) => l.length > 0);
    if (labels.length <= 2) return domain;
    return labels.slice(-2).join('.');
  }

  getLogsInWindow(windowMinutes = 5) {
    const cutoff = Date.now() - windowMinutes * 60 * 1000;
    const fromExtended = this.extendedLogs.filter((l) => l.timestamp >= cutoff);
    if (fromExtended.length > 0) return fromExtended;

    return this.statsLogger
      .getLogs(this.statsLogger.maxLogs)
      .filter((l) => l.timestamp >= cutoff)
      .map((l) => ({
        ...l,
        answerSize: l.answerSize || (l.resultCode === 'SUCCESS' ? 2 : 0),
      }));
  }

  computeWindowStats(windowMinutes = 5) {
    const logs = this.getLogsInWindow(windowMinutes);
    const domainStats = new Map();
    let totalQueries = 0;
    let totalNxdomain = 0;
    let totalHops = 0;

    for (const log of logs) {
      totalQueries += 1;
      totalHops += log.hops || 0;
      if (log.resultCode === 'NXDOMAIN') totalNxdomain += 1;

      const key = log.name.toLowerCase();
      if (!domainStats.has(key)) {
        domainStats.set(key, {
          domain: key,
          count: 0,
          nxdomainCount: 0,
          totalHops: 0,
          totalAnswerSize: 0,
          firstSeen: log.timestamp,
          lastSeen: log.timestamp,
        });
      }
      const s = domainStats.get(key);
      s.count += 1;
      if (log.resultCode === 'NXDOMAIN') s.nxdomainCount += 1;
      s.totalHops += log.hops || 0;
      s.totalAnswerSize += log.answerSize || 0;
      if (log.timestamp < s.firstSeen) s.firstSeen = log.timestamp;
      if (log.timestamp > s.lastSeen) s.lastSeen = log.timestamp;
    }

    const perDomain = [];
    for (const [, s] of domainStats) {
      perDomain.push({
        domain: s.domain,
        queryCount: s.count,
        nxdomainCount: s.nxdomainCount,
        avgHops: s.count > 0 ? s.totalHops / s.count : 0,
        avgAnswerSize: s.count > 0 ? s.totalAnswerSize / s.count : 0,
        firstSeen: s.firstSeen,
        lastSeen: s.lastSeen,
      });
    }
    perDomain.sort((a, b) => b.queryCount - a.queryCount);

    return {
      windowMinutes,
      totalQueries,
      uniqueDomains: domainStats.size,
      nxdomainRatio: totalQueries > 0 ? totalNxdomain / totalQueries : 0,
      avgHops: totalQueries > 0 ? totalHops / totalQueries : 0,
      topDomains: perDomain.slice(0, 5),
      perDomain,
      rawLogs: logs,
    };
  }

  detectAmplification(windowStats, thresholds) {
    const alerts = [];
    const countThreshold = thresholds.amplificationCount;
    const sizeThreshold = thresholds.amplificationResponseSize;

    for (const s of windowStats.perDomain) {
      if (s.queryCount > countThreshold && s.avgAnswerSize > sizeThreshold) {
        const severity = s.queryCount > 50 ? 'high' : 'medium';
        alerts.push({
          type: 'amplification',
          severity,
          data: {
            domain: s.domain,
            queryCount: s.queryCount,
            avgResponseSize: Number(s.avgAnswerSize.toFixed(2)),
            firstSeen: s.firstSeen,
            lastSeen: s.lastSeen,
          },
        });
      }
    }
    return alerts;
  }

  detectProbe(windowStats, thresholds) {
    const alerts = [];
    const ratioThreshold = thresholds.probeNxdomainRatio;
    const subdomainThreshold = thresholds.probeSubdomainCount;
    const ratio = windowStats.nxdomainRatio;

    if (ratio <= ratioThreshold) return alerts;

    const nxLogs = windowStats.rawLogs.filter((l) => l.resultCode === 'NXDOMAIN');
    const byParent = new Map();

    for (const log of nxLogs) {
      const parent = AnalysisDetector.getParentDomain(log.name);
      if (!byParent.has(parent)) {
        byParent.set(parent, new Set());
      }
      byParent.get(parent).add(log.name.toLowerCase());
    }

    for (const [parent, subdomains] of byParent) {
      if (subdomains.size > subdomainThreshold) {
        const parentNxCount = [...subdomains].reduce(
          (acc, sd) =>
            acc +
            (windowStats.perDomain.find((d) => d.domain === sd)?.nxdomainCount || 0),
          0
        );
        const severity = subdomains.size > 30 ? 'high' : 'medium';
        let first = Infinity;
        let last = 0;
        for (const log of nxLogs) {
          if (AnalysisDetector.getParentDomain(log.name) === parent) {
            if (log.timestamp < first) first = log.timestamp;
            if (log.timestamp > last) last = log.timestamp;
          }
        }
        alerts.push({
          type: 'probe',
          severity,
          data: {
            parentDomain: parent,
            subdomainCount: subdomains.size,
            nxdomainRatio: Number(ratio.toFixed(4)),
            firstSeen: first,
            lastSeen: last,
          },
        });
      }
    }
    return alerts;
  }

  detectTunneling(windowStats, thresholds) {
    const alerts = [];
    const lengthThreshold = thresholds.tunnelLabelLength;
    const entropyThreshold = thresholds.tunnelEntropy;
    const seen = new Set();

    for (const log of windowStats.rawLogs) {
      const domain = log.name.toLowerCase();
      if (seen.has(domain)) continue;
      seen.add(domain);

      const info = AnalysisDetector.getLongestLabel(domain);
      if (info.length > lengthThreshold || info.entropy > entropyThreshold) {
        const severity = info.entropy > 4.0 ? 'high' : 'medium';
        alerts.push({
          type: 'tunnel',
          severity,
          data: {
            domain,
            longestLabel: info.label,
            labelLength: info.length,
            entropy: Number(info.entropy.toFixed(4)),
            firstSeen: log.timestamp,
            lastSeen: log.timestamp,
          },
        });
      }
    }
    return alerts;
  }

  runScan(windowMinutes = 5) {
    const startTime = Date.now();
    const thresholds = db.getThresholds() || {
      amplificationCount: 20,
      amplificationResponseSize: 3,
      probeNxdomainRatio: 0.4,
      probeSubdomainCount: 10,
      tunnelLabelLength: 30,
      tunnelEntropy: 3.5,
    };

    const stats = this.computeWindowStats(windowMinutes);
    const amplificationAlerts = this.detectAmplification(stats, thresholds);
    const probeAlerts = this.detectProbe(stats, thresholds);
    const tunnelAlerts = this.detectTunneling(stats, thresholds);

    const allNewAlerts = [];
    for (const a of [...amplificationAlerts, ...probeAlerts, ...tunnelAlerts]) {
      const saved = db.createAlert(a.type, a.severity, a.data);
      allNewAlerts.push(saved);
    }

    const elapsed = Date.now() - startTime;

    return {
      windowMinutes,
      scannedLogs: stats.totalQueries,
      elapsedMs: elapsed,
      newAlerts: allNewAlerts.length,
      alerts: allNewAlerts,
      summary: {
        amplification: amplificationAlerts.length,
        probe: probeAlerts.length,
        tunnel: tunnelAlerts.length,
      },
    };
  }
}

module.exports = { AnalysisDetector };
