import React, { useEffect, useState } from 'react';
import { api } from '../api/client.js';
import StatCard from './StatCard.jsx';
import RingProgress from './RingProgress.jsx';

export default function StatsBar() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await api.getStats();
        setStats(data);
      } catch (e) {
        console.error('Failed to load stats:', e);
      }
    };
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  if (!stats) return <div className="stats-bar" />;

  const cacheHitRate = parseFloat(stats.cacheHitRate) || 0;
  const resultCounts = stats.resultCounts || {};

  return (
    <div className="stats-bar">
      <StatCard
        label="总查询数"
        value={stats.totalQueries || 0}
        icon="Q"
        iconBg="#3b82f6"
      />
      <StatCard label="缓存命中率">
        <RingProgress value={cacheHitRate} />
      </StatCard>
      <StatCard
        label="SUCCESS"
        value={resultCounts.SUCCESS || 0}
        icon="✓"
        iconBg="#10b981"
      />
      <StatCard
        label="NXDOMAIN"
        value={resultCounts.NXDOMAIN || 0}
        icon="!"
        iconBg="#f59e0b"
      />
      <StatCard
        label="SERVFAIL"
        value={resultCounts.SERVFAIL || 0}
        icon="×"
        iconBg="#ef4444"
      />
      <StatCard
        label="LOOP"
        value={resultCounts.LOOP || 0}
        icon="↻"
        iconBg="#8b5cf6"
      />
    </div>
  );
}
