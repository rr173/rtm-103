import React, { useEffect, useState, useRef } from 'react';

export default function StatCard({ label, value, icon, iconBg, children }) {
  const [bump, setBump] = useState(false);
  const prevRef = useRef(value);

  useEffect(() => {
    if (prevRef.current !== value) {
      setBump(true);
      const t = setTimeout(() => setBump(false), 300);
      prevRef.current = value;
      return () => clearTimeout(t);
    }
  }, [value]);

  return (
    <div className="stat-card">
      {children ? (
        children
      ) : (
        <div className="stat-icon" style={{ background: iconBg || '#3b82f6' }}>
          {icon}
        </div>
      )}
      <div className="stat-content">
        <span className="stat-label">{label}</span>
        <span className={`stat-value ${bump ? 'bump' : ''}`}>{value}</span>
      </div>
    </div>
  );
}
