import React, { useState } from 'react';
import { api } from '../api/client.js';

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'];

export default function QueryBar({ onResult }) {
  const [domain, setDomain] = useState('');
  const [type, setType] = useState('A');
  const [loading, setLoading] = useState(false);

  const handleResolve = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const result = await api.resolve(domain.trim(), type);
      onResult(result);
    } catch (err) {
      alert('解析失败: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleResolve();
  };

  return (
    <div className="query-bar">
      <input
        type="text"
        placeholder="输入域名，例如 www.example.com"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        onKeyDown={handleKeyDown}
      />
      <select value={type} onChange={(e) => setType(e.target.value)}>
        {RECORD_TYPES.map((t) => (
          <option key={t} value={t}>{t}</option>
        ))}
      </select>
      <button onClick={handleResolve} disabled={loading || !domain.trim()}>
        {loading ? '解析中...' : '解析'}
      </button>
    </div>
  );
}
