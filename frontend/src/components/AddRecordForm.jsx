import React, { useState } from 'react';
import { api } from '../api/client.js';

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR'];

export default function AddRecordForm({ zones, selectedZoneId, onAdded }) {
  const [zoneId, setZoneId] = useState(selectedZoneId || '');
  const [name, setName] = useState('');
  const [type, setType] = useState('A');
  const [value, setValue] = useState('');
  const [ttl, setTtl] = useState('3600');
  const [submitting, setSubmitting] = useState(false);

  React.useEffect(() => {
    if (selectedZoneId) setZoneId(selectedZoneId);
  }, [selectedZoneId]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!zoneId || !name.trim() || !value.trim()) return;

    setSubmitting(true);
    try {
      await api.addRecord(zoneId, {
        name: name.trim(),
        type: type.toUpperCase(),
        value: value.trim(),
        ttl: parseInt(ttl, 10) || 3600,
      });
      setName('');
      setValue('');
      setTtl('3600');
      if (onAdded) onAdded();
    } catch (err) {
      alert('添加记录失败: ' + err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className="add-record-form" onSubmit={handleSubmit}>
      <h4>快速添加记录</h4>
      <div className="form-row">
        <select value={zoneId} onChange={(e) => setZoneId(e.target.value)}>
          <option value="">选择 zone</option>
          {zones.map((z) => (
            <option key={z.id} value={z.id}>
              {z.name === '.' ? '(根)' : z.name}
            </option>
          ))}
        </select>
        <select value={type} onChange={(e) => setType(e.target.value)}>
          {RECORD_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>
      <div className="form-row">
        <input
          type="text"
          placeholder="Name (e.g. www)"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          type="text"
          placeholder="TTL"
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
          style={{ flex: '0 0 80px' }}
        />
      </div>
      <div className="form-row">
        <input
          type="text"
          placeholder="Value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
      </div>
      <button type="submit" disabled={submitting || !zoneId}>
        {submitting ? '添加中...' : '添加记录'}
      </button>
    </form>
  );
}
