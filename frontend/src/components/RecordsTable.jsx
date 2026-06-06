import React from 'react';

export default function RecordsTable({ records }) {
  if (!records || records.length === 0) {
    return <div className="empty-state">该 zone 暂无记录</div>;
  }

  return (
    <table className="records-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Value</th>
          <th>TTL</th>
        </tr>
      </thead>
      <tbody>
        {records.map((r) => (
          <tr key={r.id}>
            <td title={r.name}>{r.name}</td>
            <td>{r.type}</td>
            <td title={r.value}>{r.value}</td>
            <td>{r.ttl}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
