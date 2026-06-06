import React, { useState } from 'react';
import ZoneTreeNode from './ZoneTreeNode.jsx';
import RecordsTable from './RecordsTable.jsx';
import AddRecordForm from './AddRecordForm.jsx';

function buildZoneTree(zones) {
  const byId = new Map();
  zones.forEach((z) => byId.set(z.id, { zone: z, children: [] }));

  const roots = [];
  zones.forEach((z) => {
    const node = byId.get(z.id);
    if (z.parent_id && byId.has(z.parent_id)) {
      byId.get(z.parent_id).children.push(node);
    } else {
      roots.push(node);
    }
  });

  roots.sort((a, b) => {
    if (a.zone.name === '.') return -1;
    if (b.zone.name === '.') return 1;
    return a.zone.name.localeCompare(b.zone.name);
  });

  roots.forEach((node) => sortChildren(node));
  return roots;
}

function sortChildren(node) {
  node.children.sort((a, b) => a.zone.name.localeCompare(b.zone.name));
  node.children.forEach(sortChildren);
}

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export default function ZonePanel({ zones, selectedZone, onSelectZone, onZoneUpdated }) {
  const tree = React.useMemo(() => buildZoneTree(zones), [zones]);

  return (
    <div className="zone-panel">
      <div className="zone-panel-header">Zone 树</div>
      <div className="zone-tree">
        {tree.map((node) => (
          <ZoneTreeNode
            key={node.zone.id}
            zone={node.zone}
            children={node.children}
            selectedZoneId={selectedZone?.id}
            onSelect={onSelectZone}
          />
        ))}
      </div>
      {selectedZone && (
        <div className="zone-detail">
          <div className="zone-detail-title">{selectedZone.name === '.' ? '根 zone (.)' : selectedZone.name}</div>
          <div className="zone-meta">
            <span>Serial: <strong>{selectedZone.serial}</strong></span>
            <span>变更: <strong>{formatTime(selectedZone.last_change_at)}</strong></span>
          </div>
          <RecordsTable records={selectedZone.records} />
        </div>
      )}
      <AddRecordForm
        zones={zones}
        selectedZoneId={selectedZone?.id}
        onAdded={onZoneUpdated}
      />
    </div>
  );
}
