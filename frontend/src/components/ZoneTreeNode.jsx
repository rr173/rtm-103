import React, { useState } from 'react';

export default function ZoneTreeNode({ zone, children, selectedZoneId, onSelect }) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = children && children.length > 0;
  const isSelected = selectedZoneId === zone.id;
  const recordCount = (zone.records || []).length;

  const displayName = zone.name === '.' ? '.' : zone.name;

  return (
    <div className="zone-node">
      <div
        className={`zone-node-row ${isSelected ? 'selected' : ''}`}
        onClick={() => onSelect(zone)}
      >
        <span
          className={`zone-toggle ${!hasChildren ? 'empty' : ''}`}
          onClick={(e) => {
            if (hasChildren) {
              e.stopPropagation();
              setExpanded(!expanded);
            }
          }}
        >
          {hasChildren ? (expanded ? '▼' : '▶') : ''}
        </span>
        <span className="zone-name">{displayName}</span>
        <span className="zone-badge">{recordCount}</span>
      </div>
      {hasChildren && expanded && (
        <div className="zone-children">
          {children.map((child) => (
            <ZoneTreeNode
              key={child.zone.id}
              zone={child.zone}
              children={child.children}
              selectedZoneId={selectedZoneId}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  );
}
