import React, { useState, useEffect, useCallback } from 'react';
import StatsBar from './components/StatsBar.jsx';
import ZonePanel from './components/ZonePanel.jsx';
import ResolvePanel from './components/ResolvePanel.jsx';
import PreviewWorkbench from './components/PreviewWorkbench.jsx';
import { api } from './api/client.js';

const NAV_ITEMS = [
  { id: 'zones', label: 'Zone管理', icon: '📁' },
  { id: 'resolve', label: '域名解析', icon: '🔍' },
  { id: 'preview', label: '变更预演', icon: '🔬' },
];

export default function App() {
  const [activeModule, setActiveModule] = useState('zones');
  const [zones, setZones] = useState([]);
  const [selectedZone, setSelectedZone] = useState(null);

  const loadZones = useCallback(async () => {
    try {
      const data = await api.getZones();
      setZones(data);
      if (selectedZone) {
        const updated = data.find((z) => z.id === selectedZone.id);
        if (updated) setSelectedZone(updated);
      }
    } catch (e) {
      console.error('Failed to load zones:', e);
    }
  }, [selectedZone]);

  useEffect(() => {
    loadZones();
  }, [loadZones]);

  const handleSelectZone = (zone) => {
    setSelectedZone(zone);
  };

  const renderContent = () => {
    if (activeModule === 'preview') {
      return <PreviewWorkbench />;
    }

    return (
      <div className="main-layout">
        <ZonePanel
          zones={zones}
          selectedZone={selectedZone}
          onSelectZone={handleSelectZone}
          onZoneUpdated={loadZones}
        />
        <ResolvePanel />
      </div>
    );
  };

  return (
    <div className="app">
      <div className="app-header">
        <div className="app-title">
          <span style={{ fontSize: '24px', marginRight: '8px' }}>🌐</span>
          <h1>DNS 管理控制台</h1>
        </div>
        <nav className="app-nav">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveModule(item.id)}
              className={`nav-item ${activeModule === item.id ? 'active' : ''}`}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </button>
          ))}
        </nav>
      </div>
      {activeModule !== 'preview' && <StatsBar />}
      {renderContent()}
    </div>
  );
}
