import React, { useState, useEffect, useCallback } from 'react';
import StatsBar from './components/StatsBar.jsx';
import ZonePanel from './components/ZonePanel.jsx';
import ResolvePanel from './components/ResolvePanel.jsx';
import { api } from './api/client.js';

export default function App() {
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

  return (
    <div className="app">
      <StatsBar />
      <div className="main-layout">
        <ZonePanel
          zones={zones}
          selectedZone={selectedZone}
          onSelectZone={handleSelectZone}
          onZoneUpdated={loadZones}
        />
        <ResolvePanel />
      </div>
    </div>
  );
}
