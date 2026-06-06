import React, { useState } from 'react';
import QueryBar from './QueryBar.jsx';
import Flowchart from './Flowchart.jsx';

export default function ResolvePanel() {
  const [result, setResult] = useState(null);

  return (
    <div className="resolve-panel">
      <QueryBar onResult={setResult} />
      <Flowchart result={result} />
    </div>
  );
}
