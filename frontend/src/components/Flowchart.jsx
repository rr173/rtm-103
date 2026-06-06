import React, { useEffect, useState, useMemo } from 'react';

const NODE_WIDTH = 260;
const NODE_HEIGHT = 70;
const NODE_GAP = 80;
const ANSWER_GAP = 70;
const ANSWER_HEIGHT = 90;
const NODE_DELAY = 200;
const SVG_PADDING = 30;

function isCnameNode(trace) {
  if (!trace.records || trace.records.length === 0) return false;
  const firstType = trace.records[0].type;
  return firstType === 'CNAME';
}

function getRecordSummary(records) {
  if (!records || records.length === 0) return '(无记录)';
  const r = records[0];
  const val = r.value.length > 30 ? r.value.slice(0, 27) + '...' : r.value;
  return `${r.type}: ${val}`;
}

export default function Flowchart({ result }) {
  const [visibleCount, setVisibleCount] = useState(0);

  useEffect(() => {
    if (!result) return;
    setVisibleCount(0);

    let totalNodes;
    if (result.cached) {
      totalNodes = 2;
    } else {
      totalNodes = (result.trace?.length || 0) + 1;
    }

    let count = 0;
    const timer = setInterval(() => {
      count += 1;
      setVisibleCount(count);
      if (count >= totalNodes) clearInterval(timer);
    }, NODE_DELAY);

    return () => clearInterval(timer);
  }, [result]);

  const layout = useMemo(() => {
    if (!result) return null;

    let nodes = [];
    let edges = [];

    if (result.cached) {
      nodes.push({
        id: 'cache',
        x: SVG_PADDING,
        y: SVG_PADDING,
        type: 'cache-hit',
        title: 'Cache Hit',
        subtitle: '命中本地缓存',
      });

      nodes.push({
        id: 'answer',
        x: SVG_PADDING,
        y: SVG_PADDING + NODE_HEIGHT + ANSWER_GAP,
        type: result.status === 'SUCCESS' ? 'answer' : 'error',
        title: result.status,
        value: result.answer?.map((a) => `${a.name} → ${a.value}`).join(', ') || result.message || '',
        subtitle: `耗时 ${result.elapsedMs || 0}ms`,
      });

      edges.push({
        id: 'e-0',
        from: 0,
        to: 1,
        type: 'normal',
      });
    } else {
      const traces = result.trace || [];

      traces.forEach((t, i) => {
        const cname = isCnameNode(t);
        nodes.push({
          id: `n-${i}`,
          x: SVG_PADDING,
          y: SVG_PADDING + i * (NODE_HEIGHT + NODE_GAP),
          type: cname ? 'cname' : 'normal',
          title: t.zone === '.' ? '(根) .' : t.zone,
          subtitle: getRecordSummary(t.records),
          delegationTo: t.delegationTo,
        });
      });

      const answerY = SVG_PADDING + traces.length * (NODE_HEIGHT + NODE_GAP);
      const isError = result.status !== 'SUCCESS';

      nodes.push({
        id: 'answer',
        x: SVG_PADDING,
        y: answerY,
        type: isError ? 'error' : 'answer',
        title: isError ? result.status : 'Answer',
        value: isError
          ? (result.message || result.status)
          : (result.answer?.map((a) => `${a.name} → ${a.value}`).join('  |  ') || '(空)'),
        subtitle: isError ? '' : `耗时 ${result.elapsedMs || 0}ms, ${result.hops || 0} 跳`,
      });

      for (let i = 0; i < traces.length; i++) {
        const isCname = isCnameNode(traces[i]);
        const nextIsRoot = i + 1 < traces.length && (traces[i + 1].zone === '.' || traces[i + 1].zone === '');
        const cnameEdge = isCname && nextIsRoot;

        edges.push({
          id: `e-${i}`,
          from: i,
          to: i + 1,
          type: cnameEdge ? 'cname' : 'normal',
          label: cnameEdge ? `CNAME → ${traces[i].records[0]?.value || ''}` : (traces[i].delegationTo ? `→ ${traces[i].delegationTo}` : ''),
        });
      }

      if (traces.length > 0) {
        const lastIdx = traces.length - 1;
        const isCname = isCnameNode(traces[lastIdx]);
        edges.push({
          id: `e-${traces.length}`,
          from: traces.length,
          to: traces.length + 1,
          type: isCname ? 'cname' : 'normal',
        });
      }
    }

    const width = NODE_WIDTH + SVG_PADDING * 2;
    const height = (nodes[nodes.length - 1]?.y || 0) +
      (nodes[nodes.length - 1]?.type === 'answer' || nodes[nodes.length - 1]?.type === 'error' ? ANSWER_HEIGHT : NODE_HEIGHT) +
      SVG_PADDING;

    return { nodes, edges, width, height };
  }, [result]);

  if (!result || !layout) {
    return (
      <div className="flowchart-container">
        <div className="flowchart-empty">
          <div className="empty-icon">🌐</div>
          <div className="empty-text">输入域名并点击"解析"查看递归解析流程</div>
        </div>
      </div>
    );
  }

  const { nodes, edges, width, height } = layout;

  return (
    <div className="flowchart-container">
      <svg
        className="flowchart-svg"
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
      >
        <defs>
          <marker
            id="arrow-normal"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" className="flow-edge-arrow" />
          </marker>
          <marker
            id="arrow-cname"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" className="flow-edge-arrow" />
          </marker>
        </defs>

        {edges.map((edge, i) => {
          const fromNode = nodes[edge.from];
          const toNode = nodes[edge.to];
          if (!fromNode || !toNode) return null;

          const fromH = (fromNode.type === 'answer' || fromNode.type === 'error') ? ANSWER_HEIGHT : NODE_HEIGHT;
          const x1 = fromNode.x + NODE_WIDTH / 2;
          const y1 = fromNode.y + fromH;
          const x2 = toNode.x + NODE_WIDTH / 2;
          const y2 = toNode.y;
          const midY = (y1 + y2) / 2;

          const isVisible = i < visibleCount;
          const edgeClass = `flow-edge ${edge.type === 'cname' ? 'cname' : ''} ${isVisible ? 'visible' : ''}`;
          const markerId = edge.type === 'cname' ? 'arrow-cname' : 'arrow-normal';

          return (
            <g key={edge.id}>
              <path
                className={edgeClass}
                d={`M ${x1} ${y1} L ${x1} ${midY} L ${x2} ${midY} L ${x2} ${y2 - 5}`}
                markerEnd={`url(#${markerId})`}
              />
              {edge.label && isVisible && (
                <text
                  x={x1 + 10}
                  y={midY - 4}
                  className={`flow-edge-label ${edge.type === 'cname' ? 'cname' : ''}`}
                >
                  {edge.label}
                </text>
              )}
            </g>
          );
        })}

        {nodes.map((node, i) => {
          const isAnswer = node.type === 'answer' || node.type === 'error';
          const h = isAnswer ? ANSWER_HEIGHT : NODE_HEIGHT;
          const isVisible = i < visibleCount;
          const nodeClass = `flow-node ${node.type} ${isVisible ? 'visible' : ''}`;

          return (
            <g
              key={node.id}
              className={nodeClass}
              transform={`translate(${node.x}, ${node.y})`}
            >
              {isAnswer ? (
                <>
                  <rect
                    className="answer-card-rect"
                    width={NODE_WIDTH}
                    height={h}
                  />
                  <text className="answer-card-title" x={16} y={26}>
                    {node.title}
                  </text>
                  <text className="answer-card-value" x={16} y={52}>
                    {node.value.length > 36 ? node.value.slice(0, 33) + '...' : node.value}
                  </text>
                  {node.subtitle && (
                    <text className="answer-card-sub" x={16} y={74}>
                      {node.subtitle}
                    </text>
                  )}
                </>
              ) : (
                <>
                  <rect
                    className="flow-node-rect"
                    width={NODE_WIDTH}
                    height={h}
                  />
                  <text className="flow-node-title" x={14} y={28}>
                    {node.title}
                  </text>
                  <text className="flow-node-sub" x={14} y={48}>
                    {node.subtitle}
                  </text>
                  {node.delegationTo && node.type !== 'cname' && (
                    <text className="flow-node-sub" x={14} y={64} fill="#1d4ed8">
                      委派 → {node.delegationTo}
                    </text>
                  )}
                </>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
