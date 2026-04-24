import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { DataSet, Network } from 'vis-network/standalone';
import { apiUrl } from '../api';

const NODE_COLORS = {
  User: { background: '#0f766e', border: '#0b5d56' },
  Window: { background: '#2563eb', border: '#1d4ed8' },
  DetectionPattern: { background: '#d97706', border: '#b45309' },
  MITRETechnique: { background: '#7c3aed', border: '#6d28d9' },
  Playbook: { background: '#dc2626', border: '#b91c1c' },
  default: { background: '#64748b', border: '#475569' },
};

const EDGE_COLORS = {
  HAD_WINDOW: '#94a3b8',
  TRIGGERS_INDICATOR: '#1d4f91',
  DETECTED_BY: '#0f766e',
  TRIGGERS: '#111827',
  default: '#64748b',
};

function parseMaybeJson(value) {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function formatPrimitive(value) {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') {
    if (Number.isFinite(value) && value > 0 && value < 1) return value.toFixed(3);
    return String(value);
  }
  if (Array.isArray(value)) return value.length ? value.join(', ') : '-';
  if (typeof value === 'object') return 'Available';
  return String(value);
}

function mapNodeForAnalyst(node) {
  if (!node) {
    return {
      heading: 'No node selected',
      subheading: 'Click a node in the graph to inspect it.',
      facts: [],
      observations: [],
    };
  }

  const props = node.properties || {};
  const parsedIndicators = parseMaybeJson(props.behavioral_indicators);

  if (node.type === 'Window') {
    const score = Number(props.ensemble_score ?? props.score ?? 0);
    const isLikelyAttack = score >= 0.85 || props.is_attack === true;
    return {
      heading: 'Window Risk Snapshot',
      subheading: isLikelyAttack
        ? 'This time window looks strongly suspicious and should be investigated first.'
        : 'This window shows moderate or low risk, but still contributes context for surrounding nodes.',
      facts: [
        { label: 'User', value: props.user_name || node.key },
        { label: 'Window Start', value: props.window_start || props.window || node.key },
        { label: 'Ensemble Score', value: formatPrimitive(score || props.ensemble_score) },
        { label: 'Attack Type', value: props.attack_name || 'Unknown' },
        { label: 'Known Attack', value: formatPrimitive(props.is_attack) },
      ],
      observations: [
        isLikelyAttack
          ? 'Prioritize containment and triage actions from linked playbooks.'
          : 'Use linked indicators and techniques to validate if this is escalation or noise.',
        'Double-click this node to pull adjacent entities and expand context.',
      ],
    };
  }

  if (node.type === 'DetectionPattern') {
    const severity = String(props.severity || 'Unknown');
    const techniques = parseMaybeJson(props.techniques_detected);
    const playbooks = parseMaybeJson(props.triggers_playbook);
    const indicatorKeys =
      parsedIndicators && typeof parsedIndicators === 'object' && !Array.isArray(parsedIndicators)
        ? Object.keys(parsedIndicators)
        : [];

    return {
      heading: 'Detection Logic Overview',
      subheading: `Pattern ${props.id || node.key} represents a ${severity.toLowerCase()} severity behavioral rule.`,
      facts: [
        { label: 'Pattern', value: props.name || node.key },
        { label: 'Severity', value: severity },
        { label: 'Window (min)', value: formatPrimitive(props.time_window_minutes) },
        { label: 'Anomaly Threshold', value: formatPrimitive(props.anomaly_score_threshold) },
        { label: 'MITRE Links', value: formatPrimitive(techniques) },
        { label: 'Playbooks', value: formatPrimitive(playbooks) },
      ],
      observations: [
        indicatorKeys.length
          ? `Behavioral checks focus on: ${indicatorKeys.slice(0, 4).join(', ')}${indicatorKeys.length > 4 ? '...' : ''}.`
          : 'Behavioral indicators are available but not fully structured.',
        'Use route trace to see how this pattern connects to techniques and response actions.',
      ],
    };
  }

  if (node.type === 'MITRETechnique') {
    return {
      heading: 'MITRE Technique Context',
      subheading: 'This node ties graph signals to ATTACK behavior for analyst reporting and prioritization.',
      facts: [
        { label: 'Technique ID', value: props.technique_id || node.key },
        { label: 'Name', value: props.name || props.technique_name || '-' },
        { label: 'Tactic', value: formatPrimitive(props.tactic || props.tactics) },
        { label: 'Data Sources', value: formatPrimitive(props.data_sources) },
      ],
      observations: [
        'Correlate linked windows to confirm if behavior matches this ATTACK technique.',
        'Use this mapping to explain alerts in analyst-friendly threat language.',
      ],
    };
  }

  if (node.type === 'Playbook') {
    return {
      heading: 'Response Playbook Summary',
      subheading: 'This node provides practical investigation and containment actions.',
      facts: [
        { label: 'Playbook ID', value: props.id || node.key },
        { label: 'Title', value: props.name || 'Incident Playbook' },
        { label: 'Priority', value: formatPrimitive(props.priority || props.severity) },
        { label: 'Owner Team', value: formatPrimitive(props.owner_team) },
      ],
      observations: [
        'Follow this playbook for immediate triage after confirming linked suspicious windows.',
        'Use linked techniques to keep response aligned with adversary behavior.',
      ],
    };
  }

  if (node.type === 'User') {
    return {
      heading: 'User Risk Profile',
      subheading: 'This identity is connected to one or more anomalous behavioral windows.',
      facts: [
        { label: 'User Name', value: props.name || node.key },
        { label: 'Account Type', value: formatPrimitive(props.user_type) },
        { label: 'Department', value: formatPrimitive(props.department) },
      ],
      observations: [
        'Check geographic and API behavior changes across connected windows.',
        'Trace shortest path to identify likely attack progression for this identity.',
      ],
    };
  }

  const primitiveFacts = Object.entries(props)
    .filter(([, v]) => ['string', 'number', 'boolean'].includes(typeof v))
    .slice(0, 8)
    .map(([k, v]) => ({ label: k, value: formatPrimitive(v) }));

  return {
    heading: `${node.type} Details`,
    subheading: 'Entity metadata interpreted for analyst review.',
    facts: primitiveFacts,
    observations: ['Expand neighbors for more context around this entity.'],
  };
}

function KnowledgeGraphView() {
  const canvasRef = useRef(null);
  const networkRef = useRef(null);
  const nodesRef = useRef(new DataSet());
  const edgesRef = useRef(new DataSet());
  const hoverBackupRef = useRef({ nodes: {}, edges: {} });
  const traceBackupRef = useRef({ nodes: {}, edges: {} });

  const [techniques, setTechniques] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [attackTypes, setAttackTypes] = useState([]);
  const [selectedTechnique, setSelectedTechnique] = useState('');
  const [selectedAttack, setSelectedAttack] = useState('');
  const [selectedAlertKey, setSelectedAlertKey] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(false);
  const [pulseSuspicious, setPulseSuspicious] = useState(false);
  const [showEdgeLabels, setShowEdgeLabels] = useState(false);
  const [initialLimit, setInitialLimit] = useState(20);
  const [expandLimit, setExpandLimit] = useState(12);
  const [tracePath, setTracePath] = useState(null);
  const [graphQuery, setGraphQuery] = useState('');
  const [queryingGraph, setQueryingGraph] = useState(false);
  const [querySummary, setQuerySummary] = useState('');
  const [queryInsights, setQueryInsights] = useState([]);
  const [queryExplanation, setQueryExplanation] = useState('');

  const attackTypeOptions = useMemo(() => {
    const values = [
      ...attackTypes,
      ...alerts.map((alert) => alert.attack_name).filter(Boolean),
    ];
    return Array.from(new Set(values)).sort((left, right) => left.localeCompare(right));
  }, [alerts, attackTypes]);

  const techniqueOptions = useMemo(() => {
    return [...techniques]
      .filter((technique) => technique && technique.technique_id)
      .sort((left, right) => {
        const idComparison = String(left.technique_id).localeCompare(String(right.technique_id));
        if (idComparison !== 0) return idComparison;
        return String(left.name || '').localeCompare(String(right.name || ''));
      });
  }, [techniques]);

  const selectedAlert = useMemo(() => {
    if (!selectedAlertKey) return null;
    return alerts.find((a) => `${a.user_name}|${a.window}` === selectedAlertKey) || null;
  }, [alerts, selectedAlertKey]);

  const nodeDetails = useMemo(() => mapNodeForAnalyst(selectedNode), [selectedNode]);

  const getNodeStyle = useCallback((nodeType) => {
    const palette = NODE_COLORS[nodeType] || NODE_COLORS.default;
    const nodeSizes = {
      User: 19,
      Window: 23,
      DetectionPattern: 20,
      MITRETechnique: 21,
      Playbook: 22,
    };
    return {
      shape: 'dot',
      size: nodeSizes[nodeType] || 18,
      color: palette,
      font: {
        color: '#0f172a',
        size: 12,
        face: 'Segoe UI',
        strokeWidth: 3,
        strokeColor: '#ffffff',
      },
      margin: 10,
      borderWidth: 2,
    };
  }, []);

  const clampText = useCallback((value, max = 22) => {
    const text = String(value || '');
    return text.length <= max ? text : `${text.slice(0, max - 1)}...`;
  }, []);

  const compactIdentity = useCallback((value) => {
    const text = String(value || '');
    if (!text) return '-';
    const parts = text.split(/[\\/]/).filter(Boolean);
    const tail = parts[parts.length - 1] || text;
    return clampText(tail, 18);
  }, [clampText]);

  const formatWindowLabel = useCallback((rawValue) => {
    const d = new Date(rawValue);
    if (Number.isNaN(d.getTime())) return clampText(rawValue, 18);
    return d.toLocaleString([], {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  }, [clampText]);

  const formatNodeLabel = useCallback((n) => {
    switch (n.type) {
      case 'User':
        return `User\n${compactIdentity(n.key)}`;
      case 'Window':
        return `Window\n${formatWindowLabel(n.properties?.window_start || n.key)}`;
      case 'DetectionPattern':
        return `Pattern\n${clampText(n.properties?.name || n.key, 20)}`;
      case 'MITRETechnique':
        return `MITRE\n${clampText(n.key, 16)}`;
      case 'Playbook':
        return `Playbook\n${clampText(n.properties?.name || n.key, 18)}`;
      default:
        return clampText(n.label || n.key, 20);
    }
  }, [clampText, compactIdentity, formatWindowLabel]);

  const toVisNode = useCallback((n) => ({
    id: n.id,
    label: formatNodeLabel(n),
    title: `${n.type}\n${n.key}`,
    group: n.type,
    type: n.type,
    key: n.key,
    properties: n.properties || {},
    ...getNodeStyle(n.type),
  }), [formatNodeLabel, getNodeStyle]);

  const toVisEdge = useCallback((e) => ({
    id: e.id,
    from: e.source,
    to: e.target,
    label: showEdgeLabels ? e.type : '',
    arrows: 'to',
    smooth: { enabled: true, type: 'dynamic' },
    color: {
      color: EDGE_COLORS[e.type] || EDGE_COLORS.default,
      opacity: 0.8,
    },
    width: e.type === 'TRIGGERS_INDICATOR' ? 2 : 1,
    type: e.type,
    properties: e.properties || {},
  }), [showEdgeLabels]);

  const mergeGraphData = useCallback((payload) => {
    const nextNodes = (payload?.nodes || []).map(toVisNode);
    const nextEdges = (payload?.edges || []).map(toVisEdge);

    nextNodes.forEach((n) => nodesRef.current.update(n));
    nextEdges.forEach((e) => edgesRef.current.update(e));

    if (networkRef.current) {
      networkRef.current.stabilize(150);
    }
  }, [toVisEdge, toVisNode]);

  const fetchFilters = useCallback(async () => {
    const [techRes, statsRes, alertsRes] = await Promise.all([
      fetch(apiUrl('/api/rag/techniques?limit=120')),
      fetch(apiUrl('/api/stats/overview')),
      fetch(apiUrl('/api/alerts?page=1&page_size=120&sort_by=ensemble_score&sort_order=desc')),
    ]);

    if (techRes.ok) {
      const payload = await techRes.json();
      setTechniques(payload || []);
    }
    if (statsRes.ok) {
      const payload = await statsRes.json();
      setAttackTypes(Object.keys(payload?.attack_types || {}));
    }
    if (alertsRes.ok) {
      const payload = await alertsRes.json();
      setAlerts(payload?.alerts || []);
    }
  }, []);

  const fetchInitialGraph = useCallback(async () => {
    setLoading(true);
    try {
      nodesRef.current.clear();
      edgesRef.current.clear();

      let attackType = selectedAttack;
      let techniqueId = selectedTechnique;

      if (selectedAlert) {
        attackType = selectedAlert.attack_name || '';
      }

      const qs = new URLSearchParams({
        limit: String(initialLimit),
        attack_type: attackType || '',
        technique_id: techniqueId || '',
      });
      const res = await fetch(apiUrl(`/api/rag/graph/subgraph?${qs.toString()}`));
      if (!res.ok) throw new Error('Failed to load graph subgraph');
      mergeGraphData(await res.json());
      setQuerySummary('');
      setQueryInsights([]);
      setQueryExplanation('');
      if (networkRef.current) {
        networkRef.current.fit({ animation: { duration: 450, easingFunction: 'easeInOutQuad' } });
      }
    } catch (e) {
      console.error(e);
      alert('Could not load graph data. Check backend and Neo4j connection.');
    } finally {
      setLoading(false);
    }
  }, [initialLimit, mergeGraphData, selectedAlert, selectedAttack, selectedTechnique]);

  const expandNode = useCallback(async (node) => {
    try {
      const res = await fetch(apiUrl('/api/rag/graph/expand'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          node_type: node.type,
          node_key: node.key,
          limit: expandLimit,
        }),
      });
      if (!res.ok) throw new Error('Failed to expand node');
      const payload = await res.json();
      mergeGraphData(payload);

      if (networkRef.current) {
        networkRef.current.fit({ animation: { duration: 350, easingFunction: 'easeInOutQuad' } });
      }
    } catch (e) {
      console.error(e);
    }
  }, [expandLimit, mergeGraphData]);

  const clearHoverHighlight = useCallback(() => {
    const backup = hoverBackupRef.current;
    Object.values(backup.nodes).forEach((n) => nodesRef.current.update(n));
    Object.values(backup.edges).forEach((e) => edgesRef.current.update(e));
    hoverBackupRef.current = { nodes: {}, edges: {} };
  }, []);

  const applyHoverHighlight = useCallback((nodeId) => {
    clearHoverHighlight();

    if (!networkRef.current) return;
    const connected = networkRef.current.getConnectedNodes(nodeId);
    const connectedEdges = networkRef.current.getConnectedEdges(nodeId);

    const impactedNodeIds = [nodeId, ...connected];

    impactedNodeIds.forEach((id) => {
      const original = nodesRef.current.get(id);
      if (!original) return;
      hoverBackupRef.current.nodes[id] = { ...original };
      nodesRef.current.update({
        id,
        borderWidth: 3,
        color: {
          ...original.color,
          border: '#f59e0b',
        },
      });
    });

    connectedEdges.forEach((id) => {
      const original = edgesRef.current.get(id);
      if (!original) return;
      hoverBackupRef.current.edges[id] = { ...original };
      edgesRef.current.update({
        id,
        width: Math.max(3, original.width || 1),
        color: { ...(original.color || {}), color: '#f59e0b', opacity: 1 },
      });
    });
  }, [clearHoverHighlight]);

  const clearTraceHighlight = useCallback(() => {
    const backup = traceBackupRef.current;
    Object.values(backup.nodes).forEach((n) => nodesRef.current.update(n));
    Object.values(backup.edges).forEach((e) => edgesRef.current.update(e));
    traceBackupRef.current = { nodes: {}, edges: {} };
    setTracePath(null);
  }, []);

  const applyTraceHighlight = useCallback((startNodeId) => {
    clearTraceHighlight();

    const allNodes = nodesRef.current.get();
    const allEdges = edgesRef.current.get();
    if (!startNodeId || allNodes.length === 0 || allEdges.length === 0) return;

    const nodeById = new Map(allNodes.map((n) => [n.id, n]));
    const adjacency = new Map();
    allNodes.forEach((n) => adjacency.set(n.id, []));

    allEdges.forEach((e) => {
      if (!adjacency.has(e.from) || !adjacency.has(e.to)) return;
      adjacency.get(e.from).push(e.to);
      adjacency.get(e.to).push(e.from);
    });

    const targets = new Set(allNodes
      .filter((n) => ['Playbook', 'MITRETechnique', 'DetectionPattern'].includes(n.type) && n.id !== startNodeId)
      .map((n) => n.id));

    const queue = [startNodeId];
    const parent = new Map([[startNodeId, null]]);
    let found = null;

    while (queue.length > 0 && !found) {
      const curr = queue.shift();
      if (targets.has(curr)) {
        found = curr;
        break;
      }
      (adjacency.get(curr) || []).forEach((next) => {
        if (parent.has(next)) return;
        parent.set(next, curr);
        queue.push(next);
      });
    }

    if (!found) return;

    const pathNodeIds = [];
    let cursor = found;
    while (cursor !== null) {
      pathNodeIds.push(cursor);
      cursor = parent.get(cursor) ?? null;
    }
    pathNodeIds.reverse();

    const pathEdgeIds = [];
    for (let i = 0; i < pathNodeIds.length - 1; i += 1) {
      const from = pathNodeIds[i];
      const to = pathNodeIds[i + 1];
      const edge = allEdges.find((e) =>
        (e.from === from && e.to === to) || (e.from === to && e.to === from)
      );
      if (edge) pathEdgeIds.push(edge.id);
    }

    pathNodeIds.forEach((id) => {
      const original = nodesRef.current.get(id);
      if (!original) return;
      traceBackupRef.current.nodes[id] = { ...original };
      nodesRef.current.update({
        id,
        borderWidth: 4,
        color: {
          ...(original.color || {}),
          border: '#f97316',
        },
      });
    });

    pathEdgeIds.forEach((id) => {
      const original = edgesRef.current.get(id);
      if (!original) return;
      traceBackupRef.current.edges[id] = { ...original };
      edgesRef.current.update({
        id,
        width: Math.max(4, original.width || 1),
        color: { ...(original.color || {}), color: '#f97316', opacity: 1 },
      });
    });

    const pathLabels = pathNodeIds
      .map((id) => {
        const n = nodeById.get(id);
        return n ? `${n.type}:${n.key}` : String(id);
      })
      .join(' -> ');

    setTracePath(pathLabels);
  }, [clearTraceHighlight]);

  const runGraphQuery = useCallback(async () => {
    const q = graphQuery.trim();
    if (!q) return;

    setQueryingGraph(true);
    try {
      const res = await fetch(apiUrl('/api/rag/graph/query'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: q,
          limit: initialLimit,
        }),
      });
      if (!res.ok) throw new Error('Graph query failed');

      const payload = await res.json();
      nodesRef.current.clear();
      edgesRef.current.clear();
      mergeGraphData(payload);

      setQuerySummary(payload.summary || 'Graph query completed.');
      setQueryInsights(payload.insights || []);
      setQueryExplanation(payload.explanation || '');

      if (networkRef.current) {
        networkRef.current.fit({ animation: { duration: 420, easingFunction: 'easeInOutQuad' } });
      }

      const firstMatchId = payload?.matches?.[0]?.id;
      if (firstMatchId) {
        const firstNode = nodesRef.current.get(firstMatchId);
        if (firstNode) {
          setSelectedNode(firstNode);
          applyTraceHighlight(firstMatchId);
        }
      }
    } catch (e) {
      console.error(e);
      alert('Could not run graph query. Check backend logs and graph connectivity.');
    } finally {
      setQueryingGraph(false);
    }
  }, [applyTraceHighlight, graphQuery, initialLimit, mergeGraphData]);

  useEffect(() => {
    fetchFilters().catch(console.error);
  }, [fetchFilters]);

  useEffect(() => {
    fetchInitialGraph();
  }, [fetchInitialGraph, selectedAlertKey]);

  useEffect(() => {
    const allEdges = edgesRef.current.get();
    if (!allEdges || allEdges.length === 0) return;
    edgesRef.current.update(
      allEdges.map((e) => ({
        id: e.id,
        label: showEdgeLabels ? e.type : '',
      }))
    );
  }, [showEdgeLabels]);

  useEffect(() => {
    if (!canvasRef.current || networkRef.current) return;

    networkRef.current = new Network(
      canvasRef.current,
      { nodes: nodesRef.current, edges: edgesRef.current },
      {
        autoResize: true,
        interaction: {
          hover: true,
          tooltipDelay: 140,
          zoomView: true,
          dragView: true,
          navigationButtons: true,
        },
        physics: {
          enabled: true,
          solver: 'forceAtlas2Based',
          forceAtlas2Based: {
            gravitationalConstant: -90,
            centralGravity: 0.003,
            springLength: 180,
            springConstant: 0.035,
            damping: 0.5,
            avoidOverlap: 1,
          },
          stabilization: {
            enabled: true,
            iterations: 180,
            updateInterval: 25,
          },
        },
        edges: {
          arrows: { to: { enabled: true, scaleFactor: 0.75 } },
          smooth: { enabled: true, type: 'dynamic' },
          font: { size: 9, color: '#475569', align: 'middle' },
        },
      }
    );

    networkRef.current.on('hoverNode', ({ node }) => applyHoverHighlight(node));
    networkRef.current.on('blurNode', () => clearHoverHighlight());

    networkRef.current.on('click', ({ nodes }) => {
      if (!nodes || nodes.length === 0) {
        setSelectedNode(null);
        clearTraceHighlight();
        return;
      }
      const n = nodesRef.current.get(nodes[0]);
      setSelectedNode(n || null);
      applyTraceHighlight(nodes[0]);
    });

    networkRef.current.on('doubleClick', ({ nodes }) => {
      if (!nodes || nodes.length === 0) return;
      const n = nodesRef.current.get(nodes[0]);
      if (!n) return;
      setSelectedNode(n);
      applyTraceHighlight(nodes[0]);
      expandNode(n);
    });

    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
        networkRef.current = null;
      }
    };
  }, [applyHoverHighlight, applyTraceHighlight, clearHoverHighlight, clearTraceHighlight, expandNode]);

  useEffect(() => {
    if (!pulseSuspicious) return undefined;

    let on = false;
    const id = setInterval(() => {
      const suspicious = nodesRef.current.get().filter((n) => n.type === 'Window' && n.properties?.is_attack === true);
      suspicious.forEach((n) => {
        nodesRef.current.update({
          id: n.id,
          borderWidth: on ? 2 : 4,
          color: {
            ...(n.color || {}),
            border: on ? '#991b1b' : '#ef4444',
          },
        });
      });
      on = !on;
    }, 800);

    return () => clearInterval(id);
  }, [pulseSuspicious]);

  return (
    <div className="page-stack">
      <section className="page-intro">
        <h2>Knowledge Graph Explorer</h2>
        <p>Filter the graph, then double-click a node to expand neighbors and keep the surrounding path in view.</p>
      </section>

      <div className="card">
        <div className="graph-controls-grid">
          <div className="graph-controls-row graph-controls-row-primary">
            <label className="field">
              <span>Attack Type</span>
              <select value={selectedAttack} onChange={(e) => setSelectedAttack(e.target.value)}>
                <option value="">All</option>
                {attackTypeOptions.map((attackType) => (
                  <option key={attackType} value={attackType}>{attackType}</option>
                ))}
              </select>
            </label>

            <label className="field">
              <span>MITRE Technique</span>
              <select value={selectedTechnique} onChange={(e) => setSelectedTechnique(e.target.value)}>
                <option value="">All</option>
                {techniqueOptions.map((technique) => (
                  <option key={technique.technique_id} value={technique.technique_id}>
                    {technique.technique_id} - {technique.name}
                  </option>
                ))}
              </select>
            </label>

            <label className="field">
              <span>Seed from Alert Path</span>
              <select value={selectedAlertKey} onChange={(e) => setSelectedAlertKey(e.target.value)}>
                <option value="">None</option>
                {alerts.map((a) => {
                  const key = `${a.user_name}|${a.window}`;
                  return (
                    <option key={key} value={key}>
                      {a.user_name} | {new Date(a.window).toLocaleString()} | {Number(a.ensemble_score).toFixed(3)}
                    </option>
                  );
                })}
              </select>
            </label>

            <label className="field">
              <span>Initial Nodes</span>
              <select value={initialLimit} onChange={(e) => setInitialLimit(Number(e.target.value))}>
                <option value={15}>15</option>
                <option value={20}>20</option>
                <option value={30}>30</option>
                <option value={45}>45</option>
              </select>
            </label>
          </div>

          <div className="graph-controls-row graph-controls-row-secondary">
            <label className="field">
              <span>Expand Size</span>
              <select value={expandLimit} onChange={(e) => setExpandLimit(Number(e.target.value))}>
                <option value={8}>8</option>
                <option value={12}>12</option>
                <option value={20}>20</option>
                <option value={30}>30</option>
              </select>
            </label>

            <label className="field">
              <span>Edge Labels</span>
              <select value={showEdgeLabels ? 'on' : 'off'} onChange={(e) => setShowEdgeLabels(e.target.value === 'on')}>
                <option value="off">Hidden</option>
                <option value="on">Visible</option>
              </select>
            </label>

            <button className="btn btn-secondary" onClick={() => {
              setSelectedAttack('');
              setSelectedTechnique('');
              setSelectedAlertKey('');
              setSelectedNode(null);
              clearTraceHighlight();
              setQuerySummary('');
              setQueryInsights([]);
              setQueryExplanation('');
            }}>
              Clear
            </button>
            <button className="btn btn-primary" onClick={fetchInitialGraph} disabled={loading}>
              {loading ? 'Loading...' : 'Render Graph'}
            </button>
            <button className="btn btn-secondary" onClick={() => setPulseSuspicious((v) => !v)}>
              {pulseSuspicious ? 'Stop Path Pulse' : 'Pulse Suspicious Paths'}
            </button>
          </div>
        </div>

        <div className="graph-query-row">
          <label className="field" style={{ flex: 1 }}>
            <span>Graph RAG Query</span>
            <input
              type="text"
              value={graphQuery}
              onChange={(e) => setGraphQuery(e.target.value)}
              placeholder="Example: show impossible travel patterns linked to T1078"
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  runGraphQuery();
                }
              }}
            />
          </label>
          <button className="btn btn-primary" onClick={runGraphQuery} disabled={queryingGraph || !graphQuery.trim()}>
            {queryingGraph ? 'Querying...' : 'Query Graph'}
          </button>
        </div>

        {(querySummary || queryInsights.length > 0) && (
          <div className="graph-query-insights">
            {querySummary ? <p>{querySummary}</p> : null}
            {queryInsights.length > 0 ? (
              <ul>
                {queryInsights.map((item) => <li key={item}>{item}</li>)}
              </ul>
            ) : null}
          </div>
        )}

        {queryExplanation && (
          <div style={{
            marginTop: '1.5rem',
            padding: '1.5rem',
            background: '#1e3a5f',
            border: '2px solid #10b981',
            borderRadius: '0.5rem'
          }}>
            <div style={{
              fontSize: '1rem',
              fontWeight: 600,
              color: '#10b981',
              marginBottom: '1rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              🤖 AI-Powered Graph Analysis
            </div>
            <div style={{
              color: '#e2e8f0',
              lineHeight: '1.8',
              fontSize: '0.95rem',
              whiteSpace: 'pre-wrap',
              wordWrap: 'break-word'
            }}>
              {queryExplanation}
            </div>
          </div>
        )}
      </div>

      <div className="card graph-explorer-shell">
        <div className="card-header">
          <h3 className="card-title">Graph Canvas</h3>
          <span className="inline-meta">Hover: highlight | Click: open details | Double-click: expand neighbors</span>
        </div>

        <div className="graph-shell">
          <div ref={canvasRef} className="graph-canvas"></div>

          <aside className={`graph-side-panel ${selectedNode ? 'open' : ''}`}>
            <div className="graph-side-panel-header">
              <h4>Node Details</h4>
              <button className="btn btn-secondary" onClick={() => {
                setSelectedNode(null);
                clearTraceHighlight();
              }}>
                Close
              </button>
            </div>

            {selectedNode ? (
              <div className="stack-list">
                <div className="stack-item">
                  <div className="stack-header">
                    <strong>{selectedNode.type}</strong>
                    <span>{selectedNode.key}</span>
                  </div>
                  <p className="graph-node-headline">{nodeDetails.heading}</p>
                  <p>{nodeDetails.subheading}</p>
                </div>

                {nodeDetails.facts.length > 0 && (
                  <div className="stack-item">
                    <div className="stack-header">
                      <strong>Key Facts</strong>
                    </div>
                    <div className="graph-facts-grid">
                      {nodeDetails.facts.map((fact) => (
                        <div key={`${fact.label}-${fact.value}`} className="graph-fact-item">
                          <span>{fact.label}</span>
                          <strong>{fact.value}</strong>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {nodeDetails.observations.length > 0 && (
                  <div className="stack-item">
                    <div className="stack-header">
                      <strong>Analyst Guidance</strong>
                    </div>
                    <ul className="graph-bullets">
                      {nodeDetails.observations.map((obs) => <li key={obs}>{obs}</li>)}
                    </ul>
                  </div>
                )}

                {tracePath && (
                  <div className="stack-item">
                    <div className="stack-header">
                      <strong>Shortest Route</strong>
                    </div>
                    <p style={{ wordBreak: 'break-word' }}>{tracePath}</p>
                  </div>
                )}
              </div>
            ) : (
              <p className="empty-note">Click any node to open analyst-friendly context and route insights.</p>
            )}
          </aside>
        </div>

        <div className="legend-row" style={{ marginTop: '0.8rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {Object.keys(NODE_COLORS).filter((k) => k !== 'default').map((type) => (
            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginRight: '0.4rem' }}>
              <span style={{ width: 11, height: 11, borderRadius: '50%', background: NODE_COLORS[type].background, border: `1px solid ${NODE_COLORS[type].border}` }}></span>
              <span style={{ fontSize: '0.82rem', color: '#475569' }}>{type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default KnowledgeGraphView;
