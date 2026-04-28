import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { DataSet, Network } from 'vis-network/standalone';
import { apiUrl } from '../api';

// Simple markdown to HTML converter for SOC analyst responses
function markdownToHtml(text) {
  if (!text) return '';
  let html = text
    // Headers - BOLD BLACK
    .replace(/^### (.+)$/gm, '<h3 style="margin-top: 1rem; margin-bottom: 0.5rem; font-weight: bold; font-size: 1.1rem; color: #000000;">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 style="margin-top: 1.5rem; margin-bottom: 0.5rem; font-weight: bold; font-size: 1.3rem; color: #000000;">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 style="margin-top: 2rem; margin-bottom: 1rem; font-weight: bold; font-size: 1.5rem; color: #000000;">$1</h1>')
    // Horizontal rules
    .replace(/^---+$/gm, '<hr style="margin: 1rem 0; border-top: 1px solid #cccccc;" />')
    // Bold and italic
    .replace(/\*\*(.+?)\*\*/g, '<strong style="color: #000000;">$1</strong>')
    .replace(/\*(.+?)\*/g, '<em style="color: #000000;">$1</em>')
    // Bullet lists
    .replace(/^\* (.+)$/gm, '<li style="margin-left: 1.5rem; color: #000000;">$1</li>')
    .replace(/^\d+\. (.+)$/gm, '<li style="margin-left: 1.5rem; color: #000000;">$1</li>')
    // Code blocks
    .replace(/`([^`]+)`/g, '<code style="background: #f0f0f0; color: #000000; padding: 0.2rem 0.4rem; border-radius: 0.25rem;">$1</code>')
    // Line breaks
    .replace(/\n/g, '<br />');
  
  return html;
}

// Pastel palette per user's request (monochrome-first app but pastel node accents)
// Soft Coral, Muted Sky Blue, Sage Green, Dusty Yellow, Warm Beige, Pale Gray, Muted Lavender, Slate Blue Gray
const NODE_COLORS = {
  User:            { background: '#8FA3B8', border: '#7A91A5', highlight: { background: '#9CB0C2', border: '#7A91A5' } }, // Slate Blue Gray
  Window:          { background: '#E7A38F', border: '#D38F7C', highlight: { background: '#EFB6A6', border: '#D38F7C' } }, // Soft Coral (distinct from Playbook)
  DetectionPattern:{ background: '#D8C27A', border: '#C6B15E', highlight: { background: '#E2CF93', border: '#C6B15E' } }, // Dusty Yellow
  MITRETechnique:  { background: '#B8AEDB', border: '#9F94C6', highlight: { background: '#C7BFEF', border: '#9F94C6' } }, // Muted Lavender
  Playbook:        { background: '#A8CFA8', border: '#8FB78F', highlight: { background: '#C1E3C1', border: '#8FB78F' } }, // Sage Green (different from Window)
  Service:         { background: '#7FC8E8', border: '#62B7D9', highlight: { background: '#9FDFF4', border: '#62B7D9' } }, // Muted Sky Blue
  Default:         { background: '#C9D1D9', border: '#AEB9C2', highlight: { background: '#D7E0E8', border: '#AEB9C2' } }, // Pale Gray
  default:         { background: '#C9D1D9', border: '#AEB9C2', highlight: { background: '#D7E0E8', border: '#AEB9C2' } },
};

const EDGE_COLORS = {
  HAD_WINDOW:         '#B0BEC5',
  TRIGGERS_INDICATOR: '#90A4AE',
  DETECTED_BY:        '#78909C',
  TRIGGERS:           '#607D8B',
  default:            '#CFD8DC',
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
  const tooltipRef = useRef(null);
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
  //const [showEdgeLabels] = useState(true); // always show edge labels (Neo4j Bloom style)
  const [initialLimit, setInitialLimit] = useState(20);
  const [expandLimit, setExpandLimit] = useState(12);
  const [tracePath, setTracePath] = useState(null);
  const [graphQuery, setGraphQuery] = useState('');
  const [queryingGraph, setQueryingGraph] = useState(false);
  const [querySummary, setQuerySummary] = useState('');
  const [queryInsights, setQueryInsights] = useState([]);
  const [queryExplanation, setQueryExplanation] = useState('');

  /*const demoQueries = useMemo(() => ([
    { label: 'Open T1078 credential compromise path', query: 'T1078' },
    { label: 'Unusual IAM role assumption', query: 'Unusual IAM Role Assumption' },
    { label: 'Privilege escalation by policy attachment', query: 'IOC-IAM-002' },
    { label: 'Mass S3 data exfiltration', query: 'IOC-S3-001' },
    { label: 'S3 bucket policy tampering', query: 'IOC-S3-002' },
    { label: 'Access key persistence', query: 'Access Key Creation for Persistence' },
    { label: 'Reconnaissance via enumeration', query: 'Comprehensive Cloud Service Enumeration' },
    { label: 'Root account activity', query: 'IR-IAM-004' },
  ]), []);*/

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
    // Larger nodes so label fits inside the circle visually
    const nodeSizes = {
      User: 38,
      Window: 42,
      DetectionPattern: 38,
      MITRETechnique: 38,
      Playbook: 38,
    };
    return {
      shape: 'dot',
      size: nodeSizes[nodeType] || 34,
      color: {
        background: palette.background,
        border: palette.border,
        highlight: palette.highlight || { background: palette.background, border: palette.border },
        hover: { background: palette.highlight?.background || palette.background, border: palette.border },
      },
      font: {
        color: '#333333',
        size: 11,
        face: '"Segoe UI", system-ui, sans-serif',
        strokeWidth: 0,
        vadjust: 0,
        bold: false,
      },
      borderWidth: 2.5,
      borderWidthSelected: 4,
      // No shadow — kills performance
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
    // Neo4j Bloom style: type on first line (smaller), name on second line
    // vis-network dot shape renders label centered below the node
    switch (n.type) {
      case 'User':
        return compactIdentity(n.key);
      case 'Window':
        return formatWindowLabel(n.properties?.window_start || n.key);
      case 'DetectionPattern':
        return clampText(n.properties?.name || n.key, 14);
      case 'MITRETechnique':
        return clampText(n.key, 12);
      case 'Playbook':
        return clampText(n.properties?.name || n.key, 14);
      default:
        return clampText(n.label || n.key, 14);
    }
  }, [clampText, compactIdentity, formatWindowLabel]);

  const toVisNode = useCallback((n) => {
    // Build concise tooltip content but DO NOT set node `title` (avoids browser tooltip leakage)
    const props = n.properties || {};
    // Simple plaintext summary used by our custom DOM tooltip
    let tooltipContent = '';
    tooltipContent += `${n.type} — ${n.key}`;
    if (n.type === 'Window') {
      if (props.ensemble_score !== undefined) tooltipContent += ` | Risk: ${Number(props.ensemble_score).toFixed(3)}`;
      if (props.user_name) tooltipContent += ` | User: ${props.user_name}`;
      if (props.attack_name) tooltipContent += ` | Attack: ${props.attack_name}`;
    } else if (n.type === 'DetectionPattern') {
      if (props.severity) tooltipContent += ` | Severity: ${props.severity}`;
      if (props.name) tooltipContent += ` | ${props.name.substring(0, 30)}`;
    } else if (n.type === 'MITRETechnique') {
      if (props.technique_name) tooltipContent += ` | ${props.technique_name}`;
      if (props.tactic) tooltipContent += ` | ${props.tactic}`;
    } else if (n.type === 'Playbook') {
      if (props.name) tooltipContent += ` | ${props.name.substring(0, 30)}`;
      if (props.priority) tooltipContent += ` | Priority: ${props.priority}`;
    } else if (n.type === 'User') {
      if (props.name) tooltipContent += ` | ${props.name}`;
      if (props.department) tooltipContent += ` | Dept: ${props.department}`;
    }

    return {
      id: n.id,
      label: formatNodeLabel(n),
      // Keep tooltip content available on the node object for our custom tooltip
      _tooltipContent: tooltipContent,
      group: n.type,
      type: n.type,
      key: n.key,
      properties: n.properties || {},
      ...getNodeStyle(n.type),
    };
  }, [formatNodeLabel, getNodeStyle]);

  const toVisEdge = useCallback((e) => ({
    id: e.id,
    from: e.source,
    to: e.target,
    label: e.type || '',
    arrows: {
      to: { enabled: true, scaleFactor: 0.5, type: 'arrow' },
    },
    smooth: { enabled: true, type: 'continuous', roundness: 0.15 },
    color: {
      color: EDGE_COLORS[e.type] || EDGE_COLORS.default,
      highlight: '#FF6B35',
      hover: '#FF6B35',
      opacity: 0.85,
    },
    font: {
      color: '#555555',
      size: 9,
      face: '"Segoe UI", system-ui, sans-serif',
      strokeWidth: 2,
      strokeColor: '#ffffff',
      align: 'middle',
    },
    width: 1,
    selectionWidth: 2,
    hoverWidth: 1.5,
    type: e.type,
    properties: e.properties || {},
  }), []);

  const mergeGraphData = useCallback((payload) => {
    const nextNodes = (payload?.nodes || []).map(toVisNode);
    const nextEdges = (payload?.edges || []).map(toVisEdge);

    // Batch update — do NOT call stabilize() here, it re-runs full physics every merge
    nodesRef.current.update(nextNodes);
    edgesRef.current.update(nextEdges);
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

  // UI helpers: zoom, fit, expand selected
  const zoomIn = useCallback(() => {
    if (!networkRef.current) return;
    try {
      const current = networkRef.current.getScale();
      networkRef.current.moveTo({ scale: Math.min(current * 1.25, 2.5), animation: { duration: 200 } });
    } catch (e) { }
  }, []);

  const zoomOut = useCallback(() => {
    if (!networkRef.current) return;
    try {
      const current = networkRef.current.getScale();
      networkRef.current.moveTo({ scale: Math.max(current * 0.8, 0.2), animation: { duration: 200 } });
    } catch (e) { }
  }, []);

  const fitGraph = useCallback(() => {
    if (!networkRef.current) return;
    try {
      networkRef.current.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
    } catch (e) { }
  }, []);

  const expandSelected = useCallback(() => {
    if (!selectedNode) return;
    expandNode(selectedNode);
  }, [expandNode, selectedNode]);

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
        borderWidth: id === nodeId ? 4 : 3,
        color: {
          ...original.color,
          border: '#FF6B35',
        },
      });
    });

    connectedEdges.forEach((id) => {
      const original = edgesRef.current.get(id);
      if (!original) return;
      hoverBackupRef.current.edges[id] = { ...original };
      edgesRef.current.update({
        id,
        width: 2.5,
        color: { ...(original.color || {}), color: '#FF6B35', opacity: 1 },
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
          border: '#FF6B35',
        },
      });
    });

    pathEdgeIds.forEach((id) => {
      const original = edgesRef.current.get(id);
      if (!original) return;
      traceBackupRef.current.edges[id] = { ...original };
      edgesRef.current.update({
        id,
        width: Math.max(3, original.width || 1),
        color: { ...(original.color || {}), color: '#FF6B35', opacity: 1 },
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

  const runGraphQuery = useCallback(async (overrideQuery) => {
    const q = String(overrideQuery ?? graphQuery).trim();
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

      const focusMatch = payload?.focus_match || payload?.matches?.[0];
      const focusMatchId = focusMatch?.id;
      if (focusMatchId) {
        const focusNode = nodesRef.current.get(focusMatchId);
        if (focusNode) {
          setSelectedNode(focusNode);
          applyTraceHighlight(focusMatchId);
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

  // Edge labels are always shown (relationship type) — no toggle effect needed

  useEffect(() => {
    if (!canvasRef.current || networkRef.current) return;
    // Create a lightweight custom tooltip DOM node (avoids browser tooltip issues)
    const container = canvasRef.current.parentElement || document.body;
    const tooltipEl = document.createElement('div');
    tooltipEl.style.position = 'absolute';
    tooltipEl.style.pointerEvents = 'none';
    tooltipEl.style.zIndex = '9999';
    tooltipEl.style.display = 'none';
    tooltipEl.style.background = '#111827';
    tooltipEl.style.color = '#E5E7EB';
    tooltipEl.style.padding = '8px 10px';
    tooltipEl.style.borderRadius = '6px';
    tooltipEl.style.fontSize = '12px';
    tooltipEl.style.boxShadow = '0 6px 18px rgba(0,0,0,0.28)';
    tooltipEl.style.border = '1px solid rgba(255,255,255,0.04)';
    tooltipEl.style.maxWidth = '320px';
    tooltipEl.style.whiteSpace = 'nowrap';
    tooltipEl.style.overflow = 'hidden';
    tooltipEl.style.textOverflow = 'ellipsis';
    container.appendChild(tooltipEl);
    tooltipRef.current = tooltipEl;

    networkRef.current = new Network(
      canvasRef.current,
      { nodes: nodesRef.current, edges: edgesRef.current },
      {
        autoResize: true,
        interaction: {
          hover: true,
          tooltipDelay: 50,
          zoomView: true,
          dragView: true,
          navigationButtons: false,
          keyboard: { enabled: true, speed: { x: 10, y: 10, zoom: 0.02 } },
          multiselect: false,
        },
        physics: {
          enabled: true,
          solver: 'hierarchicalRepulsion',
          hierarchicalRepulsion: {
            centralGravity: 0.0,
            springLength: 200,
            springConstant: 0.04,
            nodeDistance: 140,
            damping: 0.5,
            avoidOverlap: 0.5,
          },
          stabilization: {
            enabled: true,
            iterations: 80,
            updateInterval: 25,
            fit: true,
          },
          adaptiveTimestep: true,
          minVelocity: 0.75,
          maxVelocity: 50,
          timestep: 0.5,
          globalDamping: 0.3,
        },
        nodes: {
          shape: 'ellipse',
          font: {
            size: 13,
            color: '#ffffff',
            face: '"Segoe UI", system-ui, sans-serif',
            strokeWidth: 0,
          },
        },
        edges: {
          arrows: { to: { enabled: true, scaleFactor: 0.5 } },
          smooth: { enabled: true, type: 'continuous', roundness: 0.1 },
          font: {
            size: 9,
            color: '#555555',
            strokeWidth: 2,
            strokeColor: '#ffffff',
            align: 'middle',
            background: 'rgba(255,255,255,0.8)',
          },
          color: { color: '#888888', highlight: '#FF6B35', hover: '#FF6B35' },
          selectionWidth: 2,
          hoverWidth: 1.5,
          width: 1,
        },
        layout: {
          improvedLayout: true,
        },
      }
    );

    // After stabilization, disable physics to improve interactivity/reduce lag
    networkRef.current.once('stabilizationIterationsDone', () => {
      try {
        networkRef.current.setOptions({ physics: { enabled: false } });
      } catch (e) {
        // ignore
      }
    });

    networkRef.current.on('hoverNode', (params) => {
      // params has .node and the original DOM event at params.event
      const nodeId = params.node;
      applyHoverHighlight(nodeId);

      // show custom tooltip near pointer
      try {
        const node = nodesRef.current.get(nodeId);
        if (!node || !tooltipRef.current) return;
        tooltipRef.current.textContent = node._tooltipContent || `${node.type} — ${node.key}`;
        tooltipRef.current.style.display = 'block';
        const pointer = params.event && params.event.pointer ? params.event.pointer : null;
        // fallback: use mouse coordinates
        const x = params.event && params.event.pageX ? params.event.pageX : (pointer ? pointer.x : 0);
        const y = params.event && params.event.pageY ? params.event.pageY : (pointer ? pointer.y : 0);
        // Position tooltip slightly offset
        tooltipRef.current.style.left = `${x + 12}px`;
        tooltipRef.current.style.top = `${y + 12}px`;
      } catch (err) {
        // ignore tooltip errors
      }
    });

    networkRef.current.on('blurNode', () => {
      clearHoverHighlight();
      if (tooltipRef.current) tooltipRef.current.style.display = 'none';
    });

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

    // Clean up tooltip on destroy
    const originalDestroy = networkRef.current.destroy;
    networkRef.current.destroy = function () {
      try {
        if (tooltipRef.current && tooltipRef.current.parentElement) tooltipRef.current.parentElement.removeChild(tooltipRef.current);
        tooltipRef.current = null;
      } catch (e) {}
      originalDestroy.call(this);
    };

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
        <p style={{ maxWidth: '72rem', marginTop: '0.75rem', color: '#475569', lineHeight: 1.6 }}>
          Each circle is a security entity such as a user, ATT&CK technique, detection pattern, or playbook.
          Lines show how those entities connect. The query box is best for exact IDs or exact names.
        </p>
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
            marginTop: '2rem',
            padding: '1.5rem',
            borderRadius: '0.5rem',
            width: '100%',
            boxSizing: 'border-box'
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
              color: '#000000',
              lineHeight: '1.8',
              fontSize: '0.95rem',
              wordWrap: 'break-word',
              overflowWrap: 'break-word',
              whiteSpace: 'normal',
              overflow: 'visible',
              maxHeight: 'none',
              maxWidth: '100%'
            }} dangerouslySetInnerHTML={{ __html: markdownToHtml(queryExplanation) }}>
            </div>
          </div>
        )}
      </div>

      <div className="card graph-explorer-shell">
        <div className="card-header">
          <h3 className="card-title">Graph Canvas</h3>
          <span className="inline-meta">Hover: highlight | Click: open details | Double-click: expand neighbors</span>
        </div>

        <div className="graph-shell" style={{ position: 'relative' }}>
          <div ref={canvasRef} className="graph-canvas" style={{ background: '#f8fafc', borderRadius: '0.5rem', position: 'relative' }}></div>

          <div className="graph-canvas-overlay" style={{ position: 'absolute', right: '18px', bottom: '18px', display: 'flex', gap: '8px', zIndex: 40 }}>
            <button className="btn btn-ghost" title="Zoom in" onClick={zoomIn} style={{ width: 36, height: 36, borderRadius: 6, border: '1px solid #E5E7EB', background: '#FFFFFF' }}>+</button>
            <button className="btn btn-ghost" title="Zoom out" onClick={zoomOut} style={{ width: 36, height: 36, borderRadius: 6, border: '1px solid #E5E7EB', background: '#FFFFFF' }}>−</button>
            <button className="btn btn-ghost" title="Fit graph" onClick={fitGraph} style={{ width: 36, height: 36, borderRadius: 6, border: '1px solid #E5E7EB', background: '#FFFFFF' }}>⤢</button>
            <button className="btn btn-ghost" title="Expand selected" onClick={expandSelected} style={{ width: 36, height: 36, borderRadius: 6, border: '1px solid #E5E7EB', background: '#FFFFFF' }}>⤧</button>
          </div>

          <aside className={`graph-side-panel ${selectedNode ? 'open' : ''}`}>
            <div className="graph-side-panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div
                  style={{
                    width: '16px',
                    height: '16px',
                    borderRadius: '50%',
                    background: NODE_COLORS[selectedNode?.type]?.background || '#9CA3AF',
                    border: `2px solid ${NODE_COLORS[selectedNode?.type]?.border || '#6B7280'}`,
                  }}
                />
                <div>
                  <h4 style={{ margin: '0 0 0.2rem 0', fontSize: '0.85rem', fontWeight: '700', color: '#1F2937', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    {selectedNode?.type}
                  </h4>
                  <p style={{ margin: 0, fontSize: '0.9rem', fontWeight: '600', color: '#000000' }}>
                    {selectedNode?.key}
                  </p>
                </div>
              </div>
              <button className="btn btn-secondary" onClick={() => {
                setSelectedNode(null);
                clearTraceHighlight();
              }}>
                ×
              </button>
            </div>

            {selectedNode ? (
              <div className="stack-list">
                <div className="stack-item">
                  <p className="graph-node-headline" style={{ color: '#10B981', fontWeight: '600', marginBottom: '0.5rem' }}>
                    {nodeDetails.heading}
                  </p>
                  <p style={{ fontSize: '0.9rem', color: '#6B7280', lineHeight: '1.4' }}>
                    {nodeDetails.subheading}
                  </p>
                </div>

                {nodeDetails.facts.length > 0 && (
                  <div className="stack-item">
                    <div className="stack-header" style={{ marginBottom: '0.75rem' }}>
                      <strong style={{ fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#4B5563' }}>Properties</strong>
                    </div>
                    <div className="graph-facts-grid">
                      {nodeDetails.facts.map((fact) => (
                        <div key={`${fact.label}-${fact.value}`} className="graph-fact-item" style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid #E5E7EB' }}>
                          <span style={{ color: '#6B7280', fontSize: '0.85rem', fontWeight: '500' }}>{fact.label}</span>
                          <strong style={{ color: '#000000', fontSize: '0.9rem', fontFamily: 'monospace' }}>{fact.value}</strong>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {nodeDetails.observations.length > 0 && (
                  <div className="stack-item">
                    <div className="stack-header" style={{ marginBottom: '0.75rem' }}>
                      <strong style={{ fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#4B5563' }}>Analyst Guidance</strong>
                    </div>
                    <ul className="graph-bullets" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                      {nodeDetails.observations.map((obs) => (
                        <li key={obs} style={{ fontSize: '0.85rem', color: '#374151', marginBottom: '0.75rem', paddingLeft: '1rem', position: 'relative' }}>
                          <span style={{ position: 'absolute', left: 0, color: '#0DD9FF' }}>▸</span>
                          {obs}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {tracePath && (
                  <div className="stack-item" style={{ backgroundColor: '#F3F4F6', padding: '0.75rem', borderRadius: '0.375rem', borderLeft: '3px solid #FF6B35' }}>
                    <div className="stack-header" style={{ marginBottom: '0.5rem' }}>
                      <strong style={{ fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#4B5563' }}>Shortest Route</strong>
                    </div>
                    <p style={{ wordBreak: 'break-word', fontSize: '0.8rem', color: '#000000', fontFamily: 'monospace', margin: 0 }}>{tracePath}</p>
                  </div>
                )}
              </div>
            ) : (
              <p className="empty-note" style={{ color: '#9CA3AF', fontSize: '0.85rem', textAlign: 'center', padding: '2rem 1rem' }}>
                Click any node to inspect properties and explore connections.
              </p>
            )}
          </aside>
        </div>

        <div className="legend-row" style={{ marginTop: '1rem', display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', padding: '0.75rem', backgroundColor: '#F8FAFC', borderRadius: '0.375rem', border: '1px solid #E5E7EB' }}>
          <span style={{ fontSize: '0.75rem', color: '#6B7280', fontWeight: 700, marginRight: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Legend</span>
          {Object.keys(NODE_COLORS).filter((k) => k.toLowerCase() !== 'default').map((type) => (
            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.4rem 0.75rem', borderRadius: '4px', backgroundColor: '#FFFFFF', border: `1px solid ${NODE_COLORS[type].border}` }}>
              <div style={{
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background: NODE_COLORS[type].background,
                border: `1.5px solid ${NODE_COLORS[type].border}`,
              }} />
              <span style={{ fontSize: '0.75rem', color: '#374151', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em' }}>{type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default KnowledgeGraphView;