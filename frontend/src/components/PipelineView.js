import React, { useEffect, useMemo, useState } from 'react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Scatter,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { apiUrl } from '../api';

function PipelineView() {
  const [status, setStatus] = useState({ is_running: false, current_run: null });
  const [history, setHistory] = useState([]);
  const [dataStatus, setDataStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [running, setRunning] = useState(false);

  const fetchAll = async () => {
    try {
      const [statusRes, historyRes, dataRes, alertsRes] = await Promise.all([
        fetch(apiUrl('/api/pipeline/status')),
        fetch(apiUrl('/api/pipeline/history?limit=15')),
        fetch(apiUrl('/api/pipeline/data-status')),
        fetch(apiUrl('/api/alerts?page=1&page_size=200&sort_by=window&sort_order=asc')),
      ]);

      if (statusRes.ok) {
        const payload = await statusRes.json();
        setStatus(payload);
        setRunning(Boolean(payload?.is_running));
      }
      if (historyRes.ok) {
        const payload = await historyRes.json();
        setHistory(payload?.runs || []);
      }
      if (dataRes.ok) {
        const payload = await dataRes.json();
        setDataStatus(payload?.files || {});
      }
      if (alertsRes.ok) {
        const payload = await alertsRes.json();
        setAlerts(payload?.alerts || []);
      } else {
        setAlerts([]);
      }
    } catch (err) {
      console.error('Failed to refresh pipeline data', err);
    }
  };

  useEffect(() => {
    fetchAll();
  }, []);

  useEffect(() => {
    if (!running) return undefined;
    const id = setInterval(fetchAll, 2500);
    return () => clearInterval(id);
  }, [running]);

  const onRunPipeline = async () => {
    setRunning(true);
    try {
      const res = await fetch(apiUrl('/api/pipeline/run'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_async: true, stages: ['ingest', 'features', 'models'] }),
      });
      if (!res.ok) throw new Error('Could not trigger pipeline');
      fetchAll();
    } catch (e) {
      console.error(e);
      setRunning(false);
      alert('Could not trigger pipeline. Check backend logs and AWS bucket settings.');
    }
  };

  const datasetStats = useMemo(() => {
    const normalized = dataStatus?.normalized_events?.row_count || 0;
    const windows = dataStatus?.feature_matrix?.row_count || 0;
    const alertsCount = dataStatus?.ensemble_alerts?.row_count || 0;
    const attackRows = alerts.filter((a) => a.is_attack).length;
    const attackRate = alerts.length ? (attackRows / alerts.length) * 100 : 0;

    return {
      totalEvents: normalized,
      windows,
      attackRate,
      alertsCount,
    };
  }, [dataStatus, alerts]);

  const timelineData = useMemo(() => {
    const recent = [...alerts]
      .sort((a, b) => new Date(a.window) - new Date(b.window))
      .slice(-280);

    return recent.map((a) => ({
      window: new Date(a.window).toISOString().slice(5, 16).replace('T', ' '),
      score: Number(a.ensemble_score || 0),
      attackScore: a.is_attack ? Number(a.ensemble_score || 0) : null,
    }));
  }, [alerts]);

  return (
    <div className="page-stack">
      <section className="page-intro">
        <h2>Live Pipeline Status</h2>
        <p>
          Track ingestion health, dataset readiness, and anomaly behavior over the last 14 days.
        </p>
      </section>

      <div className="action-row">
        <button className="btn btn-primary" onClick={onRunPipeline} disabled={running}>
          {running ? 'Running Pipeline...' : 'Run Pipeline'}
        </button>
        <button className="btn btn-secondary" onClick={fetchAll}>Refresh</button>
        <span className={`pill ${status?.is_running ? 'pill-live' : 'pill-idle'}`}>
          {status?.is_running ? 'Pipeline Live' : 'Pipeline Idle'}
        </span>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Events</div>
          <div className="stat-value">{datasetStats.totalEvents.toLocaleString()}</div>
          <div className="stat-trend">Normalized CloudTrail events</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Windows</div>
          <div className="stat-value">{datasetStats.windows.toLocaleString()}</div>
          <div className="stat-trend">Feature-engineered windows</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Ensemble Alerts</div>
          <div className="stat-value">{datasetStats.alertsCount.toLocaleString()}</div>
          <div className="stat-trend">Rows in ensemble_alerts.csv</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Attack Rate</div>
          <div className="stat-value stat-high">{datasetStats.attackRate.toFixed(1)}%</div>
          <div className="stat-trend">Ground-truth flagged attacks</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Alert Score Timeline</h3>
        </div>
        {timelineData.length > 0 ? (
          <ResponsiveContainer width="100%" height={320}>
            <LineChart data={timelineData} margin={{ left: 20, right: 20, top: 16, bottom: 8 }}>
              <CartesianGrid strokeDasharray="0" stroke="#e5e7eb" vertical={false} />
              <XAxis 
                dataKey="window" 
                stroke="#6b7280" 
                style={{ fontSize: '12px' }}
                interval={Math.floor(timelineData.length / 10)}
              />
              <YAxis stroke="#6b7280" style={{ fontSize: '12px' }} />
              <Tooltip 
                contentStyle={{ background: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '6px' }}
                labelStyle={{ color: '#111827' }}
              />
              <Legend wrapperStyle={{ fontSize: '12px' }} />
              <Line 
                type="monotone" 
                dataKey="score" 
                stroke="#4b5563" 
                dot={false}
                name="Anomaly Score"
                strokeWidth={2}
                isAnimationActive={false}
              />
              <Scatter 
                dataKey="attackScore" 
                fill="#dc2626"
                name="Flagged Attack"
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <p className="empty-note">No timeline data available.</p>
        )}
      </div>

      {history.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Pipeline Runs</h3>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Start Time</th>
                  <th>Duration</th>
                  <th>Stage</th>
                  <th>Status</th>
                  <th>Records Processed</th>
                </tr>
              </thead>
              <tbody>
                {history.map((run, idx) => (
                  <tr key={idx}>
                    <td>{new Date(run.start_time || run.started).toLocaleString()}</td>
                    <td>{run.duration_seconds || run.duration ? `${(run.duration_seconds || run.duration).toFixed(1)}s` : '-'}</td>
                    <td>{run.stages && Array.isArray(run.stages) ? run.stages.join(', ') : run.current_stage || '-'}</td>
                    <td>
                      <span className={`badge ${run.status === 'completed' ? 'badge-success' : run.status === 'failed' ? 'badge-critical' : 'badge-info'}`}>
                        {run.status || 'unknown'}
                      </span>
                    </td>
                    <td>{run.records_processed?.toLocaleString() || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default PipelineView;
