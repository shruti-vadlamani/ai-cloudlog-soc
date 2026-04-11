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
          <div className="stat-value stat-warning">{datasetStats.attackRate.toFixed(1)}%</div>
          <div className="stat-trend">Ground-truth flagged attacks</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">14-Day Anomaly Score Timeline</h3>
        </div>
        <div className="chart-area">
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={320}>
              <LineChart data={timelineData} margin={{ top: 20, right: 24, left: 12, bottom: 14 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#dbe2ea" />
                <XAxis dataKey="window" tick={{ fontSize: 11 }} stroke="#475569" />
                <YAxis domain={[0, 1]} stroke="#475569" />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="score" stroke="#123f73" strokeWidth={2} dot={false} name="Anomaly score" />
                <Scatter dataKey="attackScore" fill="#b91c1c" name="Attack windows" />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <p className="empty-note">No timeline points loaded. Check API base URL and backend /api/alerts response.</p>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Latest Pipeline Runs</h3>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Status</th>
                <th>Started</th>
                <th>Completed</th>
                <th>Events Ingested</th>
                <th>Alerts Generated</th>
              </tr>
            </thead>
            <tbody>
              {history.length > 0 ? history.map((run) => (
                <tr key={run.run_id}>
                  <td>{run.run_id}</td>
                  <td>
                    <span className={`badge ${run.status === 'success' ? 'badge-success' : run.status === 'failed' ? 'badge-high' : 'badge-low'}`}>
                      {run.status}
                    </span>
                  </td>
                  <td>{run.started_at ? new Date(run.started_at).toLocaleString() : '-'}</td>
                  <td>{run.completed_at ? new Date(run.completed_at).toLocaleString() : '-'}</td>
                  <td>{(run.events_ingested || 0).toLocaleString()}</td>
                  <td>{(run.alerts_generated || 0).toLocaleString()}</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="6" className="empty-note">No pipeline runs yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default PipelineView;
