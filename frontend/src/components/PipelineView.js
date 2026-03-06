import React, { useState, useEffect } from 'react';

function PipelineView() {
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [history, setHistory] = useState([]);
  const [dataStatus, setDataStatus] = useState(null);
  const [runConfig, setRunConfig] = useState({
    run_all_stages: true,
    run_models: true,
    update_rag: true
  });

  useEffect(() => {
    fetchPipelineStatus();
    fetchPipelineHistory();
    fetchDataStatus();
  }, []);

  const fetchPipelineStatus = async () => {
    try {
      const response = await fetch('/api/pipeline/status');
      if (response.ok) {
        const data = await response.json();
        setStatus(data);
      }
    } catch (err) {
      console.error('Failed to fetch pipeline status:', err);
    }
  };

  const fetchPipelineHistory = async () => {
    try {
      const response = await fetch('/api/pipeline/history');
      if (response.ok) {
        const data = await response.json();
        setHistory(data.runs || []);
      }
    } catch (err) {
      console.error('Failed to fetch pipeline history:', err);
    }
  };

  const fetchDataStatus = async () => {
    try {
      const response = await fetch('/api/pipeline/data-status');
      if (response.ok) {
        const data = await response.json();
        setDataStatus(data);
      }
    } catch (err) {
      console.error('Failed to fetch data status:', err);
    }
  };

  const handleRunPipeline = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/pipeline/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(runConfig)
      });

      if (!response.ok) throw new Error('Failed to start pipeline');

      // Poll for status updates
      const pollInterval = setInterval(async () => {
        await fetchPipelineStatus();
        await fetchPipelineHistory();
        
        const statusResponse = await fetch('/api/pipeline/status');
        if (statusResponse.ok) {
          const data = await statusResponse.json();
          if (data.status !== 'running') {
            clearInterval(pollInterval);
            setLoading(false);
            await fetchDataStatus();
          }
        }
      }, 2000);

      // Clear interval after 5 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        setLoading(false);
      }, 300000);

    } catch (err) {
      console.error('Pipeline error:', err);
      setLoading(false);
    }
  };

  const getStatusBadge = (pipelineStatus) => {
    switch(pipelineStatus) {
      case 'running':
        return <span className="badge" style={{ background: '#3b82f6' }}>RUNNING</span>;
      case 'success':
        return <span className="badge badge-success">SUCCESS</span>;
      case 'failed':
        return <span className="badge badge-high">FAILED</span>;
      case 'idle':
      default:
        return <span className="badge badge-low">IDLE</span>;
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return 'N/A';
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(2)} MB`;
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleString();
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.875rem', fontWeight: 700 }}>
          ⚙️ Pipeline Management
        </h2>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button 
            className="btn btn-secondary btn-small"
            onClick={() => {
              fetchPipelineStatus();
              fetchPipelineHistory();
              fetchDataStatus();
            }}
          >
            🔄 Refresh
          </button>
          <button 
            className="btn btn-primary"
            onClick={handleRunPipeline}
            disabled={loading || status?.status === 'running'}
          >
            {loading || status?.status === 'running' ? '⏳ Running...' : '▶️ Run Pipeline'}
          </button>
        </div>
      </div>

      {/* Current Status */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h3 className="card-title">Current Status</h3>
          {status && getStatusBadge(status.status)}
        </div>
        {status && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
            <div>
              <div className="stat-label">Last Run</div>
              <div style={{ color: '#e2e8f0', fontWeight: 500 }}>
                {formatDate(status.last_run_time)}
              </div>
            </div>
            <div>
              <div className="stat-label">Stages Completed</div>
              <div style={{ color: '#10b981', fontWeight: 600, fontSize: '1.25rem' }}>
                {status.stages_completed || 0}
              </div>
            </div>
            <div>
              <div className="stat-label">Stages Failed</div>
              <div style={{ color: '#ef4444', fontWeight: 600, fontSize: '1.25rem' }}>
                {status.stages_failed || 0}
              </div>
            </div>
            {status.elapsed_time && (
              <div>
                <div className="stat-label">Elapsed Time</div>
                <div style={{ color: '#e2e8f0', fontWeight: 500 }}>
                  {status.elapsed_time.toFixed(2)}s
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Pipeline Configuration */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h3 className="card-title">Run Configuration</h3>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={runConfig.run_all_stages}
              onChange={(e) => setRunConfig({ ...runConfig, run_all_stages: e.target.checked })}
              style={{ width: 'auto', cursor: 'pointer' }}
            />
            <span>Run all pipeline stages (ingest → features → models)</span>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={runConfig.run_models}
              onChange={(e) => setRunConfig({ ...runConfig, run_models: e.target.checked })}
              style={{ width: 'auto', cursor: 'pointer' }}
            />
            <span>Run ML models (IF, LOF, Autoencoder, Ensemble)</span>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={runConfig.update_rag}
              onChange={(e) => setRunConfig({ ...runConfig, update_rag: e.target.checked })}
              style={{ width: 'auto', cursor: 'pointer' }}
            />
            <span>Update RAG vector database with new alerts</span>
          </label>
        </div>
      </div>

      {/* Data Status */}
      {dataStatus && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card-header">
            <h3 className="card-title">📁 Data Status</h3>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem' }}>
            {Object.entries(dataStatus).map(([key, value]) => (
              <div key={key} style={{ 
                background: '#334155', 
                padding: '1rem', 
                borderRadius: '0.5rem',
                border: value.exists ? '1px solid #10b981' : '1px solid #64748b'
              }}>
                <div style={{ 
                  fontSize: '0.875rem', 
                  color: '#94a3b8', 
                  marginBottom: '0.5rem',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  {key.replace(/_/g, ' ')}
                </div>
                {value.exists ? (
                  <>
                    <div style={{ color: '#10b981', fontWeight: 600, marginBottom: '0.25rem' }}>
                      ✓ Available
                    </div>
                    <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>
                      {value.rows?.toLocaleString()} rows • {formatBytes(value.size_bytes)}
                    </div>
                  </>
                ) : (
                  <div style={{ color: '#64748b', fontWeight: 500 }}>
                    ✗ Not found
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Execution History */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">📜 Execution History</h3>
        </div>
        {history.length > 0 ? (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th>Status</th>
                  <th>Started</th>
                  <th>Completed</th>
                  <th>Duration</th>
                  <th>Stages</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 10).map((run, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                      {run.run_id?.substring(0, 8)}...
                    </td>
                    <td>{getStatusBadge(run.status)}</td>
                    <td style={{ fontSize: '0.875rem' }}>{formatDate(run.start_time)}</td>
                    <td style={{ fontSize: '0.875rem' }}>{formatDate(run.end_time)}</td>
                    <td style={{ fontWeight: 500 }}>
                      {run.elapsed_time ? `${run.elapsed_time.toFixed(2)}s` : 'N/A'}
                    </td>
                    <td>
                      <span style={{ color: '#10b981' }}>{run.stages_completed || 0} ✓</span>
                      {run.stages_failed > 0 && (
                        <span style={{ color: '#ef4444', marginLeft: '0.5rem' }}>
                          {run.stages_failed} ✗
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon">📋</div>
            <p>No pipeline executions yet</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default PipelineView;
