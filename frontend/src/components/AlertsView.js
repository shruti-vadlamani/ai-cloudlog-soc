import React, { useState, useEffect } from 'react';
import AlertDetailModal from './AlertDetailModal';

function AlertsView() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [filters, setFilters] = useState({
    user_name: '',
    min_score: '',
    is_attack: ''
  });
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Fetch alerts when page changes
  useEffect(() => {
    fetchAlerts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  // Debounced filter effect - waits 500ms after user stops typing
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (page === 1) {
        fetchAlerts();
      } else {
        setPage(1); // Reset to page 1, which will trigger fetchAlerts via the other useEffect
      }
    }, 500);

    return () => clearTimeout(timeoutId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
        ...Object.fromEntries(
          Object.entries(filters).filter(([_, v]) => v !== '')
        )
      });
      
      const response = await fetch(`/api/alerts?${params}`);
      if (!response.ok) throw new Error('Failed to fetch alerts');
      
      const data = await response.json();
      setAlerts(data.alerts || []);
      setTotalAlerts(data.total || 0);
      setError(null);
    } catch (err) {
      setError(err.message);
      setAlerts([]);
      setTotalAlerts(0);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (score) => {
    if (score >= 0.7) return <span className="badge badge-high">HIGH</span>;
    if (score >= 0.3) return <span className="badge badge-medium">MEDIUM</span>;
    return <span className="badge badge-low">LOW</span>;
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    // Page reset happens in the debounced useEffect
  };

  const handleAlertClick = (alert) => {
    setSelectedAlert(alert);
  };

  if (loading && (!alerts || alerts.length === 0)) {
    return (
      <div className="loading">
        <div className="loading-spinner"></div>
        <p>Loading alerts...</p>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.875rem', fontWeight: 700 }}>
          🚨 Security Alerts
        </h2>
        <button className="btn btn-primary btn-small" onClick={fetchAlerts}>
          🔄 Refresh
        </button>
      </div>

      {error && (
        <div className="error">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Filters */}
      <div className="filters">
        <div className="filter-group">
          <label className="filter-label">User Name</label>
          <input
            type="text"
            placeholder="Filter by user..."
            value={filters.user_name}
            onChange={(e) => handleFilterChange('user_name', e.target.value)}
            style={{ width: '200px' }}
          />
        </div>

        <div className="filter-group">
          <label className="filter-label">Min Score</label>
          <input
            type="number"
            placeholder="0.0 - 1.0"
            step="0.1"
            min="0"
            max="1"
            value={filters.min_score}
            onChange={(e) => handleFilterChange('min_score', e.target.value)}
            style={{ width: '120px' }}
          />
        </div>

        <div className="filter-group">
          <label className="filter-label">Attack Status</label>
          <select
            value={filters.is_attack}
            onChange={(e) => handleFilterChange('is_attack', e.target.value)}
            style={{ width: '150px' }}
          >
            <option value="">All Alerts</option>
            <option value="true">Attacks Only</option>
            <option value="false">Normal Only</option>
          </select>
        </div>

        {(filters.user_name || filters.min_score || filters.is_attack) && (
          <button 
            className="btn btn-secondary btn-small"
            onClick={() => {
              setFilters({ user_name: '', min_score: '', is_attack: '' });
              setPage(1);
            }}
            style={{ alignSelf: 'flex-end' }}
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Alerts Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Window ID</th>
              <th>Ensemble Score</th>
              <th>Severity</th>
              <th>Attack Type</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {alerts && alerts.length > 0 ? (
              alerts.map((alert, idx) => (
                <tr key={idx} className="clickable-row" onClick={() => handleAlertClick(alert)}>
                  <td style={{ fontWeight: 500 }}>{alert.user_name}</td>
                  <td style={{ fontFamily: 'monospace', color: '#94a3b8' }}>
                    {new Date(alert.window).toLocaleString()}
                  </td>
                  <td>
                    <div className="score-display">
                      <span style={{ minWidth: '40px' }}>{alert.ensemble_score?.toFixed(3)}</span>
                      <div className="score-bar" style={{ width: '60px' }}>
                        <div 
                          className={`score-fill ${
                            alert.ensemble_score >= 0.7 ? 'score-fill-high' :
                            alert.ensemble_score >= 0.3 ? 'score-fill-medium' : 'score-fill-low'
                          }`}
                          style={{ width: `${alert.ensemble_score * 100}%` }}
                        ></div>
                      </div>
                    </div>
                  </td>
                  <td>{getSeverityBadge(alert.ensemble_score)}</td>
                  <td>{alert.attack_name || 'unknown'}</td>
                  <td>
                    {alert.is_attack ? (
                      <span className="badge badge-attack">ATTACK</span>
                    ) : (
                      <span className="badge badge-normal">NORMAL</span>
                    )}
                  </td>
                  <td>
                    <button 
                      className="btn btn-primary btn-small"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleAlertClick(alert);
                      }}
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
                  No alerts found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="pagination">
        <button 
          onClick={() => setPage(p => Math.max(1, p - 1))}
          disabled={page === 1}
        >
          Previous
        </button>
        <span className="page-info">
          Page {page} of {Math.ceil(totalAlerts / pageSize)} ({totalAlerts} total alerts)
        </span>
        <button 
          onClick={() => setPage(p => p + 1)}
          disabled={page >= Math.ceil(totalAlerts / pageSize)}
        >
          Next
        </button>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal 
          alert={selectedAlert} 
          onClose={() => setSelectedAlert(null)} 
        />
      )}
    </div>
  );
}

export default AlertsView;
