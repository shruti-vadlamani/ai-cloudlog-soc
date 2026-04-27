import React, { useCallback, useEffect, useMemo, useState } from 'react';
import AlertDetailModal from './AlertDetailModal';
import { apiUrl } from '../api';

function AlertsView() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [sortBy, setSortBy] = useState('ensemble_score');
  const [sortOrder, setSortOrder] = useState('desc');
  const [filterOptions, setFilterOptions] = useState({
    users: [],
    attack_types: [],
    mitre_techniques: [],
  });
  const [filters, setFilters] = useState({
    user_name: '',
    min_score: '',
    attack_name: '',
    is_attack: '',
  });
  const [selectedAlert, setSelectedAlert] = useState(null);

  const queryString = useMemo(() => {
    const qs = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
      sort_by: sortBy,
      sort_order: sortOrder,
      ...Object.fromEntries(Object.entries(filters).filter(([_, v]) => v !== '')),
    });
    return qs.toString();
  }, [page, pageSize, sortBy, sortOrder, filters]);

  // Fetch filter options on mount
  useEffect(() => {
    const fetchFilterOptions = async () => {
      try {
        const response = await fetch(apiUrl('/api/stats/filter-options'));
        if (response.ok) {
          const data = await response.json();
          setFilterOptions(data);
        }
      } catch (err) {
        console.error('Failed to fetch filter options:', err);
      }
    };
    fetchFilterOptions();
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(apiUrl(`/api/alerts?${queryString}`));
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
  }, [queryString]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const setFilterValue = (key, value) => {
    setPage(1);
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const onSort = (key) => {
    if (sortBy === key) {
      setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'));
      return;
    }
    setSortBy(key);
    setSortOrder('desc');
  };

  const severityBadge = (score) => {
    if (score >= 0.7) return 'HIGH';
    if (score >= 0.3) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div className="page-stack">
      <section className="page-intro">
        <h2>Alert Triage</h2>
        <p>
          Sort and inspect all ensemble-flagged alerts. Click any row to open full RAG enrichment details.
        </p>
      </section>

      <div className="card">
        <div className="filters-grid">
          <label className="field">
            <span>User</span>
            <select
              value={filters.user_name}
              onChange={(e) => setFilterValue('user_name', e.target.value)}
            >
              <option value="">All Users</option>
              {filterOptions.users.map((user) => (
                <option key={user} value={user}>
                  {user}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span>Min Score</span>
            <input
              type="number"
              min="0"
              max="1"
              step="0.05"
              value={filters.min_score}
              onChange={(e) => setFilterValue('min_score', e.target.value)}
              placeholder="0.70"
            />
          </label>

          <label className="field">
            <span>Attack Type</span>
            <select
              value={filters.attack_name}
              onChange={(e) => setFilterValue('attack_name', e.target.value)}
            >
              <option value="">All Attack Types</option>
              {filterOptions.attack_types.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span>Status</span>
            <select value={filters.is_attack} onChange={(e) => setFilterValue('is_attack', e.target.value)}>
              <option value="">All</option>
              <option value="true">Attack</option>
              <option value="false">Normal</option>
            </select>
          </label>

          <div className="action-inline">
            <button className="btn btn-secondary" onClick={() => {
              setFilters({ user_name: '', min_score: '', attack_name: '', is_attack: '' });
              setSortBy('ensemble_score');
              setSortOrder('desc');
              setPage(1);
            }}>
              Reset
            </button>
            <button className="btn btn-primary" onClick={fetchAlerts}>Refresh</button>
          </div>
        </div>
      </div>

      {error && <div className="error"><strong>Error:</strong> {error}</div>}

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Flagged Alerts</h3>
          <span className="inline-meta">{totalAlerts.toLocaleString()} total</span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th onClick={() => onSort('user_name')} className="th-sort">User</th>
                <th onClick={() => onSort('window')} className="th-sort">Window</th>
                <th onClick={() => onSort('ensemble_score')} className="th-sort">Score</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {!loading && alerts.length > 0 ? alerts.map((alert, idx) => (
                <tr key={`${alert.user_name}-${alert.window}-${idx}`} className="clickable-row" onClick={() => setSelectedAlert(alert)}>
                  <td>{alert.user_name}</td>
                  <td>{new Date(alert.window).toLocaleString()}</td>
                  <td className="score-cell">{Number(alert.ensemble_score || 0).toFixed(3)}</td>
                  <td>
                    <span className={`badge ${severityBadge(alert.ensemble_score) === 'HIGH' ? 'badge-high' : severityBadge(alert.ensemble_score) === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>
                      {severityBadge(alert.ensemble_score)}
                    </span>
                  </td>
                  <td>{alert.attack_name || 'unknown'}</td>
                  <td>
                    <span className={`badge ${alert.is_attack ? 'badge-high' : 'badge-success'}`}>
                      {alert.is_attack ? 'ATTACK' : 'NORMAL'}
                    </span>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="6" className="empty-note">
                    {loading ? 'Loading alerts...' : 'No alerts match current filters.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="pagination">
          <button className="btn btn-secondary" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>Previous</button>
          <span className="page-info">Page {page} of {Math.max(1, Math.ceil(totalAlerts / pageSize))}</span>
          <button className="btn btn-secondary" onClick={() => setPage((p) => p + 1)} disabled={page >= Math.ceil(totalAlerts / pageSize)}>Next</button>
        </div>
      </div>

      {selectedAlert && <AlertDetailModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />}
    </div>
  );
}

export default AlertsView;
