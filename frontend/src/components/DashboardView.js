import React, { useState, useEffect } from 'react';

function DashboardView() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetchDashboardStats();
  }, []);

  const fetchDashboardStats = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/stats/overview');
      if (!response.ok) throw new Error('Failed to fetch statistics');
      const data = await response.json();
      setStats(data);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="loading-spinner"></div>
        <p>Loading dashboard statistics...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error">
        <strong>Error:</strong> {error}
      </div>
    );
  }

  return (
    <div>
      <h2 style={{ marginBottom: '1.5rem', fontSize: '1.875rem', fontWeight: 700 }}>
        Security Overview
      </h2>

      {/* Key Metrics */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Alerts</div>
          <div className="stat-value">{stats?.total_alerts || 0}</div>
          <div className="stat-trend">Last 24 hours</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">High Severity</div>
          <div className="stat-value" style={{ color: '#ef4444' }}>
            {stats?.high_severity_count || 0}
          </div>
          <div className="stat-trend">Requires immediate attention</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">Medium Severity</div>
          <div className="stat-value" style={{ color: '#f59e0b' }}>
            {stats?.medium_severity_count || 0}
          </div>
          <div className="stat-trend">Monitor closely</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">Low Severity</div>
          <div className="stat-value" style={{ color: '#64748b' }}>
            {stats?.low_severity_count || 0}
          </div>
          <div className="stat-trend">Informational</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginTop: '1.5rem' }}>
        {/* Attack Distribution */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">🎯 Top Attack Types</h3>
          </div>
          <div>
            {stats?.attack_types && Object.keys(stats.attack_types).length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {Object.entries(stats.attack_types)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 5)
                  .map(([attack_type, count], idx) => (
                  <div key={idx} style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center',
                    padding: '0.75rem',
                    background: '#334155',
                    borderRadius: '0.5rem'
                  }}>
                    <span style={{ fontWeight: 500 }}>{attack_type}</span>
                    <span className="badge badge-attack">{count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: '#64748b', textAlign: 'center', padding: '2rem' }}>
                No attack patterns detected
              </p>
            )}
          </div>
        </div>

        {/* Top Users */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">👤 Top Affected Users</h3>
          </div>
          <div>
            {stats?.top_users && stats.top_users.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {stats.top_users.slice(0, 5).map((item, idx) => (
                  <div key={idx} style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center',
                    padding: '0.75rem',
                    background: '#334155',
                    borderRadius: '0.5rem'
                  }}>
                    <span style={{ fontWeight: 500 }}>{item.user_name}</span>
                    <span className="badge badge-high">{item.alert_count} alerts</span>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: '#64748b', textAlign: 'center', padding: '2rem' }}>
                No user data available
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Alert Timeline */}
      <div className="card" style={{ marginTop: '1.5rem' }}>
        <div className="card-header">
          <h3 className="card-title">📈 Alert Timeline</h3>
        </div>
        <div>
          {stats?.alerts_by_date && stats.alerts_by_date.length > 0 ? (
            <div style={{ overflowX: 'auto' }}>
              <div style={{ display: 'flex', gap: '1rem', padding: '1rem 0', minWidth: '600px' }}>
                {stats.alerts_by_date.map((point, idx) => (
                  <div key={idx} style={{ 
                    flex: 1, 
                    textAlign: 'center',
                    padding: '1rem',
                    background: '#334155',
                    borderRadius: '0.5rem'
                  }}>
                    <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#3b82f6', marginBottom: '0.5rem' }}>
                      {point.count}
                    </div>
                    <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>
                      {point.date}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p style={{ color: '#64748b', textAlign: 'center', padding: '2rem' }}>
              No timeline data available
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export default DashboardView;
