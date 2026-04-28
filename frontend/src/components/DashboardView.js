import React, { useState, useEffect } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { apiUrl } from '../api';

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
      const response = await fetch(apiUrl('/api/stats/overview'));
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
        <p>Loading security overview...</p>
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

  const timelineData = stats?.alerts_by_date || [];
  const topUsers = (stats?.top_users || []).map((u) => ({
    user: u.user || u.user_name || 'unknown',
    alert_count: u.alert_count || 0,
    avg_score: u.avg_score || 0,
  }));

  const attackPieData = Object.entries(stats?.attack_types || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, value]) => ({ name, value }));

  // Enterprise color palette - monochrome with minimal accents
  const pieColors = ['#374151', '#4b5563', '#6b7280', '#9ca3af', '#bcc2c9', '#d1d5db'];

  return (
    <div className="page-stack">
      <section className="page-intro">
        <h2>Security Overview</h2>
        <p>Operational health, alert distribution, and top impacted identities.</p>
      </section>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Alerts</div>
          <div className="stat-value">{stats?.total_alerts || 0}</div>
          <div className="stat-trend">Current dataset</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">Critical Severity</div>
          <div className="stat-value stat-critical">
            {stats?.high_severity_count || 0}
          </div>
          <div className="stat-trend">Immediate attention</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">High Severity</div>
          <div className="stat-value stat-high">
            {stats?.medium_severity_count || 0}
          </div>
          <div className="stat-trend">Needs triage</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">Unique Users</div>
          <div className="stat-value stat-neutral">
            {stats?.unique_users_affected || 0}
          </div>
          <div className="stat-trend">Distinct identities</div>
        </div>
      </div>

      <div className="two-col-layout">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Top Affected Users</h3>
          </div>
          {topUsers.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={topUsers.slice(0, 8)} layout="vertical" margin={{ left: 100, right: 16, top: 8, bottom: 8 }}>
                <CartesianGrid strokeDasharray="0" stroke="#e5e7eb" vertical={false} />
                <XAxis type="number" stroke="#6b7280" style={{ fontSize: '12px' }} />
                <YAxis dataKey="user" type="category" width={90} stroke="#6b7280" style={{ fontSize: '12px' }} />
                <Tooltip 
                  contentStyle={{ background: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '6px' }}
                  labelStyle={{ color: '#111827' }}
                />
                <Bar dataKey="alert_count" fill="#374151" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="empty-note">No user distribution available.</p>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Attack Type Distribution</h3>
          </div>
          {attackPieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie data={attackPieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label={{ fontSize: 12, fill: '#374151' }}>
                  {attackPieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={pieColors[index % pieColors.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ background: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '6px' }}
                  labelStyle={{ color: '#111827' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="empty-note">No attack distribution available.</p>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Alert Volume Timeline</h3>
        </div>
        {timelineData.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={timelineData} margin={{ left: 20, right: 20, top: 16, bottom: 8 }}>
              <CartesianGrid strokeDasharray="0" stroke="#e5e7eb" vertical={false} />
              <XAxis dataKey="date" stroke="#6b7280" style={{ fontSize: '12px' }} />
              <YAxis stroke="#6b7280" style={{ fontSize: '12px' }} />
              <Tooltip 
                contentStyle={{ background: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '6px' }}
                labelStyle={{ color: '#111827' }}
              />
              <Bar dataKey="count" fill="#4b5563" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <p className="empty-note">No timeline data available.</p>
        )}
      </div>
    </div>
  );
}

export default DashboardView;
