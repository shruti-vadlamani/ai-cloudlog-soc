import React, { useState, useEffect } from 'react';
import './index.css';
import DashboardView from './components/DashboardView';
import AlertsView from './components/AlertsView';
import PipelineView from './components/PipelineView';
import KnowledgeGraphView from './components/KnowledgeGraphView';
import { apiUrl } from './api';

function App() {
  const [activeTab, setActiveTab] = useState('pipeline');
  const [healthStatus, setHealthStatus] = useState('checking');

  useEffect(() => {
    // Check backend health
    fetch(apiUrl('/health'))
      .then(res => res.json())
      .then(() => setHealthStatus('healthy'))
      .catch(() => setHealthStatus('error'));
  }, []);

  const renderContent = () => {
    switch(activeTab) {
      case 'pipeline':
        return <PipelineView />;
      case 'alerts':
        return <AlertsView />;
      case 'graph':
        return <KnowledgeGraphView />;
      case 'dashboard':
      default:
        return <DashboardView />;
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <div className="header-content">
          <h1>
            Cloud SOC Control Center
            <span className="header-badge">Production</span>
          </h1>
          <div className="status-indicator">
            <div className="status-dot" style={{
              background: healthStatus === 'healthy' ? '#10b981' : '#ef4444'
            }}></div>
            <span>{healthStatus === 'healthy' ? 'Backend Connected' : 'Backend Offline'}</span>
          </div>
        </div>
      </header>

      <nav className="nav-tabs">
        <div className="nav-tabs-inner">
          <button 
            className={`nav-tab ${activeTab === 'pipeline' ? 'active' : ''}`}
            onClick={() => setActiveTab('pipeline')}
          >
            Live Pipeline Status
          </button>
          <button 
            className={`nav-tab ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('alerts')}
          >
            Alert Triage
          </button>
          <button 
            className={`nav-tab ${activeTab === 'graph' ? 'active' : ''}`}
            onClick={() => setActiveTab('graph')}
          >
            Knowledge Graph Explorer
          </button>
          <button 
            className={`nav-tab ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            Security Overview
          </button>
        </div>
      </nav>

      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  );
}

export default App;
