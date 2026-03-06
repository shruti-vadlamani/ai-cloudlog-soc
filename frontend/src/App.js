import React, { useState, useEffect } from 'react';
import './index.css';
import DashboardView from './components/DashboardView';
import AlertsView from './components/AlertsView';
import RAGQueryView from './components/RAGQueryView';
import PipelineView from './components/PipelineView';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [healthStatus, setHealthStatus] = useState('checking');

  useEffect(() => {
    // Check backend health
    fetch('/health')
      .then(res => res.json())
      .then(() => setHealthStatus('healthy'))
      .catch(() => setHealthStatus('error'));
  }, []);

  const renderContent = () => {
    switch(activeTab) {
      case 'dashboard':
        return <DashboardView />;
      case 'alerts':
        return <AlertsView />;
      case 'rag':
        return <RAGQueryView />;
      case 'pipeline':
        return <PipelineView />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <div className="header-content">
          <h1>
            🛡️ Cloud SOC Dashboard
            <span className="header-badge">AI-Powered</span>
          </h1>
          <div className="status-indicator">
            <div className="status-dot" style={{
              background: healthStatus === 'healthy' ? '#10b981' : '#ef4444'
            }}></div>
            <span>{healthStatus === 'healthy' ? 'System Online' : 'Backend Offline'}</span>
          </div>
        </div>
      </header>

      <nav className="nav-tabs">
        <div className="nav-tabs-inner">
          <button 
            className={`nav-tab ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            📊 Dashboard
          </button>
          <button 
            className={`nav-tab ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('alerts')}
          >
            🚨 Alerts
          </button>
          <button 
            className={`nav-tab ${activeTab === 'rag' ? 'active' : ''}`}
            onClick={() => setActiveTab('rag')}
          >
            🔍 RAG Query
          </button>
          <button 
            className={`nav-tab ${activeTab === 'pipeline' ? 'active' : ''}`}
            onClick={() => setActiveTab('pipeline')}
          >
            ⚙️ Pipeline
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
