import React, { useState, useEffect } from 'react';

function AlertDetailModal({ alert, onClose }) {
  const [enrichedData, setEnrichedData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchEnrichedAlert();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alert]);

  const fetchEnrichedAlert = async () => {
    try {
      setLoading(true);
      const windowParam = encodeURIComponent(alert.window);
      const response = await fetch(`/api/alerts/${alert.user_name}/${windowParam}`);
      if (!response.ok) throw new Error('Failed to fetch enriched alert');
      const data = await response.json();
      setEnrichedData(data);
    } catch (err) {
      console.error('Enrichment error:', err);
      setEnrichedData(null);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (score) => {
    if (score >= 0.7) return <span className="badge badge-high">HIGH</span>;
    if (score >= 0.3) return <span className="badge badge-medium">MEDIUM</span>;
    return <span className="badge badge-low">LOW</span>;
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">Alert Details</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>

        <div className="modal-body">
          {/* Basic Alert Info */}
          <div className="modal-section">
            <h3 className="modal-section-title">🔍 Alert Information</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '0.25rem' }}>User</div>
                <div style={{ fontWeight: 600 }}>{alert.user_name}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Window</div>
                <div style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>{new Date(alert.window).toLocaleString()}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Ensemble Score</div>
                <div style={{ fontWeight: 600, fontSize: '1.25rem', color: '#3b82f6' }}>
                  {alert.ensemble_score?.toFixed(3)}
                </div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Severity</div>
                <div>{getSeverityBadge(alert.ensemble_score)}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Attack Type</div>
                <div style={{ fontWeight: 500 }}>{alert.attack_name || 'Unknown'}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Status</div>
                <div>
                  {alert.is_attack ? (
                    <span className="badge badge-attack">ATTACK</span>
                  ) : (
                    <span className="badge badge-normal">NORMAL</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Model Scores */}
          <div className="modal-section">
            <h3 className="modal-section-title">🤖 Model Scores</h3>
            <div style={{ display: 'grid', gap: '0.75rem' }}>
              {alert.if_norm !== undefined && (
                <div style={{ background: '#334155', padding: '0.75rem', borderRadius: '0.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>Isolation Forest</span>
                    <span style={{ fontWeight: 600 }}>{alert.if_norm?.toFixed(3)}</span>
                  </div>
                  <div className="score-bar" style={{ marginTop: '0.5rem' }}>
                    <div 
                      className="score-fill score-fill-medium"
                      style={{ width: `${(alert.if_norm || 0) * 100}%` }}
                    ></div>
                  </div>
                </div>
              )}
              {alert.lof_norm !== undefined && (
                <div style={{ background: '#334155', padding: '0.75rem', borderRadius: '0.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>LOF (Local Outlier Factor)</span>
                    <span style={{ fontWeight: 600 }}>{alert.lof_norm?.toFixed(3)}</span>
                  </div>
                  <div className="score-bar" style={{ marginTop: '0.5rem' }}>
                    <div 
                      className="score-fill score-fill-medium"
                      style={{ width: `${(alert.lof_norm || 0) * 100}%` }}
                    ></div>
                  </div>
                </div>
              )}
              {alert.ae_norm !== undefined && (
                <div style={{ background: '#334155', padding: '0.75rem', borderRadius: '0.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>Autoencoder</span>
                    <span style={{ fontWeight: 600 }}>{alert.ae_norm?.toFixed(3)}</span>
                  </div>
                  <div className="score-bar" style={{ marginTop: '0.5rem' }}>
                    <div 
                      className="score-fill score-fill-medium"
                      style={{ width: `${(alert.ae_norm || 0) * 100}%` }}
                    ></div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {loading ? (
            <div className="loading">
              <div className="loading-spinner"></div>
              <p>Loading enrichment data...</p>
            </div>
          ) : enrichedData ? (
            <>
              {/* MITRE Techniques */}
              {enrichedData.detection?.techniques && enrichedData.detection.techniques.length > 0 && (
                <div className="modal-section">
                  <h3 className="modal-section-title">⚔️ MITRE ATT&CK Techniques</h3>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {enrichedData.detection.techniques.map((tech, idx) => (
                      <div key={idx} style={{
                        background: '#334155',
                        padding: '0.5rem 1rem',
                        borderRadius: '0.5rem',
                        fontSize: '0.875rem',
                        border: '1px solid #475569'
                      }}>
                        <div style={{ fontWeight: 600, color: '#3b82f6' }}>{tech.technique_id}</div>
                        <div style={{ color: '#94a3b8', fontSize: '0.8125rem' }}>{tech.technique_name}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Detection Patterns */}
              {enrichedData.detection?.matched_patterns && enrichedData.detection.matched_patterns.length > 0 && (
                <div className="modal-section">
                  <h3 className="modal-section-title">🎯 Detection Patterns</h3>
                  <ul style={{ paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {enrichedData.detection.matched_patterns.map((pattern, idx) => (
                      <li key={idx} style={{ color: '#e2e8f0' }}>{pattern}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Playbooks */}
              {enrichedData.detection?.primary_playbooks && enrichedData.detection.primary_playbooks.length > 0 && (
                <div className="modal-section">
                  <h3 className="modal-section-title">📖 Response Playbooks</h3>
                  {enrichedData.detection.primary_playbooks.map((playbook, idx) => (
                    <div key={idx} style={{ 
                      background: '#334155', 
                      padding: '1rem', 
                      borderRadius: '0.5rem',
                      marginBottom: '0.75rem'
                    }}>
                      <div style={{ fontWeight: 600, marginBottom: '0.5rem', fontSize: '1rem' }}>
                        {playbook.name}
                      </div>
                      {playbook.triage_questions && playbook.triage_questions.length > 0 && (
                        <div style={{ marginBottom: '0.75rem' }}>
                          <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '0.25rem' }}>
                            Triage Questions:
                          </div>
                          <ul style={{ paddingLeft: '1.5rem', fontSize: '0.875rem' }}>
                            {playbook.triage_questions.slice(0, 3).map((q, qIdx) => (
                              <li key={qIdx}>{q}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {playbook.containment_steps && playbook.containment_steps.length > 0 && (
                        <div>
                          <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '0.25rem' }}>
                            Containment Steps:
                          </div>
                          <ol style={{ paddingLeft: '1.5rem', fontSize: '0.875rem' }}>
                            {playbook.containment_steps.slice(0, 3).map((step, sIdx) => (
                              <li key={sIdx}>{step}</li>
                            ))}
                          </ol>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Behavioral Context */}
              {enrichedData.behavioral_context && (
                <div className="modal-section">
                  <h3 className="modal-section-title">💡 Behavioral Context</h3>
                  <div style={{ 
                    background: '#334155', 
                    padding: '1rem', 
                    borderRadius: '0.5rem',
                    fontSize: '0.9375rem',
                    lineHeight: '1.6'
                  }}>
                    {enrichedData.behavioral_context}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="modal-section">
              <p style={{ color: '#94a3b8', textAlign: 'center' }}>
                No enrichment data available
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default AlertDetailModal;
