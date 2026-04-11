import React, { useEffect, useState } from 'react';
import { apiUrl } from '../api';

function AlertDetailModal({ alert, onClose }) {
  const [enriched, setEnriched] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchEnrichment = async () => {
      try {
        setLoading(true);
        const windowParam = encodeURIComponent(alert.window);
        const response = await fetch(apiUrl(`/api/alerts/${alert.user_name}/${windowParam}`));
        if (!response.ok) throw new Error('Failed to load enrichment');
        setEnriched(await response.json());
      } catch (err) {
        console.error(err);
        setEnriched(null);
      } finally {
        setLoading(false);
      }
    };

    fetchEnrichment();
  }, [alert]);

  const detail = enriched?.detection || {};
  const context = enriched?.behavioral_context || {};
  const retrieval = enriched?.rag_retrieval || {};

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">Alert Enrichment</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>

        {loading ? (
          <div className="loading"><div className="loading-spinner"></div><p>Loading enrichment...</p></div>
        ) : (
          <div className="modal-body">
            <div className="modal-section">
              <h3 className="modal-section-title">Alert Snapshot</h3>
              <div className="details-grid">
                <div><span>User</span><strong>{alert.user_name}</strong></div>
                <div><span>Window</span><strong>{new Date(alert.window).toLocaleString()}</strong></div>
                <div><span>Ensemble Score</span><strong>{Number(alert.ensemble_score || 0).toFixed(3)}</strong></div>
                <div><span>Attack Type</span><strong>{alert.attack_name || 'unknown'}</strong></div>
              </div>
            </div>

            <div className="modal-section">
              <h3 className="modal-section-title">MITRE Techniques</h3>
              {(detail.techniques || []).length > 0 ? (
                <div className="chip-row">
                  {detail.techniques.map((t) => (
                    <div className="chip" key={`${t.technique_id}-${t.name}`}>
                      <strong>{t.technique_id}</strong>
                      <span>{t.name}</span>
                    </div>
                  ))}
                </div>
              ) : <p className="empty-note">No techniques mapped.</p>}
            </div>

            <div className="modal-section">
              <h3 className="modal-section-title">Matched Patterns</h3>
              {(detail.matched_patterns || []).length > 0 ? (
                <div className="stack-list">
                  {detail.matched_patterns.map((p) => (
                    <div className="stack-item" key={p.pattern_id || p.name}>
                      <div className="stack-header">
                        <strong>{p.name}</strong>
                        <span className="badge badge-low">score {Number(p.match_score || 0).toFixed(2)}</span>
                      </div>
                      <p>{p.description || 'No description provided.'}</p>
                      {Array.isArray(p.matched_features) && p.matched_features.length > 0 && (
                        <div className="inline-meta">Matched features: {p.matched_features.join(', ')}</div>
                      )}
                    </div>
                  ))}
                </div>
              ) : <p className="empty-note">No matched patterns.</p>}
            </div>

            <div className="modal-section">
              <h3 className="modal-section-title">Playbooks</h3>
              {(detail.primary_playbooks || []).length > 0 ? (
                <div className="stack-list">
                  {detail.primary_playbooks.map((pb) => (
                    <div className="stack-item" key={pb.playbook_id || pb.name}>
                      <div className="stack-header">
                        <strong>{pb.playbook_id}</strong>
                        <span>{pb.name}</span>
                      </div>
                      {Array.isArray(pb.containment_steps) && pb.containment_steps.length > 0 && (
                        <ol>
                          {pb.containment_steps.slice(0, 4).map((s, idx) => (
                            <li key={`${pb.playbook_id}-${idx}`}>{typeof s === 'string' ? s : (s.action || JSON.stringify(s))}</li>
                          ))}
                        </ol>
                      )}
                    </div>
                  ))}
                </div>
              ) : <p className="empty-note">No playbook guidance available.</p>}
            </div>

            <div className="modal-section">
              <h3 className="modal-section-title">Similar Past Incidents</h3>
              {(retrieval.similar_past_incidents || []).length > 0 ? (
                <div className="stack-list">
                  {retrieval.similar_past_incidents.map((item, idx) => (
                    <div className="stack-item" key={`${item.user || 'u'}-${idx}`}>
                      <div className="stack-header">
                        <strong>{item.attack_name || 'unknown'}</strong>
                        <span>similarity {Number(item.similarity || 0).toFixed(3)}</span>
                      </div>
                      <p>{item.summary || item.content || 'No summary available.'}</p>
                    </div>
                  ))}
                </div>
              ) : <p className="empty-note">No similar incidents retrieved.</p>}
            </div>

            <div className="modal-section">
              <h3 className="modal-section-title">Behavioral Context</h3>
              <pre className="json-block">{JSON.stringify(context, null, 2)}</pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default AlertDetailModal;
