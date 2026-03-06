import React, { useState } from 'react';

function RAGQueryView() {
  const [query, setQuery] = useState('');
  const [collection, setCollection] = useState('all');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const handleQuery = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/rag/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: query.trim(),
          collection: collection === 'all' ? undefined : collection,
          top_k: 5
        })
      });

      if (!response.ok) throw new Error('Query failed');
      
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: '1.5rem', fontSize: '1.875rem', fontWeight: 700 }}>
        🔍 RAG Knowledge Base Query
      </h2>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <form onSubmit={handleQuery}>
          <div style={{ marginBottom: '1rem' }}>
            <label className="filter-label" style={{ display: 'block', marginBottom: '0.5rem' }}>
              Search Query
            </label>
            <textarea
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter your security-related query... (e.g., 'privilege escalation techniques', 'S3 bucket misconfigurations')"
              rows={4}
              style={{ width: '100%', resize: 'vertical' }}
            />
          </div>

          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
            <div className="filter-group">
              <label className="filter-label">Collection</label>
              <select
                value={collection}
                onChange={(e) => setCollection(e.target.value)}
                style={{ width: '250px' }}
              >
                <option value="all">All Collections</option>
                <option value="threat_intelligence">Threat Intelligence</option>
                <option value="behavioral_incidents">Behavioral Incidents</option>
              </select>
            </div>

            <button type="submit" className="btn btn-primary" disabled={loading || !query.trim()}>
              {loading ? 'Searching...' : '🔍 Search'}
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="error">
          <strong>Error:</strong> {error}
        </div>
      )}

      {loading && (
        <div className="loading">
          <div className="loading-spinner"></div>
          <p>Querying knowledge base...</p>
        </div>
      )}

      {results && results.results && results.results.length > 0 && (
        <div>
          <div style={{ 
            marginBottom: '1rem', 
            color: '#94a3b8', 
            fontSize: '0.875rem' 
          }}>
            Found {results.results.length} results in {results.query_time?.toFixed(3)}s
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {results.results.map((result, idx) => (
              <div key={idx} className="card" style={{ 
                borderLeft: '4px solid #3b82f6',
                transition: 'transform 0.2s',
                cursor: 'pointer'
              }}
              onMouseEnter={(e) => e.currentTarget.style.transform = 'translateX(4px)'}
              onMouseLeave={(e) => e.currentTarget.style.transform = 'translateX(0)'}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ 
                      fontSize: '0.875rem', 
                      color: '#3b82f6', 
                      fontWeight: 600,
                      marginBottom: '0.25rem'
                    }}>
                      {result.metadata?.source || 'Knowledge Base'}
                    </div>
                    <div style={{ 
                      fontSize: '0.8125rem', 
                      color: '#64748b' 
                    }}>
                      Collection: {result.metadata?.collection || 'Unknown'}
                    </div>
                  </div>
                  <div style={{
                    background: '#334155',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '0.5rem',
                    fontSize: '0.8125rem',
                    fontWeight: 600,
                    color: '#10b981'
                  }}>
                    {(result.similarity * 100).toFixed(1)}% match
                  </div>
                </div>

                <div style={{ 
                  color: '#e2e8f0', 
                  lineHeight: '1.6',
                  fontSize: '0.9375rem',
                  marginBottom: '0.75rem'
                }}>
                  {result.content}
                </div>

                {result.metadata && Object.keys(result.metadata).length > 0 && (
                  <details style={{ 
                    marginTop: '0.75rem',
                    paddingTop: '0.75rem',
                    borderTop: '1px solid #334155'
                  }}>
                    <summary style={{ 
                      cursor: 'pointer', 
                      color: '#94a3b8', 
                      fontSize: '0.875rem',
                      fontWeight: 500
                    }}>
                      View Metadata
                    </summary>
                    <div style={{ 
                      marginTop: '0.5rem',
                      background: '#0f172a',
                      padding: '0.75rem',
                      borderRadius: '0.375rem',
                      fontSize: '0.8125rem',
                      fontFamily: 'monospace'
                    }}>
                      <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: '#94a3b8' }}>
                        {JSON.stringify(result.metadata, null, 2)}
                      </pre>
                    </div>
                  </details>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {results && results.results && results.results.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">🔍</div>
          <p>No results found for your query</p>
          <p style={{ fontSize: '0.875rem', color: '#64748b', marginTop: '0.5rem' }}>
            Try different keywords or select a different collection
          </p>
        </div>
      )}

      {!results && !loading && (
        <div className="card" style={{ background: 'rgba(59, 130, 246, 0.05)' }}>
          <h3 style={{ color: '#3b82f6', marginBottom: '1rem' }}>💡 Query Tips</h3>
          <ul style={{ paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <li>Ask about specific attack techniques (e.g., "credential dumping", "lateral movement")</li>
            <li>Search for AWS service security issues (e.g., "S3 bucket public access")</li>
            <li>Look up incident response procedures (e.g., "how to respond to data exfiltration")</li>
            <li>Query MITRE ATT&CK tactics and techniques</li>
            <li>Find similar past security incidents from your behavioral data</li>
          </ul>
        </div>
      )}
    </div>
  );
}

export default RAGQueryView;
