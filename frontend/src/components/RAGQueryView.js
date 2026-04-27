import React, { useState } from 'react';
import { apiUrl } from '../api';

// Simple markdown to HTML converter for SOC analyst responses
function markdownToHtml(text) {
  if (!text) return '';
  let html = text
    // Headers - BOLD BLACK
    .replace(/^### (.+)$/gm, '<h3 style="margin-top: 1rem; margin-bottom: 0.5rem; font-weight: bold; font-size: 1.1rem; color: #000000;">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 style="margin-top: 1.5rem; margin-bottom: 0.5rem; font-weight: bold; font-size: 1.3rem; color: #000000;">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 style="margin-top: 2rem; margin-bottom: 1rem; font-weight: bold; font-size: 1.5rem; color: #000000;">$1</h1>')
    // Horizontal rules
    .replace(/^---+$/gm, '<hr style="margin: 1rem 0; border-top: 1px solid #cccccc;" />')
    // Bold and italic
    .replace(/\*\*(.+?)\*\*/g, '<strong style="color: #000000;">$1</strong>')
    .replace(/\*(.+?)\*/g, '<em style="color: #000000;">$1</em>')
    // Bullet lists
    .replace(/^\* (.+)$/gm, '<li style="margin-left: 1.5rem; color: #000000;">$1</li>')
    .replace(/^\d+\. (.+)$/gm, '<li style="margin-left: 1.5rem; color: #000000;">$1</li>')
    // Code blocks
    .replace(/`([^`]+)`/g, '<code style="background: #f0f0f0; color: #000000; padding: 0.2rem 0.4rem; border-radius: 0.25rem;">$1</code>')
    // Line breaks
    .replace(/\n/g, '<br />');
  
  return html;
}

function RAGQueryView() {
  const [query, setQuery] = useState('');
  const [collection, setCollection] = useState('all');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const exampleQueries = [
    "What are the indicators of privilege escalation in AWS?",
    "How to detect and respond to S3 bucket data exfiltration?",
    "What are the lateral movement techniques in cloud environments?",
    "How to identify suspicious IAM role assumption patterns?",
  ];

  const handleQuery = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(apiUrl('/api/rag/query'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: query.trim(),
          collection: collection === 'all' ? undefined : collection,
          max_results: 5,
          use_llm: true
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Query failed with status ${response.status}`);

      }
      
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message || 'An error occurred while querying the knowledge base');
      console.error('Query error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleExampleQuery = (exampleQuery) => {
    setQuery(exampleQuery);
  };

  const handleDownloadPdf = async () => {
    if (!results || results.results.length === 0) return;

    try {
      setDownloadingPdf(true);
      
      const response = await fetch(apiUrl('/api/rag/export/pdf'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: results.query,
          collection: results.collection,
          max_results: results.results.length
        })
      });

      if (!response.ok) {
        throw new Error('Failed to generate PDF');
      }

      // Get the PDF blob and trigger download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `query_report_${results.query.substring(0, 30).replace(/\s+/g, '_')}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      alert('Failed to download PDF: ' + err.message);
    } finally {
      setDownloadingPdf(false);
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
              style={{ 
                width: '100%', 
                resize: 'vertical',
                padding: '0.75rem',
                borderRadius: '0.375rem',
                border: '1px solid #334155',
                background: '#1e293b',
                color: '#e2e8f0',
                fontFamily: 'inherit'
              }}
            />
          </div>

          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end', marginBottom: '1rem' }}>
            <div className="filter-group">
              <label className="filter-label">Collection</label>
              <select
                value={collection}
                onChange={(e) => setCollection(e.target.value)}
                style={{ 
                  width: '250px',
                  padding: '0.5rem',
                  borderRadius: '0.375rem',
                  border: '1px solid #334155',
                  background: '#1e293b',
                  color: '#e2e8f0'
                }}
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

        {/* Example queries */}
        <div style={{ marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid #334155' }}>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '0.75rem' }}>
            💡 Try one of these example queries:
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {exampleQueries.map((example, idx) => (
              <button
                key={idx}
                onClick={() => handleExampleQuery(example)}
                style={{
                  padding: '0.5rem 0.875rem',
                  fontSize: '0.8125rem',
                  background: '#334155',
                  color: '#3b82f6',
                  border: '1px solid #3b82f6',
                  borderRadius: '0.375rem',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = '#3b82f6';
                  e.currentTarget.style.color = '#ffffff';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = '#334155';
                  e.currentTarget.style.color = '#3b82f6';
                }}
              >
                {example.substring(0, 40)}...
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div style={{
          background: '#7f1d1d',
          border: '1px solid #dc2626',
          color: '#fca5a5',
          padding: '1rem',
          borderRadius: '0.5rem',
          marginBottom: '1.5rem'
        }}>
          <strong>⚠️ Error:</strong> {error}
        </div>
      )}

      {loading && (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '2rem',
          textAlign: 'center'
        }}>
          <div className="loading-spinner" style={{ marginBottom: '1rem' }}></div>
          <p style={{ color: '#e2e8f0' }}>Querying knowledge base...</p>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '0.5rem' }}>
            This may take a moment while we search for relevant information.
          </p>
        </div>
      )}

      {results && results.results && results.results.length > 0 && (
        <div>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '1.5rem',
            padding: '1rem',
            background: '#1e293b',
            borderRadius: '0.5rem'
          }}>
            <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
              ✅ Found <strong>{results.results.length}</strong> relevant result{results.results.length !== 1 ? 's' : ''}
            </div>
            <button
              onClick={handleDownloadPdf}
              disabled={downloadingPdf}
              style={{
                padding: '0.5rem 1rem',
                background: downloadingPdf ? '#64748b' : '#10b981',
                color: 'white',
                border: 'none',
                borderRadius: '0.375rem',
                cursor: downloadingPdf ? 'not-allowed' : 'pointer',
                fontSize: '0.875rem',
                fontWeight: 500,
                transition: 'background 0.2s'
              }}
              onMouseEnter={(e) => !downloadingPdf && (e.currentTarget.style.background = '#059669')}
              onMouseLeave={(e) => !downloadingPdf && (e.currentTarget.style.background = '#10b981')}
            >
              {downloadingPdf ? '⏳ Generating PDF...' : '📄 Download PDF Report'}
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {results.results.map((result, idx) => (
              <div 
                key={idx} 
                className="card" 
                style={{
                  borderLeft: '4px solid #3b82f6',
                  transition: 'transform 0.2s, box-shadow 0.2s',
                  cursor: 'pointer'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'translateX(4px)';
                  e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(59, 130, 246, 0.1)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateX(0)';
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{
                      fontSize: '0.875rem',
                      color: '#3b82f6',
                      fontWeight: 600,
                      marginBottom: '0.25rem'
                    }}>
                      Result #{idx + 1}
                    </div>
                    {result.metadata?.source && (
                      <div style={{
                        fontSize: '0.8125rem',
                        color: '#64748b'
                      }}>
                        📌 <strong>Source:</strong> {result.metadata.source}
                      </div>
                    )}
                    {result.metadata?.collection && (
                      <div style={{
                        fontSize: '0.8125rem',
                        color: '#64748b'
                      }}>
                        📂 <strong>Collection:</strong> {result.metadata.collection}
                      </div>
                    )}
                  </div>
                  <div style={{
                    background: '#1e579f',
                    padding: '0.375rem 0.875rem',
                    borderRadius: '0.5rem',
                    fontSize: '0.8125rem',
                    fontWeight: 600,
                    color: '#10b981',
                    textAlign: 'right'
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
                      View Full Metadata
                    </summary>
                    <div style={{
                      marginTop: '0.5rem',
                      background: '#0f172a',
                      padding: '0.75rem',
                      borderRadius: '0.375rem',
                      fontSize: '0.8125rem',
                      fontFamily: 'monospace',
                      overflowX: 'auto'
                    }}>
                      <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: '#94a3b8', wordBreak: 'break-word' }}>
                        {JSON.stringify(result.metadata, null, 2)}
                      </pre>
                    </div>
                  </details>
                )}
              </div>
            ))}
          </div>

          {results.explanation && (
            <div style={{
              marginTop: '2rem',
              padding: '1.5rem',
              borderRadius: '0.5rem',
              width: '100%',
              boxSizing: 'border-box'
            }}>
              <div style={{
                fontSize: '1rem',
                fontWeight: 600,
                color: '#10b981',
                marginBottom: '1rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                🤖 AI Analysis & Explanation
              </div>
              <div style={{
                color: '#000000',
                lineHeight: '1.8',
                fontSize: '0.95rem',
                wordWrap: 'break-word',
                overflowWrap: 'break-word',
                whiteSpace: 'normal',
                overflow: 'visible',
                maxHeight: 'none',
                maxWidth: '100%'
              }} dangerouslySetInnerHTML={{ __html: markdownToHtml(results.explanation) }}>
              </div>
            </div>
          )}
        </div>
      )}

      {results && results.results && results.results.length === 0 && (
        <div style={{
          background: 'rgba(59, 130, 246, 0.05)',
          border: '1px solid #3b82f6',
          borderRadius: '0.5rem',
          padding: '2rem',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔍</div>
          <p style={{ color: '#e2e8f0', marginBottom: '0.5rem' }}>No results found for your query</p>
          <p style={{ fontSize: '0.875rem', color: '#64748b' }}>
            Try different keywords or select a different collection
          </p>
        </div>
      )}

      {!results && !loading && !error && (
        <div className="card" style={{ background: 'rgba(59, 130, 246, 0.05)', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
          <h3 style={{ color: '#3b82f6', marginBottom: '1rem' }}>💡 Getting Started with Queries</h3>
          <ul style={{ paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem', color: '#cbd5e1' }}>
            <li><strong>Ask about attack techniques</strong> - e.g., "credential dumping", "lateral movement in AWS"</li>
            <li><strong>Search for AWS issues</strong> - e.g., "S3 bucket public access", "insecure EC2 security groups"</li>
            <li><strong>Look up incident response</strong> - e.g., "how to respond to data exfiltration", "ransomware containment"</li>
            <li><strong>Query MITRE techniques</strong> - e.g., "T1078", "privilege escalation"</li>
            <li><strong>Find similar incidents</strong> - e.g., "insider threat indicators", "compromised credentials"</li>
          </ul>
          <div style={{ marginTop: '1.5rem', padding: '1rem', background: 'rgba(16, 185, 129, 0.1)', borderRadius: '0.375rem' }}>
            <p style={{ color: '#10b981', fontSize: '0.875rem', marginBottom: '0.5rem' }}>
              ✨ <strong>Tip:</strong> Use the example queries above or click on them to populate the search box.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default RAGQueryView;
