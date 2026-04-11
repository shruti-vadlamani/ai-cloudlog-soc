const { createProxyMiddleware } = require('http-proxy-middleware');

// Use environment variable or default to localhost for development
const target = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000';

console.log(`[setupProxy] Backend target: ${target}`);

module.exports = function(app) {
  app.use(
    ['/api', '/health', '/docs', '/openapi.json'],
    createProxyMiddleware({
      target,
      changeOrigin: true,
      logLevel: 'warn',
      onError: (err, req, res) => {
        console.error('[setupProxy] Error:', err.message);
        res.writeHead(500, {
          'Content-Type': 'application/json',
        });
        res.end(JSON.stringify({ 
          error: 'Backend offline', 
          details: err.message,
          target: target
        }));
      },
    })
  );
};

