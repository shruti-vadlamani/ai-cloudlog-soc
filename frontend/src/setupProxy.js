const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  app.use(
    ['/api', '/health', '/docs', '/openapi.json'],
    createProxyMiddleware({
      target: 'http://127.0.0.1:8000',
      changeOrigin: true,
      logLevel: 'warn',
      onError: (err, req, res) => {
        console.error('Proxy Error:', err.message);
        res.writeHead(500, {
          'Content-Type': 'application/json',
        });
        res.end(JSON.stringify({ error: 'Backend offline', details: err.message }));
      },
    })
  );
};
