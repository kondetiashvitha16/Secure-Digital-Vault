const express = require('express');
const path = require('path');
const cors = require('cors');
const morgan = require('morgan');
const { exec } = require('child_process');
const config = require('./config/env');
const { connectDB } = require('./config/db');
const { helmetMiddleware, generalLimiter } = require('./middleware/securityMiddleware');
const errorHandler = require('./middleware/errorHandler');

// Route Imports
const authRoutes = require('./routes/authRoutes');
const fileRoutes = require('./routes/fileRoutes');
const logRoutes = require('./routes/logRoutes');

const app = express();

// 1. Security Headers & CORS
app.use(helmetMiddleware);
app.use(cors());

// 2. Body Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 3. Request Logging (in development)
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// 4. Rate Limiting for general API
app.use('/api', generalLimiter);

// 5. API Routes
app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/logs', logRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'online',
    timestamp: new Date().toISOString(),
    system: 'Secure Digital Vault Cryptographic Subsystem',
    encryption: 'AES-256-CBC',
    integrity: 'SHA-256'
  });
});

// 6. Serve Frontend Static Files
const frontendPath = path.join(__dirname, '../frontend');
app.use(express.static(frontendPath));

// Fallback for HTML routing
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({
      success: false,
      error: `API endpoint not found: ${req.method} ${req.originalUrl}`
    });
  }
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// 7. Error Handling Middleware
app.use(errorHandler);

// 8. Start Server
function autoOpenBrowser(url) {
  const startCmd = process.platform === 'win32'
    ? `start "" "${url}"`
    : process.platform === 'darwin'
    ? `open "${url}"`
    : `xdg-open "${url}"`;

  exec(startCmd, () => {
    // Ignore errors in headless or CI environments
  });
}

async function startServer(portOverride = null, shouldOpenBrowser = false) {
  const listenPort = portOverride || config.PORT || 5000;
  try {
    await connectDB();
    const server = app.listen(listenPort, () => {
      const serverUrl = `http://localhost:${listenPort}`;
      console.log(`\n======================================================`);
      console.log(`🔒 SECURE DIGITAL VAULT SERVER INITIALIZED`);
      console.log(`📡 URL: ${serverUrl}`);
      console.log(`🔐 Cryptography: AES-256-CBC + SHA-256 Hash Verification`);
      console.log(`🛡️ Access Control: JWT & Role/Ownership Isolation`);
      console.log(`📂 Vault Directory: ${config.UPLOAD_DIR}`);
      console.log(`======================================================\n`);

      if (shouldOpenBrowser) {
        console.log(`🌐 Opening default browser at ${serverUrl}...`);
        autoOpenBrowser(serverUrl);
      }
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`\n❌ Error: Port ${listenPort} is already in use by another running process.`);
        console.error(`💡 Tip: Change the PORT in your .env file, or close previous terminal processes holding port ${listenPort}.\n`);
      } else {
        console.error('Server error:', err);
      }
      process.exit(1);
    });

    return server;
  } catch (error) {
    console.error('❌ Fatal Server Initialization Failure:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  // Automatically launch browser when started via "npm start" or "node server/server.js"
  startServer(null, true);
}

module.exports = { app, startServer };
