const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('../config/env');
const { logActivity } = require('../services/logService');

// Configure Helmet with relaxed CSP allowing blob: for image, iframe/pdf, and worker previews
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      frameSrc: ["'self'", "blob:", "data:"],
      childSrc: ["'self'", "blob:", "data:"],
      objectSrc: ["'self'", "blob:", "data:"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
});

// General API rate limiter
const generalLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this IP. Please try again later.'
  }
});

// Stricter Rate Limiter for Authentication endpoints (prevent brute-force password guessing)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 25, // limit each IP to 25 auth requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    await logActivity({
      user: null,
      username: req.body && req.body.email ? req.body.email : 'Unknown Guest',
      action: 'LOGIN_FAILURE',
      status: 'ALERT',
      details: 'Rate limit exceeded on authentication endpoint (Possible brute force attack)',
      req
    });
    res.status(429).json({
      success: false,
      error: 'Too many authentication attempts. Please wait 15 minutes before trying again.'
    });
  }
});

module.exports = {
  helmetMiddleware,
  generalLimiter,
  authLimiter
};
