const jwt = require('jsonwebtoken');
const User = require('../models/User');
const config = require('../config/env');
const { logActivity } = require('../services/logService');

const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      token = req.headers.authorization.split(' ')[1];

      // Verify token
      const decoded = jwt.verify(token, config.JWT_SECRET);

      // Get user from token ID
      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
        await logActivity({
          user: null,
          username: 'Unknown Token ID',
          action: 'UNAUTHORIZED_ACCESS',
          status: 'WARNING',
          details: `Attempted access with token for non-existent user ID: ${decoded.id}`,
          req
        });
        return res.status(401).json({
          success: false,
          error: 'User belonging to this token no longer exists.'
        });
      }

      // Check if user is locked
      if (user.isLocked()) {
        await logActivity({
          user,
          username: user.username,
          action: 'ACCOUNT_LOCKED',
          status: 'WARNING',
          details: 'Locked user attempted API access.',
          req
        });
        return res.status(403).json({
          success: false,
          error: 'Your account is temporarily locked due to excessive failed attempts. Please try again later.'
        });
      }

      req.user = user;
      next();
    } catch (error) {
      await logActivity({
        user: null,
        username: 'Invalid Token',
        action: 'UNAUTHORIZED_ACCESS',
        status: 'WARNING',
        details: `JWT Verification error: ${error.message}`,
        req
      });
      return res.status(401).json({
        success: false,
        error: 'Authentication failed: Invalid or expired token.'
      });
    }
  }

  if (!token) {
    await logActivity({
      user: null,
      username: 'Unauthenticated Guest',
      action: 'UNAUTHORIZED_ACCESS',
      status: 'WARNING',
      details: `Unauthorized attempt to access protected route: ${req.originalUrl}`,
      req
    });
    return res.status(401).json({
      success: false,
      error: 'Not authorized to access this resource. No token provided.'
    });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({
      success: false,
      error: 'Access denied: Administrator privileges required.'
    });
  }
};

module.exports = { protect, adminOnly };
