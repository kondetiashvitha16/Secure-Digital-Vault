const jwt = require('jsonwebtoken');
const User = require('../models/User');
const config = require('../config/env');
const { logActivity } = require('../services/logService');

// Helper to generate JWT Token
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, username: user.username, role: user.role },
    config.JWT_SECRET,
    { expiresIn: config.JWT_EXPIRES_IN }
  );
};

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user account
 * @access  Public
 */
exports.register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    // Validate inputs
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Please provide username, email, and password.'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 8 characters long.'
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username }]
    });

    if (existingUser) {
      const matchField = existingUser.email === email.toLowerCase() ? 'Email' : 'Username';
      return res.status(400).json({
        success: false,
        error: `${matchField} is already registered.`
      });
    }

    // Create user
    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password
    });

    // Generate token
    const token = generateToken(user);

    // Audit log
    await logActivity({
      user,
      username: user.username,
      action: 'USER_REGISTER',
      status: 'SUCCESS',
      details: `New vault user registered: ${user.username} (${user.email})`,
      req
    });

    res.status(201).json({
      success: true,
      message: 'Account registered successfully.',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user & issue JWT
 * @access  Public
 */
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Please provide email and password.'
      });
    }

    // Find user with password field included
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

    if (!user) {
      await logActivity({
        user: null,
        username: email,
        action: 'LOGIN_FAILURE',
        status: 'WARNING',
        details: `Failed login attempt for non-existent email: ${email}`,
        req
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password.'
      });
    }

    // Check if account is locked
    if (user.isLocked()) {
      const remainingMinutes = Math.ceil((user.lockUntil - Date.now()) / (60 * 1000));
      await logActivity({
        user,
        username: user.username,
        action: 'LOGIN_FAILURE',
        status: 'ALERT',
        details: `Login attempt on locked account. ${remainingMinutes}m remaining.`,
        req
      });
      return res.status(403).json({
        success: false,
        error: `Account is temporarily locked due to excessive failed attempts. Please try again in ${remainingMinutes} minutes.`
      });
    }

    // Compare password
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      await user.incLoginAttempts();
      const updatedUser = await User.findById(user._id);
      const attemptsLeft = config.MAX_FAILED_LOGINS - updatedUser.failedLoginAttempts;

      const isNowLocked = updatedUser.isLocked();

      await logActivity({
        user,
        username: user.username,
        action: isNowLocked ? 'ACCOUNT_LOCKED' : 'LOGIN_FAILURE',
        status: isNowLocked ? 'ALERT' : 'WARNING',
        details: isNowLocked
          ? `Account locked after ${config.MAX_FAILED_LOGINS} consecutive failed attempts.`
          : `Invalid password entered. Attempts remaining before lock: ${attemptsLeft}`,
        req
      });

      if (isNowLocked) {
        return res.status(403).json({
          success: false,
          error: `Maximum login attempts exceeded. Your account is locked for 15 minutes.`
        });
      }

      return res.status(401).json({
        success: false,
        error: `Invalid email or password. (${attemptsLeft} attempt${attemptsLeft === 1 ? '' : 's'} remaining before account lock)`
      });
    }

    // Reset failed attempts upon successful login
    if (user.failedLoginAttempts > 0 || user.lockUntil) {
      await user.resetLoginAttempts();
    }

    const token = generateToken(user);

    await logActivity({
      user,
      username: user.username,
      action: 'LOGIN_SUCCESS',
      status: 'SUCCESS',
      details: 'User authenticated successfully via credentials.',
      req
    });

    res.status(200).json({
      success: true,
      message: 'Login successful.',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/auth/me
 * @desc    Get logged in user profile
 * @access  Private
 */
exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   POST /api/auth/logout
 * @desc    Log out user and record activity
 * @access  Private
 */
exports.logout = async (req, res, next) => {
  try {
    await logActivity({
      user: req.user,
      username: req.user.username,
      action: 'LOGOUT',
      status: 'SUCCESS',
      details: 'User logged out of vault session.',
      req
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully.'
    });
  } catch (error) {
    next(error);
  }
};
