const ActivityLog = require('../models/ActivityLog');

/**
 * Record an activity or security event into the database.
 */
async function logActivity({
  user = null,
  username = 'Anonymous',
  action,
  status = 'SUCCESS',
  details = '',
  fileId = null,
  fileName = null,
  req = null
}) {
  try {
    let ipAddress = '127.0.0.1';
    let userAgent = 'Unknown';

    if (req) {
      ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
      userAgent = req.headers['user-agent'] || 'Unknown';
    }

    const logEntry = new ActivityLog({
      user: user ? (user._id || user) : null,
      username: username || (user && user.username) || 'Anonymous',
      action,
      status,
      details,
      fileId,
      fileName,
      ipAddress,
      userAgent,
      timestamp: new Date()
    });

    await logEntry.save();
    return logEntry;
  } catch (error) {
    console.error('❌ Failed to write activity log:', error.message);
    return null;
  }
}

/**
 * Fetch recent activity logs for a user (or all if admin).
 */
async function getUserLogs(userId, limit = 50) {
  return await ActivityLog.find({ user: userId })
    .sort({ timestamp: -1 })
    .limit(limit)
    .lean();
}

/**
 * Fetch security alerts (WARNING or ALERT status) for a user.
 */
async function getSecurityAlerts(userId, limit = 20) {
  return await ActivityLog.find({
    $or: [
      { user: userId, status: { $in: ['WARNING', 'ALERT', 'FAILURE'] } },
      { user: null, status: 'ALERT' } // System-level alerts
    ]
  })
    .sort({ timestamp: -1 })
    .limit(limit)
    .lean();
}

module.exports = {
  logActivity,
  getUserLogs,
  getSecurityAlerts
};
