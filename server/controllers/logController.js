const ActivityLog = require('../models/ActivityLog');
const File = require('../models/File');
const { getUserLogs, getSecurityAlerts } = require('../services/logService');

/**
 * @route   GET /api/logs
 * @desc    Get user's activity logs
 * @access  Private
 */
exports.getLogs = async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const logs = await getUserLogs(req.user._id, limit);

    res.status(200).json({
      success: true,
      count: logs.length,
      logs
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/logs/alerts
 * @desc    Get security alerts for user
 * @access  Private
 */
exports.getAlerts = async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 20;
    const alerts = await getSecurityAlerts(req.user._id, limit);

    res.status(200).json({
      success: true,
      count: alerts.length,
      alerts
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/logs/stats
 * @desc    Get vault security metrics and activity overview
 * @access  Private
 */
exports.getStats = async (req, res, next) => {
  try {
    const userId = req.user._id;

    const [filesCount, totalSizeResult, totalLogs, alertCount] = await Promise.all([
      File.countDocuments({ owner: userId }),
      File.aggregate([
        { $match: { owner: userId } },
        { $group: { _id: null, totalBytes: { $sum: '$size' }, totalEncryptedBytes: { $sum: '$encryptedSize' } } }
      ]),
      ActivityLog.countDocuments({ user: userId }),
      ActivityLog.countDocuments({
        user: userId,
        status: { $in: ['WARNING', 'ALERT'] }
      })
    ]);

    const totalBytes = totalSizeResult.length > 0 ? totalSizeResult[0].totalBytes : 0;
    const totalEncryptedBytes = totalSizeResult.length > 0 ? totalSizeResult[0].totalEncryptedBytes : 0;

    res.status(200).json({
      success: true,
      stats: {
        totalFiles: filesCount,
        totalBytes,
        totalEncryptedBytes,
        totalLogs,
        securityAlertsCount: alertCount,
        encryptionAlgorithm: 'AES-256-CBC',
        hashingAlgorithm: 'SHA-256',
        integrityStatus: alertCount === 0 ? '100% SECURE' : `${alertCount} ALERTS DETECTED`
      }
    });
  } catch (error) {
    next(error);
  }
};
