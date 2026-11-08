const mongoose = require('mongoose');

const activityLogSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true,
    default: null
  },
  username: {
    type: String,
    default: 'Anonymous / Guest'
  },
  action: {
    type: String,
    required: true,
    enum: [
      'USER_REGISTER',
      'LOGIN_SUCCESS',
      'LOGIN_FAILURE',
      'LOGOUT',
      'FILE_UPLOAD',
      'FILE_DOWNLOAD',
      'FILE_DELETE',
      'UNAUTHORIZED_ACCESS',
      'INTEGRITY_VERIFIED',
      'INTEGRITY_MISMATCH',
      'TAMPER_SIMULATION',
      'ACCOUNT_LOCKED'
    ]
  },
  status: {
    type: String,
    enum: ['SUCCESS', 'FAILURE', 'WARNING', 'ALERT'],
    default: 'SUCCESS'
  },
  details: {
    type: String,
    default: ''
  },
  fileId: {
    type: String,
    default: null
  },
  fileName: {
    type: String,
    default: null
  },
  ipAddress: {
    type: String,
    default: '127.0.0.1'
  },
  userAgent: {
    type: String,
    default: 'Unknown'
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('ActivityLog', activityLogSchema);
