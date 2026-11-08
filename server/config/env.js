const dotenv = require('dotenv');
const crypto = require('crypto');
const path = require('path');

// Load .env file from root
dotenv.config({ path: path.join(__dirname, '../../.env') });

// Helper to validate or generate 32-byte AES key
function getValidatedAesKey() {
  let keyHex = process.env.AES_ENCRYPTION_KEY;
  if (!keyHex || keyHex.length !== 64) {
    console.warn('⚠️ [WARNING] AES_ENCRYPTION_KEY is missing or not 64 hex characters (32 bytes). Using a generated secure key for this session.');
    const generatedKey = crypto.randomBytes(32);
    return generatedKey;
  }
  return Buffer.from(keyHex, 'hex');
}

const config = {
  PORT: process.env.PORT || 5000,
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/secure_digital_vault',
  JWT_SECRET: process.env.JWT_SECRET || 'fallback_default_jwt_secret_change_in_production_2026',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',
  AES_KEY: getValidatedAesKey(),
  UPLOAD_DIR: path.join(__dirname, '../uploads'),
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX, 10) || 200,
  MAX_FAILED_LOGINS: 5,
  LOCK_TIME_MS: 15 * 60 * 1000 // 15 minutes lock
};

module.exports = config;
