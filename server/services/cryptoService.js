const crypto = require('crypto');
const config = require('../config/env');

const DEFAULT_ALGORITHM = 'aes-256-gcm';
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32; // 256 bits for AES-256
const PBKDF2_DIGEST = 'sha256';
const GCM_IV_LENGTH = 12; // 12 bytes / 96 bits standard for GCM

/**
 * Compute SHA-256 cryptographic hash of a data buffer.
 * @param {Buffer|string} buffer - The raw binary buffer
 * @returns {string} Hexadecimal SHA-256 string
 */
function generateSha256(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer);
  }
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Derive a 256-bit encryption key from a user password and unique salt using PBKDF2.
 * @param {string} password - The user's per-file password
 * @param {Buffer|string} salt - The cryptographically random salt
 * @returns {Buffer} 32-byte derived key
 */
function deriveKey(password, salt) {
  if (!password) {
    throw new Error('Password is required for key derivation.');
  }
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'hex');
  return crypto.pbkdf2Sync(password, saltBuf, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
}

/**
 * Encrypt a buffer with a user-provided password using PBKDF2 key derivation and AES-256-GCM.
 * @param {Buffer} buffer - The raw plaintext file buffer to encrypt
 * @param {string} password - The user-provided per-file password
 * @returns {{ encryptedBuffer: Buffer, salt: string, iv: string, authTag: string, sha256Hash: string, algorithm: string }}
 */
function encryptBufferWithPassword(buffer, password) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer);
  }
  if (!password || typeof password !== 'string' || password.length === 0) {
    throw new Error('A valid file password is required for encryption.');
  }

  // 1. Compute original unencrypted SHA-256 hash for integrity verification
  const sha256Hash = generateSha256(buffer);

  // 2. Generate a unique 32-byte cryptographically secure random salt per file
  const salt = crypto.randomBytes(32);

  // 3. Derive 256-bit encryption key using PBKDF2
  const derivedKey = deriveKey(password, salt);

  // 4. Generate a unique 12-byte random IV/nonce for GCM
  const iv = crypto.randomBytes(GCM_IV_LENGTH);

  // 5. Encrypt using AES-256-GCM
  const cipher = crypto.createCipheriv(DEFAULT_ALGORITHM, derivedKey, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encryptedBuffer: encrypted,
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    sha256Hash,
    algorithm: DEFAULT_ALGORITHM
  };
}

/**
 * Decrypt an encrypted buffer with a user-provided password using PBKDF2 and AES-256-GCM / CBC.
 * @param {Buffer} encryptedBuffer - The ciphertext buffer from disk
 * @param {string} password - The entered file password
 * @param {string} saltHex - The salt in hex
 * @param {string} ivHex - The IV in hex
 * @param {string} [authTagHex] - The GCM authentication tag in hex
 * @param {string} [algorithm='aes-256-gcm'] - The cipher algorithm used
 * @returns {Buffer} The decrypted raw plaintext file buffer
 */
function decryptBufferWithPassword(encryptedBuffer, password, saltHex, ivHex, authTagHex, algorithm = DEFAULT_ALGORITHM) {
  if (!Buffer.isBuffer(encryptedBuffer)) {
    encryptedBuffer = Buffer.from(encryptedBuffer);
  }
  if (!password || typeof password !== 'string') {
    throw new Error('A valid file password is required for decryption.');
  }
  if (!saltHex || !ivHex) {
    throw new Error('Missing salt or initialization vector for decryption.');
  }

  const derivedKey = deriveKey(password, saltHex);
  const iv = Buffer.from(ivHex, 'hex');

  if (algorithm === 'aes-256-gcm') {
    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
    if (authTagHex) {
      decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    }
    const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
    return decrypted;
  } else if (algorithm === 'aes-256-cbc') {
    const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
    return decrypted;
  } else {
    throw new Error(`Unsupported cipher algorithm: ${algorithm}`);
  }
}

/**
 * Legacy support for AES-256-CBC encryption using server master key (if salt is absent).
 */
function encryptBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer);
  }
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', config.AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return {
    encryptedBuffer: encrypted,
    iv: iv.toString('hex'),
    algorithm: 'aes-256-cbc'
  };
}

function decryptBuffer(encryptedBuffer, ivHex) {
  if (!Buffer.isBuffer(encryptedBuffer)) {
    encryptedBuffer = Buffer.from(encryptedBuffer);
  }
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', config.AES_KEY, iv);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

/**
 * Verify integrity by recalculating SHA-256 and comparing with the recorded hash.
 * @param {Buffer} buffer - The decrypted buffer to verify
 * @param {string} expectedSha256 - The recorded SHA-256 hash
 * @returns {{ valid: boolean, actualHash: string, expectedHash: string }}
 */
function verifyIntegrity(buffer, expectedSha256) {
  const actualHash = generateSha256(buffer);
  let valid = false;
  try {
    const bufActual = Buffer.from(actualHash, 'utf8');
    const bufExpected = Buffer.from(expectedSha256, 'utf8');
    valid = bufActual.length === bufExpected.length && crypto.timingSafeEqual(bufActual, bufExpected);
  } catch {
    valid = (actualHash.toLowerCase() === expectedSha256.toLowerCase());
  }

  return {
    valid,
    actualHash,
    expectedHash: expectedSha256
  };
}

module.exports = {
  DEFAULT_ALGORITHM,
  generateSha256,
  deriveKey,
  encryptBufferWithPassword,
  decryptBufferWithPassword,
  encryptBuffer,
  decryptBuffer,
  verifyIntegrity
};
