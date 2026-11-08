const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  fileId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  originalName: {
    type: String,
    required: [true, 'Original filename is required'],
    trim: true
  },
  fileName: {
    type: String,
    required: true // Encrypted disk filename (e.g. uuid.enc)
  },
  mimeType: {
    type: String,
    default: 'application/octet-stream'
  },
  size: {
    type: Number,
    required: true // Original unencrypted file size in bytes
  },
  encryptedSize: {
    type: Number,
    required: true // Encrypted ciphertext size in bytes
  },
  sha256Hash: {
    type: String,
    required: [true, 'SHA-256 hash is required for integrity verification'],
    index: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  salt: {
    type: String,
    required: true // Unique per-file PBKDF2 random salt in hex
  },
  iv: {
    type: String,
    required: true // Initialization vector / nonce in hex
  },
  authTag: {
    type: String // GCM 16-byte authentication tag in hex
  },
  algorithm: {
    type: String,
    default: 'aes-256-gcm'
  },
  isTampered: {
    type: Boolean,
    default: false // Used for educational demonstration of integrity checking
  },
  uploadDate: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('File', fileSchema);
