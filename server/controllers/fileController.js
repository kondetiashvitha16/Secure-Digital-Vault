const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const File = require('../models/File');
const config = require('../config/env');
const cryptoService = require('../services/cryptoService');
const { logActivity } = require('../services/logService');

// Ensure uploads folder exists
const ensureUploadsDir = async () => {
  try {
    await fs.mkdir(config.UPLOAD_DIR, { recursive: true });
  } catch (err) {
    console.error('Error creating uploads dir:', err);
  }
};
ensureUploadsDir();

/**
 * Safely extract and decode file password from header, body, or query
 */
function getFilePassword(req) {
  let raw = req.headers['x-file-password'];
  if (raw && typeof raw === 'string') {
    try {
      raw = decodeURIComponent(raw);
    } catch {
      // already plain string
    }
  } else if (req.body?.filePassword) {
    raw = req.body.filePassword;
  } else if (req.query?.filePassword) {
    raw = req.query.filePassword;
  }
  return raw && typeof raw === 'string' && raw.length > 0 ? raw : null;
}

/**
 * Construct safe query to find file by UUID fileId or ObjectId
 */
function findFileQuery(id) {
  if (id && /^[0-9a-fA-F]{24}$/.test(id)) {
    return { $or: [{ fileId: id }, { _id: id }] };
  }
  return { fileId: id };
}

/**
 * @route   POST /api/files/upload
 * @desc    Upload, derive key from password (PBKDF2), encrypt (AES-256-GCM), and store ciphertext ONLY
 * @access  Private
 */
exports.uploadFile = async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'Please select a file to upload.'
      });
    }

    const filePassword = getFilePassword(req);
    if (!filePassword) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a password to secure and encrypt this file.'
      });
    }

    const rawBuffer = req.file.buffer;
    const originalName = path.basename(req.file.originalname);
    const mimeType = req.file.mimetype || 'application/octet-stream';
    const originalSize = rawBuffer.length;

    // Step 1: Encrypt the buffer using PBKDF2 key derivation and AES-256-GCM
    // Produces: encryptedBuffer, random 32-byte salt, random 12-byte IV, 16-byte authTag, SHA-256 hash
    const encryptionResult = cryptoService.encryptBufferWithPassword(rawBuffer, filePassword);

    // Step 2: Generate unique file identifier and disk storage filename
    const fileId = uuidv4();
    const diskFileName = `${fileId}.enc`;
    const diskFilePath = path.join(config.UPLOAD_DIR, diskFileName);

    // Step 3: Write ONLY the encrypted ciphertext to disk.
    // The plaintext file buffer is NEVER written to disk.
    await fs.writeFile(diskFilePath, encryptionResult.encryptedBuffer);

    // Step 4: Save metadata in MongoDB (No password or key is stored)
    const fileRecord = await File.create({
      fileId,
      originalName,
      fileName: diskFileName,
      mimeType,
      size: originalSize,
      encryptedSize: encryptionResult.encryptedBuffer.length,
      sha256Hash: encryptionResult.sha256Hash,
      owner: req.user._id,
      salt: encryptionResult.salt,
      iv: encryptionResult.iv,
      authTag: encryptionResult.authTag,
      algorithm: encryptionResult.algorithm,
      uploadDate: new Date()
    });

    // Step 5: Log activity
    await logActivity({
      user: req.user,
      username: req.user.username,
      action: 'FILE_UPLOAD',
      status: 'SUCCESS',
      details: `File "${originalName}" (${(originalSize / 1024).toFixed(2)} KB) encrypted and stored.`,
      fileId,
      fileName: originalName,
      req
    });

    res.status(201).json({
      success: true,
      message: 'File successfully encrypted and stored in vault.',
      file: {
        id: fileRecord._id,
        fileId: fileRecord.fileId,
        originalName: fileRecord.originalName,
        size: fileRecord.size,
        encryptedSize: fileRecord.encryptedSize,
        mimeType: fileRecord.mimeType,
        uploadDate: fileRecord.uploadDate,
        isTampered: fileRecord.isTampered
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/files
 * @desc    Get list of files belonging to current authenticated user
 * @access  Private
 */
exports.getFiles = async (req, res, next) => {
  try {
    const files = await File.find({ owner: req.user._id })
      .select('fileId originalName mimeType size encryptedSize uploadDate isTampered createdAt')
      .sort({ uploadDate: -1 });

    res.status(200).json({
      success: true,
      count: files.length,
      files
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/files/:id/download or POST /api/files/:id/download
 * @desc    Verify password, derive key, decrypt in-memory, verify integrity, and download file
 * @access  Private
 */
exports.downloadFile = async (req, res, next) => {
  try {
    const { id } = req.params;
    const filePassword = getFilePassword(req);

    if (!filePassword) {
      return res.status(400).json({
        success: false,
        error: 'Please enter the file password.'
      });
    }

    // Find file by fileId or MongoDB _id
    const file = await File.findOne(findFileQuery(id));

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found in vault.'
      });
    }

    // Access Control check: Ensure logged-in user is the owner
    if (file.owner.toString() !== req.user._id.toString()) {
      await logActivity({
        user: req.user,
        username: req.user.username,
        action: 'UNAUTHORIZED_ACCESS',
        status: 'ALERT',
        details: `User attempted unauthorized access to file "${file.originalName}".`,
        fileId: file.fileId,
        fileName: file.originalName,
        req
      });

      return res.status(403).json({
        success: false,
        error: 'Unauthorized access attempt blocked.'
      });
    }

    const diskFilePath = path.join(config.UPLOAD_DIR, file.fileName);

    // Read encrypted ciphertext from disk
    let encryptedBuffer;
    try {
      encryptedBuffer = await fs.readFile(diskFilePath);
    } catch (err) {
      return res.status(404).json({
        success: false,
        error: 'Encrypted file storage asset not found.'
      });
    }

    // Step 1: Decrypt using user-provided password + stored salt, IV, and authTag
    let decryptedBuffer;
    try {
      if (file.salt) {
        decryptedBuffer = cryptoService.decryptBufferWithPassword(
          encryptedBuffer,
          filePassword,
          file.salt,
          file.iv,
          file.authTag,
          file.algorithm || 'aes-256-gcm'
        );
      } else {
        decryptedBuffer = cryptoService.decryptBuffer(encryptedBuffer, file.iv);
      }
    } catch (decryptErr) {
      await logActivity({
        user: req.user,
        username: req.user.username,
        action: 'INTEGRITY_MISMATCH',
        status: 'ALERT',
        details: `Failed decryption attempt for file "${file.originalName}". Incorrect password or corrupted data.`,
        fileId: file.fileId,
        fileName: file.originalName,
        req
      });

      return res.status(401).json({
        success: false,
        error: 'Incorrect file password.'
      });
    }

    // Step 2: Recalculate SHA-256 hash and verify integrity
    const integrityResult = cryptoService.verifyIntegrity(decryptedBuffer, file.sha256Hash);

    if (!integrityResult.valid) {
      await logActivity({
        user: req.user,
        username: req.user.username,
        action: 'INTEGRITY_MISMATCH',
        status: 'ALERT',
        details: `Integrity check failed for file "${file.originalName}". Download blocked.`,
        fileId: file.fileId,
        fileName: file.originalName,
        req
      });

      return res.status(409).json({
        success: false,
        error: 'File could not be verified.'
      });
    }

    // Step 3: Integrity Verified - Log & Stream decrypted file
    await logActivity({
      user: req.user,
      username: req.user.username,
      action: 'FILE_DOWNLOAD',
      status: 'SUCCESS',
      details: `File "${file.originalName}" decrypted and downloaded.`,
      fileId: file.fileId,
      fileName: file.originalName,
      req
    });

    // Send file headers and buffer
    res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.originalName)}"`);
    res.setHeader('Content-Length', decryptedBuffer.length);

    return res.send(decryptedBuffer);
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/files/:id/view or POST /api/files/:id/view
 * @desc    Verify password, derive key, decrypt in-memory, and stream file inline for preview
 * @access  Private
 */
exports.viewFile = async (req, res, next) => {
  try {
    const { id } = req.params;
    const filePassword = getFilePassword(req);

    if (!filePassword) {
      return res.status(400).json({
        success: false,
        error: 'Please enter the file password.'
      });
    }

    const file = await File.findOne(findFileQuery(id));

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found.'
      });
    }

    // Access control check
    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized access attempt blocked.'
      });
    }

    const diskFilePath = path.join(config.UPLOAD_DIR, file.fileName);
    let encryptedBuffer;
    try {
      encryptedBuffer = await fs.readFile(diskFilePath);
    } catch (err) {
      return res.status(404).json({
        success: false,
        error: 'Encrypted file storage asset not found.'
      });
    }

    let decryptedBuffer;
    try {
      if (file.salt) {
        decryptedBuffer = cryptoService.decryptBufferWithPassword(
          encryptedBuffer,
          filePassword,
          file.salt,
          file.iv,
          file.authTag,
          file.algorithm || 'aes-256-gcm'
        );
      } else {
        decryptedBuffer = cryptoService.decryptBuffer(encryptedBuffer, file.iv);
      }
    } catch (decryptErr) {
      return res.status(401).json({
        success: false,
        error: 'Incorrect file password.'
      });
    }

    // Verify integrity
    const integrityResult = cryptoService.verifyIntegrity(decryptedBuffer, file.sha256Hash);
    if (!integrityResult.valid) {
      return res.status(409).json({
        success: false,
        error: 'File could not be verified.'
      });
    }

    // Set inline disposition for preview
    res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(file.originalName)}"`);
    res.setHeader('Content-Length', decryptedBuffer.length);

    return res.send(decryptedBuffer);
  } catch (error) {
    next(error);
  }
};

/**
 * @route   DELETE /api/files/:id
 * @desc    Verify password, then permanently delete encrypted file from disk and database
 * @access  Private
 */
exports.deleteFile = async (req, res, next) => {
  try {
    const { id } = req.params;
    const filePassword = getFilePassword(req);

    if (!filePassword) {
      return res.status(400).json({
        success: false,
        error: 'Please enter the file password.'
      });
    }

    const file = await File.findOne(findFileQuery(id));

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found.'
      });
    }

    // Access control check
    if (file.owner.toString() !== req.user._id.toString()) {
      await logActivity({
        user: req.user,
        username: req.user.username,
        action: 'UNAUTHORIZED_ACCESS',
        status: 'ALERT',
        details: `Unauthorized attempt to delete file "${file.originalName}".`,
        fileId: file.fileId,
        fileName: file.originalName,
        req
      });

      return res.status(403).json({
        success: false,
        error: 'Unauthorized access attempt blocked.'
      });
    }

    const diskFilePath = path.join(config.UPLOAD_DIR, file.fileName);
    let encryptedBuffer;
    try {
      encryptedBuffer = await fs.readFile(diskFilePath);
    } catch (err) {
      // File missing on disk
    }

    // Validate the file password before allowing deletion
    if (encryptedBuffer && file.salt) {
      try {
        cryptoService.decryptBufferWithPassword(
          encryptedBuffer,
          filePassword,
          file.salt,
          file.iv,
          file.authTag,
          file.algorithm || 'aes-256-gcm'
        );
      } catch (decryptErr) {
        await logActivity({
          user: req.user,
          username: req.user.username,
          action: 'INTEGRITY_MISMATCH',
          status: 'ALERT',
          details: `Failed deletion attempt for file "${file.originalName}". Incorrect password.`,
          fileId: file.fileId,
          fileName: file.originalName,
          req
        });

        return res.status(401).json({
          success: false,
          error: 'Incorrect file password.'
        });
      }
    }

    // Delete encrypted ciphertext file on disk
    try {
      await fs.unlink(diskFilePath);
    } catch (err) {
      console.warn(`File on disk already removed: ${file.fileName}`);
    }

    // Delete DB record
    await File.deleteOne({ _id: file._id });

    // Log deletion
    await logActivity({
      user: req.user,
      username: req.user.username,
      action: 'FILE_DELETE',
      status: 'SUCCESS',
      details: `File "${file.originalName}" deleted from vault.`,
      fileId: file.fileId,
      fileName: file.originalName,
      req
    });

    res.status(200).json({
      success: true,
      message: 'File deleted successfully.'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   POST /api/files/:id/simulate-tamper
 * @desc    Simulate byte tampering on disk ciphertext to test authTag & integrity rejection
 * @access  Private
 */
exports.simulateTamper = async (req, res, next) => {
  try {
    const { id } = req.params;

    const file = await File.findOne({
      $or: [{ fileId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }],
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found.'
      });
    }

    const diskFilePath = path.join(config.UPLOAD_DIR, file.fileName);

    if (!file.isTampered) {
      const originalCipher = await fs.readFile(diskFilePath);
      await fs.writeFile(`${diskFilePath}.orig`, originalCipher);

      const tamperedCipher = Buffer.from(originalCipher);
      tamperedCipher[tamperedCipher.length - 1] ^= 0xFF; // Flip bits in ciphertext
      await fs.writeFile(diskFilePath, tamperedCipher);

      file.isTampered = true;
      await file.save();

      await logActivity({
        user: req.user,
        username: req.user.username,
        action: 'TAMPER_SIMULATION',
        status: 'WARNING',
        details: `File "${file.originalName}" ciphertext on disk was modified to test integrity verification.`,
        fileId: file.fileId,
        fileName: file.originalName,
        req
      });

      return res.status(200).json({
        success: true,
        isTampered: true,
        message: `Tampering simulated for "${file.originalName}".`
      });
    } else {
      try {
        const originalCipher = await fs.readFile(`${diskFilePath}.orig`);
        await fs.writeFile(diskFilePath, originalCipher);
        await fs.unlink(`${diskFilePath}.orig`);
      } catch (e) {
        // no backup
      }

      file.isTampered = false;
      await file.save();

      await logActivity({
        user: req.user,
        username: req.user.username,
        action: 'TAMPER_SIMULATION',
        status: 'SUCCESS',
        details: `File "${file.originalName}" restored to authentic state.`,
        fileId: file.fileId,
        fileName: file.originalName,
        req
      });

      return res.status(200).json({
        success: true,
        isTampered: false,
        message: `File "${file.originalName}" restored.`
      });
    }
  } catch (error) {
    next(error);
  }
};
