const multer = require('multer');

// Store files in memory so we can compute SHA-256 hash and AES-256 encrypt before writing to disk
const storage = multer.memoryStorage();

// File filter (allow all standard document/media types, block dangerous executable binaries if desired)
const fileFilter = (req, file, cb) => {
  // Disallow suspicious extensions like .exe, .bat, .cmd, .sh, .vbs for security demonstration
  const forbiddenExts = /\.(exe|bat|cmd|vbs|scr|com|pif)$/i;
  if (forbiddenExts.test(file.originalname)) {
    return cb(new Error('Executable and potentially hazardous script files (.exe, .bat, etc.) are restricted from vault upload.'), false);
  }
  cb(null, true);
};

const upload = multer({
  storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB max file size
  },
  fileFilter
});

module.exports = upload;
