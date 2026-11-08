const express = require('express');
const router = express.Router();
const fileController = require('../controllers/fileController');
const { protect } = require('../middleware/authMiddleware');
const upload = require('../middleware/uploadMiddleware');

// All file routes require authentication
router.use(protect);

router.post('/upload', upload.single('file'), fileController.uploadFile);
router.get('/', fileController.getFiles);
router.get('/:id/download', fileController.downloadFile);
router.post('/:id/download', fileController.downloadFile);
router.get('/:id/view', fileController.viewFile);
router.post('/:id/view', fileController.viewFile);
router.delete('/:id', fileController.deleteFile);
router.post('/:id/simulate-tamper', fileController.simulateTamper);

module.exports = router;
