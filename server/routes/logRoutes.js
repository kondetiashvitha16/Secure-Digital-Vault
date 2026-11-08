const express = require('express');
const router = express.Router();
const logController = require('../controllers/logController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);

router.get('/', logController.getLogs);
router.get('/alerts', logController.getAlerts);
router.get('/stats', logController.getStats);

module.exports = router;
