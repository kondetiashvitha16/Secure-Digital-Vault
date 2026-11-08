/**
 * Dashboard Logic for Secure Digital Vault
 * Manages Encrypted File Storage, Password-Protected Downloads/Views/Deletions, Activity Logs, and Notifications.
 */

let currentFiles = [];
let currentLogs = [];
let currentAlerts = [];
let selectedFileToUpload = null;

// State for active modal actions
let activePromptContext = null; // { mode: 'download'|'view'|'delete', file: Object }
let activePreviewState = null; // { file: Object, blob: Blob, password: string, blobUrl: string }

/**
 * Standard Helper to safely retrieve file ID from any backend format
 * Returns String ID or null
 */
function getFileId(file) {
  if (!file) return null;
  const rawId = file.fileId || file._id || file.id || null;
  return rawId ? String(rawId) : null;
}

/**
 * Standard Helper to find a file from currentFiles by ID
 */
function findFileById(targetId) {
  if (!targetId) return null;
  const searchId = String(targetId);
  return currentFiles.find(f => getFileId(f) === searchId) || null;
}

document.addEventListener('DOMContentLoaded', async () => {
  // 1. Session verification
  const token = api.getToken();
  const user = api.getUser();

  if (!token || !user) {
    window.location.href = 'login.html';
    return;
  }

  // Display user information
  const usernameDisplay = document.getElementById('user-display-name');
  const welcomeTitle = document.getElementById('welcome-title');
  const userAvatar = document.getElementById('user-avatar-initial');
  
  const displayName = user.username || 'User';
  if (usernameDisplay) usernameDisplay.textContent = displayName;
  if (welcomeTitle) welcomeTitle.textContent = `Welcome back, ${displayName}`;
  if (userAvatar) userAvatar.textContent = displayName[0].toUpperCase();

  // 2. Setup Tabs
  setupTabs();

  // 3. Setup File Upload Dropzone, Modals & Event Delegation
  setupDropzone();
  setupModals();
  setupFileActionDelegation();

  // 4. Setup Search & Filters
  setupSearch();

  // 5. Setup Password Toggles in Modals
  setupPasswordToggles();

  // 6. Setup Logout
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try {
        await api.post('/auth/logout', {});
      } catch (e) {
        // Continue clearing session
      }
      api.clearSession();
      alerts.info('Signed Out', 'You have been signed out.');
      setTimeout(() => {
        window.location.href = 'login.html';
      }, 500);
    });
  }

  // 7. Initial Data Load
  await refreshDashboard();

  // Polling for live activity logs every 30 seconds
  setInterval(loadLogsAndAlerts, 30000);
});

/**
 * Event Delegation for File Action Buttons (View, Download, Delete)
 */
function setupFileActionDelegation() {
  document.addEventListener('click', (event) => {
    const viewBtn = event.target.closest('.file-view-btn');
    const downloadBtn = event.target.closest('.file-download-btn');
    const deleteBtn = event.target.closest('.file-delete-btn');

    if (viewBtn) {
      const fileId = viewBtn.dataset.fileId;
      if (fileId) {
        promptViewFile(fileId);
      }
      return;
    }

    if (downloadBtn) {
      const fileId = downloadBtn.dataset.fileId;
      if (fileId) {
        promptDownloadFile(fileId);
      }
      return;
    }

    if (deleteBtn) {
      const fileId = deleteBtn.dataset.fileId;
      if (fileId) {
        promptDeleteFile(fileId);
      }
      return;
    }
  });
}

/**
 * Setup Tab Switching
 */
function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');

      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const activePane = document.getElementById(targetTab);
      if (activePane) activePane.classList.add('active');

      if (targetTab === 'logs-tab') loadLogsAndAlerts();
      if (targetTab === 'alerts-tab') loadLogsAndAlerts();
    });
  });
}

/**
 * Password Visibility Toggle Buttons
 */
function setupPasswordToggles() {
  const togglePasswordBtns = document.querySelectorAll('.password-toggle-btn');
  togglePasswordBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const input = btn.previousElementSibling;
      if (input && input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🔒';
      } else if (input) {
        input.type = 'password';
        btn.textContent = '👁️';
      }
    });
  });
}

/**
 * Refresh all dashboard components
 */
async function refreshDashboard() {
  await Promise.allSettled([
    loadStats(),
    loadFiles(),
    loadLogsAndAlerts()
  ]);
}

/**
 * Load Vault Statistics
 */
async function loadStats() {
  try {
    const res = await api.get('/logs/stats');
    if (res && res.success && res.stats) {
      const s = res.stats;
      const totalFilesElem = document.getElementById('stat-total-files');
      const totalStorageElem = document.getElementById('stat-total-storage');
      const activityCountElem = document.getElementById('stat-activity-count');

      if (totalFilesElem) totalFilesElem.textContent = s.totalFiles ?? 0;
      if (totalStorageElem) totalStorageElem.textContent = formatBytes(s.totalBytes ?? 0);
      if (activityCountElem) activityCountElem.textContent = `${s.totalLogs ?? 0} events`;
    }
  } catch (err) {
    console.warn('Stats endpoint unavailable or failed:', err.message);
  }
}

/**
 * Load Files from API
 */
async function loadFiles() {
  const tableBody = document.getElementById('files-table-body');
  if (!tableBody) return;

  try {
    const res = await api.get('/files');
    if (res && res.success) {
      currentFiles = res.files || [];
      renderFiles(currentFiles);
    }
  } catch (err) {
    alerts.error('Failed to Load Files', 'Unable to retrieve your files. Please try again.');
  }
}

/**
 * Render File List using Safe Data Attributes (No inline onclick)
 */
function renderFiles(files) {
  const tableBody = document.getElementById('files-table-body');
  const emptyState = document.getElementById('files-empty-state');
  const countIndicator = document.getElementById('file-count-indicator');
  if (!tableBody) return;

  tableBody.innerHTML = '';

  if (countIndicator) {
    countIndicator.textContent = `${files.length} file${files.length === 1 ? '' : 's'} stored`;
  }

  if (files.length === 0) {
    if (emptyState) emptyState.style.display = 'block';
    return;
  }

  if (emptyState) emptyState.style.display = 'none';

  files.forEach(file => {
    const targetFileId = getFileId(file);
    if (!targetFileId) {
      console.error('File item missing valid identifier:', file);
      return;
    }

    const tr = document.createElement('tr');

    const uploadDateFormatted = new Date(file.uploadDate || file.createdAt || Date.now()).toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });

    const fileIcon = getFileIcon(file.originalName);
    const fileType = getFileTypeDescription(file.originalName, file.mimeType);

    tr.innerHTML = `
      <td>
        <div class="file-name-cell">
          <span class="file-icon">${fileIcon}</span>
          <div>
            <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(file.originalName)}</div>
          </div>
        </div>
      </td>
      <td>
        <span style="font-size: 0.85rem; color: var(--text-secondary);">${fileType}</span>
      </td>
      <td>
        <span style="font-weight: 600;">${formatBytes(file.size)}</span>
      </td>
      <td>
        <span style="font-size: 0.85rem; color: var(--text-secondary);">${uploadDateFormatted}</span>
      </td>
      <td style="text-align: right;">
        <div class="action-buttons" style="justify-content: flex-end;">
          <button class="btn btn-outline btn-sm file-view-btn" data-file-id="${escapeHtml(targetFileId)}">
            👁️ View
          </button>
          <button class="btn btn-primary btn-sm file-download-btn" data-file-id="${escapeHtml(targetFileId)}">
            ⬇️ Download
          </button>
          <button class="btn btn-danger btn-sm file-delete-btn btn-icon" title="Delete File" data-file-id="${escapeHtml(targetFileId)}">
            🗑️
          </button>
        </div>
      </td>
    `;

    tableBody.appendChild(tr);
  });
}

/**
 * Handle Drag & Drop File Upload
 */
function setupDropzone() {
  const dropzone = document.getElementById('upload-dropzone');
  const fileInput = document.getElementById('file-input');
  const selectedInfo = document.getElementById('selected-file-info');
  const fileNameDisplay = document.getElementById('selected-file-name');
  const fileSizeDisplay = document.getElementById('selected-file-size');
  const startUploadBtn = document.getElementById('start-secure-upload-btn');
  const cancelBtn = document.getElementById('cancel-upload-btn');

  if (!dropzone || !fileInput) return;

  dropzone.addEventListener('click', () => fileInput.click());

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });

  function handleFileSelected(file) {
    if (file.size > 50 * 1024 * 1024) {
      alerts.error('File Too Large', 'Maximum allowed file size is 50MB.');
      return;
    }
    selectedFileToUpload = file;
    if (fileNameDisplay) fileNameDisplay.textContent = file.name;
    if (fileSizeDisplay) fileSizeDisplay.textContent = formatBytes(file.size);
    if (selectedInfo) selectedInfo.style.display = 'flex';
  }

  if (cancelBtn) {
    cancelBtn.addEventListener('click', () => {
      selectedFileToUpload = null;
      fileInput.value = '';
      if (selectedInfo) selectedInfo.style.display = 'none';
    });
  }

  // Open "Secure Your File" Password Modal
  if (startUploadBtn) {
    startUploadBtn.addEventListener('click', () => {
      if (!selectedFileToUpload) {
        alerts.warning('No File Selected', 'Please select a file to upload.');
        return;
      }
      openUploadPasswordModal(selectedFileToUpload);
    });
  }
}

/**
 * Setup All Modals and Submit Handlers
 */
function setupModals() {
  // Modal backdrop click-to-close & close buttons
  const allModals = document.querySelectorAll('.modal-backdrop');
  allModals.forEach(modal => {
    const closeBtns = modal.querySelectorAll('.modal-close-btn, .modal-cancel-btn');
    closeBtns.forEach(btn => {
      btn.addEventListener('click', () => closeModal(modal));
    });

    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal(modal);
    });
  });

  // 1. Upload Password Form Submit
  const uploadForm = document.getElementById('upload-password-form');
  const uploadModal = document.getElementById('upload-password-modal');
  const submitUploadBtn = document.getElementById('submit-secure-upload-btn');

  if (uploadForm) {
    uploadForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('upload-file-password').value;
      const confirmPassword = document.getElementById('upload-file-confirm-password').value;

      if (password !== confirmPassword) {
        alerts.error('Password Mismatch', 'Passwords do not match. Please verify your passwords.');
        return;
      }

      if (password.length < 4) {
        alerts.error('Password Too Short', 'File password must be at least 4 characters long.');
        return;
      }

      if (!selectedFileToUpload) {
        alerts.warning('No File Selected', 'Please select a file to upload.');
        closeModal(uploadModal);
        return;
      }

      submitUploadBtn.disabled = true;
      submitUploadBtn.textContent = 'Encrypting & Storing...';

      const formData = new FormData();
      formData.append('file', selectedFileToUpload);
      formData.append('filePassword', password);

      try {
        await api.postForm('/files/upload', formData);
        alerts.success('Upload Successful', 'File uploaded successfully.');
        
        // Reset state
        closeModal(uploadModal);
        uploadForm.reset();
        selectedFileToUpload = null;
        const fileInput = document.getElementById('file-input');
        if (fileInput) fileInput.value = '';
        const selectedInfo = document.getElementById('selected-file-info');
        if (selectedInfo) selectedInfo.style.display = 'none';

        await refreshDashboard();
      } catch (err) {
        alerts.error('Upload Failed', err.message || 'An error occurred while uploading.');
      } finally {
        submitUploadBtn.disabled = false;
        submitUploadBtn.textContent = 'Secure & Upload';
      }
    });
  }

  // 2. Password Prompt Form (for Download, View, and Delete)
  const promptForm = document.getElementById('password-prompt-form');
  const promptModal = document.getElementById('password-prompt-modal');
  const promptSubmitBtn = document.getElementById('prompt-submit-btn');

  if (promptForm) {
    promptForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const enteredPassword = document.getElementById('prompt-file-password').value;
      if (!enteredPassword || !activePromptContext) return;

      const file = activePromptContext.file;
      const mode = activePromptContext.mode;
      const targetId = getFileId(file);

      if (!targetId) {
        alerts.error('Error', 'Invalid file identifier.');
        return;
      }

      promptSubmitBtn.disabled = true;
      const originalBtnText = promptSubmitBtn.textContent;
      promptSubmitBtn.textContent = 'Verifying...';

      if (mode === 'download') {
        try {
          await api.download(`/files/${targetId}/download`, file.originalName, enteredPassword);
          alerts.success('Download Complete', 'File downloaded successfully.');
          closeModal(promptModal);
          promptForm.reset();
          activePromptContext = null;
          await refreshDashboard();
        } catch (err) {
          if (err.status === 401) {
            alerts.error('Incorrect Password', 'Incorrect file password.');
          } else if (err.status === 409) {
            alerts.error('Security Alert', 'File could not be verified.');
            closeModal(promptModal);
          } else {
            alerts.error('Download Failed', err.message || 'Unable to download file.');
          }
        } finally {
          promptSubmitBtn.disabled = false;
          promptSubmitBtn.textContent = originalBtnText;
        }
      } else if (mode === 'view') {
        try {
          const result = await api.fetchBlob(`/files/${targetId}/view`, enteredPassword);
          closeModal(promptModal);
          promptForm.reset();
          activePromptContext = null;

          // Render file preview in the preview modal
          renderFilePreview(file, result.blob, result.contentType, enteredPassword);
        } catch (err) {
          if (err.status === 401) {
            alerts.error('Incorrect Password', 'Incorrect file password.');
          } else if (err.status === 409) {
            alerts.error('Security Alert', 'File could not be verified.');
            closeModal(promptModal);
          } else {
            alerts.error('Preview Failed', err.message || 'Unable to view file.');
          }
        } finally {
          promptSubmitBtn.disabled = false;
          promptSubmitBtn.textContent = originalBtnText;
        }
      } else if (mode === 'delete') {
        try {
          await api.delete(`/files/${targetId}`, enteredPassword);
          alerts.success('File Deleted', 'File deleted successfully.');
          closeModal(promptModal);
          promptForm.reset();
          activePromptContext = null;
          await refreshDashboard();
        } catch (err) {
          if (err.status === 401) {
            alerts.error('Incorrect Password', 'Incorrect file password. The file was not deleted.');
          } else {
            alerts.error('Delete Failed', err.message || 'Unable to delete file.');
          }
        } finally {
          promptSubmitBtn.disabled = false;
          promptSubmitBtn.textContent = originalBtnText;
        }
      }
    });
  }

  // 3. Preview Modal Download Button
  const previewDownloadBtn = document.getElementById('preview-download-btn');
  if (previewDownloadBtn) {
    previewDownloadBtn.addEventListener('click', async () => {
      if (activePreviewState) {
        const file = activePreviewState.file;
        const password = activePreviewState.password;
        const targetId = getFileId(file);
        if (!targetId) return;

        try {
          await api.download(`/files/${targetId}/download`, file.originalName, password);
          alerts.success('Download Complete', 'File downloaded successfully.');
        } catch (err) {
          alerts.error('Download Failed', err.message || 'Unable to download file.');
        }
      }
    });
  }
}

function closeModal(modal) {
  if (!modal) return;
  modal.classList.remove('open');

  if (modal.id === 'file-preview-modal' && activePreviewState) {
    if (activePreviewState.blobUrl) {
      window.URL.revokeObjectURL(activePreviewState.blobUrl);
    }
    activePreviewState = null;
  }

  if (modal.id === 'password-prompt-modal') {
    const promptForm = document.getElementById('password-prompt-form');
    if (promptForm) promptForm.reset();
    activePromptContext = null;
  }
}

function openUploadPasswordModal(file) {
  const modal = document.getElementById('upload-password-modal');
  const fileNameElem = document.getElementById('modal-upload-filename');
  const fileSizeElem = document.getElementById('modal-upload-filesize');
  const passwordInput = document.getElementById('upload-file-password');
  const confirmPasswordInput = document.getElementById('upload-file-confirm-password');

  if (fileNameElem) fileNameElem.textContent = file.name;
  if (fileSizeElem) fileSizeElem.textContent = formatBytes(file.size);
  if (passwordInput) passwordInput.value = '';
  if (confirmPasswordInput) confirmPasswordInput.value = '';

  if (modal) modal.classList.add('open');
  if (passwordInput) setTimeout(() => passwordInput.focus(), 150);
}

/**
 * Trigger Download Flow with Password Prompt
 */
function promptDownloadFile(fileId) {
  const file = findFileById(fileId);
  if (!file) {
    console.error('File not found for ID:', fileId);
    alerts.error('Error', 'Selected file could not be found.');
    return;
  }

  activePromptContext = { mode: 'download', file };

  const modal = document.getElementById('password-prompt-modal');
  const titleElem = document.getElementById('prompt-modal-title');
  const descElem = document.getElementById('prompt-modal-desc');
  const nameElem = document.getElementById('prompt-file-name');
  const sizeElem = document.getElementById('prompt-file-size');
  const iconElem = document.getElementById('prompt-file-icon');
  const passwordInput = document.getElementById('prompt-file-password');
  const submitBtn = document.getElementById('prompt-submit-btn');

  if (titleElem) titleElem.innerHTML = '<span>⬇️</span> Enter File Password';
  if (descElem) descElem.textContent = `Please enter the password to decrypt and download "${file.originalName}".`;
  if (nameElem) nameElem.textContent = file.originalName;
  if (sizeElem) sizeElem.textContent = formatBytes(file.size);
  if (iconElem) iconElem.textContent = getFileIcon(file.originalName);
  if (submitBtn) {
    submitBtn.textContent = 'Download';
    submitBtn.className = 'btn btn-primary btn-sm';
  }
  if (passwordInput) passwordInput.value = '';

  if (modal) modal.classList.add('open');
  if (passwordInput) setTimeout(() => passwordInput.focus(), 150);
}

/**
 * Trigger View Flow with Password Prompt
 */
function promptViewFile(fileId) {
  const file = findFileById(fileId);
  if (!file) {
    console.error('File not found for ID:', fileId);
    alerts.error('Error', 'Selected file could not be found.');
    return;
  }

  activePromptContext = { mode: 'view', file };

  const modal = document.getElementById('password-prompt-modal');
  const titleElem = document.getElementById('prompt-modal-title');
  const descElem = document.getElementById('prompt-modal-desc');
  const nameElem = document.getElementById('prompt-file-name');
  const sizeElem = document.getElementById('prompt-file-size');
  const iconElem = document.getElementById('prompt-file-icon');
  const passwordInput = document.getElementById('prompt-file-password');
  const submitBtn = document.getElementById('prompt-submit-btn');

  if (titleElem) titleElem.innerHTML = '<span>👁️</span> Enter File Password';
  if (descElem) descElem.textContent = `Please enter the password to view "${file.originalName}".`;
  if (nameElem) nameElem.textContent = file.originalName;
  if (sizeElem) sizeElem.textContent = formatBytes(file.size);
  if (iconElem) iconElem.textContent = getFileIcon(file.originalName);
  if (submitBtn) {
    submitBtn.textContent = 'View File';
    submitBtn.className = 'btn btn-primary btn-sm';
  }
  if (passwordInput) passwordInput.value = '';

  if (modal) modal.classList.add('open');
  if (passwordInput) setTimeout(() => passwordInput.focus(), 150);
}

/**
 * Trigger Delete Flow with Password Prompt
 */
function promptDeleteFile(fileId) {
  const file = findFileById(fileId);
  if (!file) {
    console.error('File not found for ID:', fileId);
    alerts.error('Error', 'Selected file could not be found.');
    return;
  }

  activePromptContext = { mode: 'delete', file };

  const modal = document.getElementById('password-prompt-modal');
  const titleElem = document.getElementById('prompt-modal-title');
  const descElem = document.getElementById('prompt-modal-desc');
  const nameElem = document.getElementById('prompt-file-name');
  const sizeElem = document.getElementById('prompt-file-size');
  const iconElem = document.getElementById('prompt-file-icon');
  const passwordInput = document.getElementById('prompt-file-password');
  const submitBtn = document.getElementById('prompt-submit-btn');

  if (titleElem) titleElem.innerHTML = '<span>🗑️</span> Delete File?';
  if (descElem) descElem.textContent = `To permanently delete "${file.originalName}", enter the file password.`;
  if (nameElem) nameElem.textContent = file.originalName;
  if (sizeElem) sizeElem.textContent = formatBytes(file.size);
  if (iconElem) iconElem.textContent = getFileIcon(file.originalName);
  if (submitBtn) {
    submitBtn.textContent = 'Delete File';
    submitBtn.className = 'btn btn-danger btn-sm';
  }
  if (passwordInput) passwordInput.value = '';

  if (modal) modal.classList.add('open');
  if (passwordInput) setTimeout(() => passwordInput.focus(), 150);
}

/**
 * Render File Preview in Modal
 */
async function renderFilePreview(file, blob, contentType, password) {
  const modal = document.getElementById('file-preview-modal');
  const nameElem = document.getElementById('preview-meta-name');
  const typeElem = document.getElementById('preview-meta-type');
  const sizeElem = document.getElementById('preview-meta-size');
  const targetElem = document.getElementById('preview-render-target');

  if (!modal || !targetElem) return;

  // Revoke previous preview blob URL if exists
  if (activePreviewState && activePreviewState.blobUrl) {
    window.URL.revokeObjectURL(activePreviewState.blobUrl);
    activePreviewState.blobUrl = null;
  }

  const ext = (file.originalName.split('.').pop() || '').toLowerCase();
  const fileTypeDesc = getFileTypeDescription(file.originalName, contentType);

  if (nameElem) nameElem.textContent = file.originalName;
  if (typeElem) typeElem.textContent = `(${fileTypeDesc})`;
  if (sizeElem) sizeElem.textContent = formatBytes(file.size);

  targetElem.innerHTML = '';
  let blobUrl = null;

  const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'];
  const textCodeExts = ['txt', 'md', 'json', 'csv', 'js', 'py', 'html', 'css', 'xml', 'log'];

  // 1. Image Preview
  if (imageExts.includes(ext) || contentType.startsWith('image/')) {
    blobUrl = window.URL.createObjectURL(blob);
    const img = document.createElement('img');
    img.src = blobUrl;
    img.alt = file.originalName;
    img.className = 'preview-image';
    targetElem.appendChild(img);
  }
  // 2. PDF Preview
  else if (ext === 'pdf' || contentType === 'application/pdf') {
    const pdfBlob = blob.type === 'application/pdf' ? blob : new Blob([blob], { type: 'application/pdf' });
    blobUrl = window.URL.createObjectURL(pdfBlob);
    const iframe = document.createElement('iframe');
    iframe.src = blobUrl;
    iframe.className = 'preview-pdf';
    iframe.title = file.originalName;
    targetElem.appendChild(iframe);
  }
  // 3. Text / Code Preview (TXT, MD, JSON, CSV, JS, PY, HTML, CSS, XML, LOG)
  else if (textCodeExts.includes(ext) || contentType.startsWith('text/') || contentType.includes('json') || contentType.includes('xml')) {
    try {
      const textContent = await blob.text();
      const pre = document.createElement('pre');
      pre.className = 'preview-text';
      pre.textContent = textContent; // Safely set text without executing scripts
      targetElem.appendChild(pre);
    } catch {
      targetElem.innerHTML = `
        <div class="preview-fallback">
          <p>Unable to display text preview.</p>
        </div>
      `;
    }
  }
  // 4. Unsupported Preview Types
  else {
    targetElem.innerHTML = `
      <div class="preview-fallback">
        <div style="font-size: 3rem; margin-bottom: 0.75rem;">📦</div>
        <h4 style="color: var(--text-primary); margin-bottom: 0.35rem;">Preview Not Available</h4>
        <p>This file format cannot be previewed in the browser. Please download it instead.</p>
      </div>
    `;
  }

  activePreviewState = {
    file,
    blob,
    password,
    blobUrl
  };

  modal.classList.add('open');
}

/**
 * Load Activity Logs & Security Alerts using Promise.allSettled
 */
async function loadLogsAndAlerts() {
  try {
    const results = await Promise.allSettled([
      api.get('/logs?limit=30'),
      api.get('/logs/alerts?limit=15')
    ]);

    const [logsResult, alertsResult] = results;

    if (logsResult.status === 'fulfilled' && logsResult.value && logsResult.value.success) {
      currentLogs = logsResult.value.logs || [];
      renderLogs(currentLogs);
    } else if (logsResult.status === 'rejected') {
      console.warn('Logs endpoint unavailable or failed:', logsResult.reason?.message);
      renderLogs([]);
    }

    if (alertsResult.status === 'fulfilled' && alertsResult.value && alertsResult.value.success) {
      currentAlerts = alertsResult.value.alerts || [];
      renderAlerts(currentAlerts);
    } else if (alertsResult.status === 'rejected') {
      console.warn('Alerts endpoint unavailable or failed:', alertsResult.reason?.message);
      renderAlerts([]);
    }
  } catch (err) {
    console.warn('Unable to load logs or alerts:', err);
  }
}

/**
 * Convert raw activity actions into clean, friendly descriptions
 */
function getFriendlyAction(action) {
  switch (action) {
    case 'FILE_UPLOAD': return 'File Uploaded';
    case 'FILE_DOWNLOAD': return 'File Downloaded';
    case 'FILE_DELETE': return 'File Deleted';
    case 'USER_REGISTER': return 'Account Registered';
    case 'LOGIN_SUCCESS': return 'Sign In';
    case 'LOGOUT': return 'Sign Out';
    case 'LOGIN_FAILURE': return 'Failed Sign In Attempt';
    case 'ACCOUNT_LOCKED': return 'Account Locked';
    case 'UNAUTHORIZED_ACCESS': return 'Unauthorized Access Attempt';
    case 'INTEGRITY_MISMATCH': return 'File Verification Alert';
    case 'TAMPER_SIMULATION': return 'File Update';
    default: return action;
  }
}

function getFriendlyDetails(log) {
  if (log.action === 'FILE_UPLOAD') {
    return log.fileName ? `Uploaded "${log.fileName}"` : 'Uploaded a new file';
  }
  if (log.action === 'FILE_DOWNLOAD') {
    return log.fileName ? `Downloaded "${log.fileName}"` : 'Downloaded a file';
  }
  if (log.action === 'FILE_DELETE') {
    return log.fileName ? `Deleted "${log.fileName}"` : 'Deleted a file';
  }
  if (log.action === 'LOGIN_SUCCESS') {
    return 'Successfully signed in to your account';
  }
  if (log.action === 'LOGOUT') {
    return 'Signed out of your session';
  }
  if (log.action === 'LOGIN_FAILURE') {
    return 'Unusual login activity detected.';
  }
  if (log.action === 'UNAUTHORIZED_ACCESS') {
    return 'Unauthorized access attempt blocked.';
  }
  if (log.action === 'INTEGRITY_MISMATCH') {
    return 'File could not be verified.';
  }
  if (log.action === 'USER_REGISTER') {
    return 'Account successfully created';
  }
  return log.details || 'Account activity recorded';
}

/**
 * Render Audit Log Table
 */
function renderLogs(logs) {
  const tableBody = document.getElementById('logs-table-body');
  const emptyLogs = document.getElementById('logs-empty-state');
  if (!tableBody) return;

  tableBody.innerHTML = '';

  if (logs.length === 0) {
    if (emptyLogs) emptyLogs.style.display = 'block';
    return;
  }

  if (emptyLogs) emptyLogs.style.display = 'none';

  logs.forEach(log => {
    const tr = document.createElement('tr');
    const timeFormatted = new Date(log.timestamp).toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });

    let statusBadge = `<span class="badge badge-success">Completed</span>`;
    if (log.status === 'ALERT') statusBadge = `<span class="badge badge-danger">Alert</span>`;
    if (log.status === 'WARNING') statusBadge = `<span class="badge badge-warning">Notice</span>`;
    if (log.status === 'FAILURE') statusBadge = `<span class="badge badge-danger">Failed</span>`;

    const friendlyAction = getFriendlyAction(log.action);
    const friendlyDetails = getFriendlyDetails(log);

    tr.innerHTML = `
      <td><span style="font-size: 0.85rem; color: var(--text-secondary);">${timeFormatted}</span></td>
      <td><strong style="color: var(--text-primary); font-size: 0.9rem;">${friendlyAction}</strong></td>
      <td>${statusBadge}</td>
      <td style="font-size: 0.875rem; color: var(--text-secondary);">${escapeHtml(friendlyDetails)}</td>
    `;

    tableBody.appendChild(tr);
  });
}

/**
 * Render Security Alerts / Notifications Feed
 */
function renderAlerts(alertsList) {
  const container = document.getElementById('alerts-feed-container');
  const emptyAlerts = document.getElementById('alerts-empty-state');
  if (!container) return;

  container.innerHTML = '';

  if (alertsList.length === 0) {
    if (emptyAlerts) emptyAlerts.style.display = 'block';
    return;
  }

  if (emptyAlerts) emptyAlerts.style.display = 'none';

  alertsList.forEach(alert => {
    const alertCard = document.createElement('div');
    const isHighAlert = alert.status === 'ALERT';
    alertCard.className = `alert-box ${isHighAlert ? 'alert-box-danger' : 'alert-box-warning'}`;
    
    const timeFormatted = new Date(alert.timestamp).toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });

    let friendlyTitle = 'Security Notice';
    let friendlyMessage = 'An unusual activity was detected on your account.';

    if (alert.action === 'INTEGRITY_MISMATCH') {
      friendlyTitle = 'File Verification Alert';
      friendlyMessage = 'File could not be verified.';
    } else if (alert.action === 'UNAUTHORIZED_ACCESS') {
      friendlyTitle = 'Access Denied';
      friendlyMessage = 'Unauthorized access attempt blocked.';
    } else if (alert.action === 'LOGIN_FAILURE' || alert.action === 'ACCOUNT_LOCKED') {
      friendlyTitle = 'Sign In Alert';
      friendlyMessage = 'Unusual login activity detected.';
    } else {
      friendlyMessage = getFriendlyDetails(alert);
    }

    alertCard.innerHTML = `
      <div style="font-size: 1.4rem;">${isHighAlert ? '🚨' : '⚠️'}</div>
      <div style="flex-grow: 1;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.25rem;">
          <strong style="font-size: 0.95rem; color: #fff;">${friendlyTitle}</strong>
          <span style="font-size: 0.75rem; color: rgba(255,255,255,0.7);">${timeFormatted}</span>
        </div>
        <p style="margin: 0; font-size: 0.85rem; color: rgba(255,255,255,0.9);">${escapeHtml(friendlyMessage)}</p>
      </div>
    `;

    container.appendChild(alertCard);
  });
}

/**
 * Search & Filtering for Files Table
 */
function setupSearch() {
  const searchInput = document.getElementById('file-search-input');
  if (!searchInput) return;

  searchInput.addEventListener('input', () => {
    const query = searchInput.value.toLowerCase().trim();
    const filtered = currentFiles.filter(f => 
      f.originalName && f.originalName.toLowerCase().includes(query)
    );
    renderFiles(filtered);
  });
}

// Helpers
function formatBytes(bytes, decimals = 2) {
  if (!+bytes) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function getFileTypeDescription(filename, mimeType) {
  const ext = (filename.split('.').pop() || '').toUpperCase();
  if (['PDF'].includes(ext)) return 'PDF Document';
  if (['JPG', 'JPEG', 'PNG', 'GIF', 'SVG', 'WEBP'].includes(ext)) return `${ext} Image`;
  if (['ZIP', 'RAR', 'TAR', 'GZ', '7Z'].includes(ext)) return `${ext} Archive`;
  if (['MP4', 'MKV', 'AVI', 'MOV'].includes(ext)) return 'Video File';
  if (['MP3', 'WAV', 'OGG'].includes(ext)) return 'Audio File';
  if (['TXT', 'MD', 'JSON', 'CSV', 'JS', 'PY', 'HTML', 'CSS', 'XML', 'LOG', 'DOC', 'DOCX', 'XLS', 'XLSX'].includes(ext)) return `${ext} Document`;
  return ext ? `${ext} File` : 'Binary File';
}

function getFileIcon(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  if (['pdf'].includes(ext)) return '📄';
  if (['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'].includes(ext)) return '🖼️';
  if (['zip', 'rar', 'tar', 'gz', '7z'].includes(ext)) return '📦';
  if (['mp4', 'mkv', 'avi', 'mov'].includes(ext)) return '🎥';
  if (['mp3', 'wav', 'ogg'].includes(ext)) return '🎵';
  if (['txt', 'md', 'json', 'csv', 'js', 'py', 'html', 'css', 'xml', 'log', 'doc', 'docx', 'xls', 'xlsx'].includes(ext)) return '📝';
  return '📁';
}

function escapeHtml(string) {
  if (!string) return '';
  return String(string)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Make file action functions available globally as well
window.getFileId = getFileId;
window.promptViewFile = promptViewFile;
window.promptDownloadFile = promptDownloadFile;
window.promptDeleteFile = promptDeleteFile;

