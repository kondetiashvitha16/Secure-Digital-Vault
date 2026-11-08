/**
 * Toast and Modal Alert Utility for Secure Digital Vault
 */

const alerts = {
  getContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }
    return container;
  },

  showToast({ title, message, type = 'info', duration = 4500 }) {
    const container = this.getContainer();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error') icon = '🚨';
    if (type === 'warning') icon = '⚠️';

    toast.innerHTML = `
      <div class="toast-icon">${icon}</div>
      <div class="toast-content">
        <div class="toast-title">${title}</div>
        <div class="toast-body">${message}</div>
      </div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },

  success(title, message) {
    this.showToast({ title, message, type: 'success' });
  },

  error(title, message) {
    this.showToast({ title, message, type: 'error', duration: 6000 });
  },

  warning(title, message) {
    this.showToast({ title, message, type: 'warning', duration: 5000 });
  },

  info(title, message) {
    this.showToast({ title, message, type: 'info' });
  },

  copyToClipboard(text, label = 'Text') {
    navigator.clipboard.writeText(text).then(() => {
      this.success('Copied to Clipboard', `${label} copied successfully.`);
    }).catch(() => {
      this.warning('Copy Failed', 'Unable to copy text to clipboard.');
    });
  }
};
