/**
 * API Wrapper Service for Secure Digital Vault
 * Handles session tokens, multipart uploads, and secure authenticated file streaming.
 */

const API_BASE = '/api';

const api = {
  getToken() {
    return localStorage.getItem('vault_token');
  },

  setToken(token) {
    localStorage.setItem('vault_token', token);
  },

  getUser() {
    const userStr = localStorage.getItem('vault_user');
    return userStr ? JSON.parse(userStr) : null;
  },

  setUser(user) {
    localStorage.setItem('vault_user', JSON.stringify(user));
  },

  clearSession() {
    localStorage.removeItem('vault_token');
    localStorage.removeItem('vault_user');
  },

  getHeaders(isMultipart = false, filePassword = null) {
    const headers = {};
    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    if (filePassword) {
      headers['X-File-Password'] = encodeURIComponent(filePassword);
    }
    if (!isMultipart) {
      headers['Content-Type'] = 'application/json';
    }
    return headers;
  },

  async request(endpoint, options = {}) {
    const formattedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const url = `${API_BASE}${formattedEndpoint}`;
    const isMultipart = options.body instanceof FormData;
    
    const config = {
      ...options,
      headers: {
        ...this.getHeaders(isMultipart, options.filePassword),
        ...(options.headers || {})
      }
    };

    try {
      const response = await fetch(url, config);

      if (response.status === 401) {
        let errorJson = {};
        try {
          errorJson = await response.json();
        } catch {
          errorJson = {};
        }
        const errMsg = errorJson.error || '';

        // If it is a file-specific password error, do NOT logout the user!
        if (errMsg.toLowerCase().includes('password') || endpoint.includes('/files/')) {
          const err = new Error(errMsg || 'Incorrect file password.');
          err.status = 401;
          err.data = errorJson;
          throw err;
        }

        // Actual auth token expiration
        this.clearSession();
        if (!window.location.pathname.endsWith('login.html') && 
            !window.location.pathname.endsWith('register.html') && 
            !window.location.pathname.endsWith('index.html') && 
            window.location.pathname !== '/') {
          window.location.href = 'login.html?expired=1';
        }
        const err = new Error(errMsg || 'Authentication session expired. Please sign in again.');
        err.status = 401;
        err.data = errorJson;
        throw err;
      }

      let data = {};
      const contentType = response.headers.get('Content-Type') || '';
      if (contentType.includes('application/json')) {
        try {
          data = await response.json();
        } catch {
          data = {};
        }
      } else {
        try {
          const text = await response.text();
          data = { error: text || `Request failed with status ${response.status}` };
        } catch {
          data = {};
        }
      }

      if (!response.ok) {
        const error = new Error(data.error || `Request failed with status ${response.status}`);
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        const netErr = new Error('Network error: Unable to connect to server.');
        netErr.status = 0;
        netErr.originalError = error;
        throw netErr;
      }
      throw error;
    }
  },

  get(endpoint) {
    return this.request(endpoint, { method: 'GET' });
  },

  post(endpoint, body, filePassword = null) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
      filePassword
    });
  },

  postForm(endpoint, formData) {
    return this.request(endpoint, {
      method: 'POST',
      body: formData
    });
  },

  delete(endpoint, filePassword = null) {
    return this.request(endpoint, {
      method: 'DELETE',
      filePassword
    });
  },

  /**
   * Download and stream decrypted file with password verification.
   */
  async download(endpoint, defaultFilename = 'downloaded_file', filePassword = '') {
    const formattedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const url = `${API_BASE}${formattedEndpoint}`;
    const token = this.getToken();

    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    if (filePassword) {
      headers['X-File-Password'] = encodeURIComponent(filePassword);
    }

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers
      });

      if (response.status === 401) {
        let errorJson = {};
        try {
          errorJson = await response.json();
        } catch {
          errorJson = { error: 'Incorrect file password.' };
        }
        const error = new Error(errorJson.error || 'Incorrect file password.');
        error.status = 401;
        error.data = errorJson;
        throw error;
      }

      if (!response.ok) {
        let errorJson = {};
        try {
          errorJson = await response.json();
        } catch {
          errorJson = { error: `Download failed with status ${response.status}` };
        }
        const error = new Error(errorJson.error || 'Download failed.');
        error.status = response.status;
        error.data = errorJson;
        throw error;
      }

      // Extract filename from Content-Disposition header if available
      let filename = defaultFilename;
      const disposition = response.headers.get('Content-Disposition');
      if (disposition && disposition.includes('filename')) {
        const filenameStarMatch = disposition.match(/filename\*=UTF-8''([^;]+)/i);
        if (filenameStarMatch && filenameStarMatch[1]) {
          try {
            filename = decodeURIComponent(filenameStarMatch[1]);
          } catch {
            filename = filenameStarMatch[1];
          }
        } else {
          const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
          if (match && match[1]) {
            try {
              filename = decodeURIComponent(match[1].replace(/['"]/g, ''));
            } catch {
              filename = match[1].replace(/['"]/g, '');
            }
          }
        }
      }

      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();

      // Revoke blob URL safely after download initiates
      setTimeout(() => {
        window.URL.revokeObjectURL(blobUrl);
      }, 2000);

      return {
        success: true,
        filename,
        size: blob.size
      };
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        const netErr = new Error('Network error: Unable to download file.');
        netErr.status = 0;
        netErr.originalError = error;
        throw netErr;
      }
      throw error;
    }
  },

  /**
   * Fetch decrypted blob in-memory for previewing in the browser.
   */
  async fetchBlob(endpoint, filePassword = '') {
    const formattedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const url = `${API_BASE}${formattedEndpoint}`;
    const token = this.getToken();

    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    if (filePassword) {
      headers['X-File-Password'] = encodeURIComponent(filePassword);
    }

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers
      });

      if (response.status === 401) {
        let errorJson = {};
        try {
          errorJson = await response.json();
        } catch {
          errorJson = { error: 'Incorrect file password.' };
        }
        const error = new Error(errorJson.error || 'Incorrect file password.');
        error.status = 401;
        error.data = errorJson;
        throw error;
      }

      if (!response.ok) {
        let errorJson = {};
        try {
          errorJson = await response.json();
        } catch {
          errorJson = { error: `Preview failed with status ${response.status}` };
        }
        const error = new Error(errorJson.error || 'Failed to retrieve file preview.');
        error.status = response.status;
        error.data = errorJson;
        throw error;
      }

      const blob = await response.blob();
      const contentType = response.headers.get('Content-Type') || 'application/octet-stream';
      return {
        blob,
        contentType
      };
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        const netErr = new Error('Network error: Unable to retrieve file preview.');
        netErr.status = 0;
        netErr.originalError = error;
        throw netErr;
      }
      throw error;
    }
  }
};
