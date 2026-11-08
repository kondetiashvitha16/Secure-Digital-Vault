/**
 * Authentication Management Script for Login and Register Pages
 */

document.addEventListener('DOMContentLoaded', () => {
  // Check if session expired param is in URL
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has('expired')) {
    alerts.warning('Session Expired', 'Your session has expired. Please sign in again.');
  }

  // Password visibility toggle
  const togglePasswordBtns = document.querySelectorAll('.password-toggle-btn');
  togglePasswordBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const input = btn.previousElementSibling;
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🔒';
      } else {
        input.type = 'password';
        btn.textContent = '👁️';
      }
    });
  });

  // Password Strength Checker on Register Page
  const passwordInput = document.getElementById('reg-password');
  const strengthBar = document.getElementById('strength-bar');
  const strengthText = document.getElementById('strength-text');

  if (passwordInput && strengthBar && strengthText) {
    passwordInput.addEventListener('input', () => {
      const val = passwordInput.value;
      let score = 0;
      if (val.length >= 8) score += 1;
      if (/[A-Z]/.test(val)) score += 1;
      if (/[0-9]/.test(val)) score += 1;
      if (/[^A-Za-z0-9]/.test(val)) score += 1;

      if (val.length === 0) {
        strengthBar.style.width = '0%';
        strengthText.textContent = '';
      } else if (score <= 1) {
        strengthBar.style.width = '25%';
        strengthBar.style.backgroundColor = '#f43f5e';
        strengthText.textContent = 'Strength: Weak (Min 8 chars, uppercase & number)';
        strengthText.style.color = '#fda4af';
      } else if (score === 2 || score === 3) {
        strengthBar.style.width = '65%';
        strengthBar.style.backgroundColor = '#f59e0b';
        strengthText.textContent = 'Strength: Moderate (Add special characters for strong)';
        strengthText.style.color = '#fde68a';
      } else {
        strengthBar.style.width = '100%';
        strengthBar.style.backgroundColor = '#10b981';
        strengthText.textContent = 'Strength: Strong password';
        strengthText.style.color = '#6ee7b7';
      }
    });
  }

  // Handle Registration Form Submit
  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('reg-username').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const password = document.getElementById('reg-password').value;
      const confirmPassword = document.getElementById('reg-confirm-password').value;
      const submitBtn = registerForm.querySelector('button[type="submit"]');

      if (password !== confirmPassword) {
        alerts.error('Registration Failed', 'Passwords do not match.');
        return;
      }

      if (password.length < 8) {
        alerts.error('Registration Failed', 'Password must be at least 8 characters long.');
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating Account...';

      try {
        const response = await api.post('/auth/register', { username, email, password });
        api.setToken(response.token);
        api.setUser(response.user);
        alerts.success('Account Created', 'Registration successful! Redirecting to dashboard...');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 1000);
      } catch (error) {
        alerts.error('Registration Error', error.message);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Account';
      }
    });
  }

  // Handle Login Form Submit
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;
      const submitBtn = loginForm.querySelector('button[type="submit"]');

      submitBtn.disabled = true;
      submitBtn.textContent = 'Signing in...';

      try {
        const response = await api.post('/auth/login', { email, password });
        api.setToken(response.token);
        api.setUser(response.user);
        alerts.success('Welcome Back', 'Sign in successful. Opening your dashboard...');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 800);
      } catch (error) {
        alerts.error('Sign In Failed', error.message);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In';
      }
    });
  }

  // Handle Demo Fill Button Click
  const demoFillBtn = document.getElementById('demo-fill-btn');
  if (demoFillBtn) {
    demoFillBtn.addEventListener('click', () => {
      fillDemoCredentials('alice@vault.local', 'VaultPass@2026');
    });
  }
});

// Quick-fill helper for demonstration and testing
function fillDemoCredentials(email, pass) {
  const emailInput = document.getElementById('login-email') || document.getElementById('reg-email');
  const passInput = document.getElementById('login-password') || document.getElementById('reg-password');
  const confirmPassInput = document.getElementById('reg-confirm-password');
  const usernameInput = document.getElementById('reg-username');

  if (emailInput) emailInput.value = email;
  if (passInput) passInput.value = pass;
  if (confirmPassInput) confirmPassInput.value = pass;
  if (usernameInput) usernameInput.value = 'DemoUser';

  if (passInput) {
    passInput.dispatchEvent(new Event('input'));
  }
  alerts.info('Demo Auto-Fill', 'Demo credentials populated.');
}
