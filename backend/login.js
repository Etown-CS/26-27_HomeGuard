/* HomeGuard: js/login.js
   Validates the login form and sends it to the backend.

   Backend contract (Flask):
     POST /api/login   body {email, password}
       200 -> logged in (the server sets the session cookie)
       401 -> {error: "Incorrect email or password."}
       429 -> {error: "Too many failed attempts. Try again in 15 minutes."}
   Implemented in backend/app.py.
   The server must compare the password against users.pwd_hash. Never do that check in the browser.
   Serve the site over HTTPS outside of local testing, since the password travels in this request.
*/
(function () {
  'use strict';

  const LOGIN_URL = '/api/login';
  const AFTER_LOGIN = '/';          // Flask serves the dashboard at / once you are logged in

  const $ = id => document.getElementById(id);
  const form = $('login-form');
  const submit = $('submit');
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  /* ---------- messages ---------- */
  function setError(id, message) {
    const el = $(id);
    el.textContent = message || '';
    el.hidden = !message;
  }
  function setFieldError(field, message) {
    setError(field + '-error', message);
    $(field).setAttribute('aria-invalid', message ? 'true' : 'false');
  }
  function clearErrors() {
    ['email', 'password'].forEach(f => setFieldError(f, ''));
    setError('form-error', '');
  }

  // Shown after a successful sign-up (signup.js redirects here with ?registered=1)
  if (new URLSearchParams(window.location.search).get('registered') === '1') {
    const notice = $('notice');
    notice.textContent = 'Account created. Log in to continue.';
    notice.hidden = false;
  }

  /* ---------- show password ---------- */
  $('show-password').addEventListener('change', e => {
    $('password').type = e.target.checked ? 'text' : 'password';
  });

  /* ---------- validation ---------- */
  function validate(values) {
    const errors = {};
    if (!values.email) errors.email = 'Enter your email.';
    else if (!EMAIL_RE.test(values.email)) errors.email = 'Enter a valid email, like name@example.com.';
    if (!values.password) errors.password = 'Enter your password.';
    return errors;
  }

  /* ---------- submit ---------- */
  form.addEventListener('submit', async e => {
    e.preventDefault();
    clearErrors();

    const values = { email: $('email').value.trim(), password: $('password').value };
    const errors = validate(values);
    const bad = Object.keys(errors);
    if (bad.length) {
      bad.forEach(f => setFieldError(f, errors[f]));
      $(bad[0]).focus();
      return;
    }

    submit.disabled = true;
    submit.textContent = 'Logging in...';
    try {
      const res = await fetch(LOGIN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(values),
      });
      let data = {};
      try { data = await res.json(); } catch (_) { /* no JSON body */ }

      if (res.ok) {
        window.location.href = AFTER_LOGIN;
        return;
      }
      setError('form-error', data.error ||
        (res.status === 401 ? 'Incorrect email or password.' : 'Something went wrong. Try again in a moment.'));
    } catch (err) {
      console.error(err);
      setError('form-error', "Can't reach the HomeGuard server. Check that it's running, then try again.");
    }
    submit.disabled = false;
    submit.textContent = 'Log in';
    $('password').select();
  });
})();