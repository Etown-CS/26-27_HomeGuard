/* HomeGuard: js/signup.js
   Validates the sign-up form and sends it to the backend.

   Backend contract (Flask):
     POST /api/signup  body {fname, lname, email, password}
       201 -> account created
       409 -> {error: "An account with that email already exists."}
       400 -> {error: "..."} for anything the server rejects
   Implemented in backend/app.py.
   The server must hash the password (e.g. werkzeug generate_password_hash) and store it in
   users.pwd_hash, and must repeat these checks itself. Browser checks are only for convenience.
   Serve the site over HTTPS outside of local testing, since the password travels in this request.
*/
(function () {
  'use strict';

  const SIGNUP_URL = '/api/signup';
  const AFTER_SIGNUP = 'login.html?registered=1';
  const MIN_PASSWORD = 8;

  const $ = id => document.getElementById(id);
  const form = $('signup-form');
  const submit = $('submit');
  const FIELDS = ['fname', 'lname', 'email', 'password', 'confirm'];
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
    FIELDS.forEach(f => setFieldError(f, ''));
    setError('form-error', '');
  }

  /* ---------- show password ---------- */
  $('show-password').addEventListener('change', e => {
    const type = e.target.checked ? 'text' : 'password';
    $('password').type = type;
    $('confirm').type = type;
  });

  /* ---------- validation ---------- */
  function validate(v) {
    const errors = {};
    if (!v.fname) errors.fname = 'Enter your first name.';
    if (!v.lname) errors.lname = 'Enter your last name.';
    if (!v.email) errors.email = 'Enter your email.';
    else if (!EMAIL_RE.test(v.email)) errors.email = 'Enter a valid email, like name@example.com.';
    if (!v.password) errors.password = 'Create a password.';
    else if (v.password.length < MIN_PASSWORD) errors.password = `Use at least ${MIN_PASSWORD} characters.`;
    if (!v.confirm) errors.confirm = 'Enter your password again.';
    else if (v.confirm !== v.password) errors.confirm = "Passwords don't match.";
    return errors;
  }

  /* ---------- submit ---------- */
  form.addEventListener('submit', async e => {
    e.preventDefault();
    clearErrors();

    const values = {
      fname: $('fname').value.trim(),
      lname: $('lname').value.trim(),
      email: $('email').value.trim(),
      password: $('password').value,
      confirm: $('confirm').value,
    };
    const errors = validate(values);
    const bad = FIELDS.filter(f => errors[f]);
    if (bad.length) {
      bad.forEach(f => setFieldError(f, errors[f]));
      $(bad[0]).focus();
      return;
    }

    submit.disabled = true;
    submit.textContent = 'Creating account...';
    try {
      const res = await fetch(SIGNUP_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        // confirm is not sent; the server only needs the password once
        body: JSON.stringify({ fname: values.fname, lname: values.lname, email: values.email, password: values.password }),
      });
      let data = {};
      try { data = await res.json(); } catch (_) { /* no JSON body */ }

      if (res.ok) {
        window.location.href = AFTER_SIGNUP;
        return;
      }
      if (res.status === 409) {
        setFieldError('email', data.error || 'An account with that email already exists.');
        $('email').focus();
      } else {
        setError('form-error', data.error || 'Something went wrong. Try again in a moment.');
      }
    } catch (err) {
      console.error(err);
      setError('form-error', "Can't reach the HomeGuard server. Check that it's running, then try again.");
    }
    submit.disabled = false;
    submit.textContent = 'Create account';
  });
})();