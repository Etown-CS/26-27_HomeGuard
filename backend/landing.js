/* HomeGuard: backend/landing.js
   The landing page is public. If a login session already exists, swap the
   "Log in / Create an account" buttons for an "Open dashboard" button.
   (GET /api/me returns 401 when nobody is logged in.) */
(function () {
  'use strict';

  async function showLoggedInState() {
    try {
      const res = await fetch('/api/me', { credentials: 'same-origin', cache: 'no-store' });
      if (!res.ok) return;                       // not logged in: keep the default buttons
      const user = await res.json();

      const welcome = document.getElementById('welcome');
      welcome.textContent = 'Welcome back, ' + user.fname + '.';
      welcome.hidden = false;
      document.getElementById('guest-actions').hidden = true;
      document.getElementById('user-actions').hidden = false;
    } catch (err) {
      /* server unreachable: keep the default buttons */
    }
  }

  showLoggedInState();
})();