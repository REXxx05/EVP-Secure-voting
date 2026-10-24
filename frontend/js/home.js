// home.js
// Checks the API is running and shows the result on the home page.

const statusEl = document.getElementById('api-status');

apiRequest('/api/health')
  .then((data) => {
    // We use textContent, NOT innerHTML.
    // textContent shows text as plain text, so if it ever contained
    // something like <script>, it wouldn't run (stops XSS).
    statusEl.textContent = data.status;
  })
  .catch(() => {
    statusEl.textContent = 'not reachable';
    statusEl.className = 'error';
  });