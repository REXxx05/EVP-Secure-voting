// api.js
// Shared helper for calling our backend API from any page.
// Using one helper means every request is sent the same (safe) way.

async function apiRequest(url, method = 'GET', body = null) {
  const options = {
    method: method,
    headers: { 'Content-Type': 'application/json' },
    // send cookies (our login session) only to our own site
    credentials: 'same-origin'
  };

  // Only add a body for things like POST requests
  if (body) {
    options.body = JSON.stringify(body);
  }

  const res = await fetch(url, options);
  const data = await res.json();

  // If the server sent back an error code, throw it so the page can show a message
  if (!res.ok) {
    throw new Error(data.error || 'Request failed');
  }

  return data;
}