async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) throw new Error('No active tab');
  return tab;
}

function setStatus(msg) {
  document.getElementById('status').textContent = msg;
}

function setLog(obj) {
  const el = document.getElementById('log');
  el.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

async function getApiBaseUrl() {
  const { apiBaseUrl } = await chrome.storage.local.get({ apiBaseUrl: 'http://127.0.0.1:8001' });
  return apiBaseUrl;
}

document.getElementById('run').addEventListener('click', async () => {
  try {
    setStatus('Starting…');
    setLog('');

    const task = document.getElementById('task').value.trim();
    if (!task) throw new Error('Enter a task');

    const tab = await getActiveTab();
    const apiBaseUrl = await getApiBaseUrl();

    // We use tab.id as the correlation key. Server maps it to a CDP target.
    const payload = { task, tabId: tab.id, tabUrl: tab.url || '' };

    setStatus(`Calling local agent API… (${apiBaseUrl})`);
    const resp = await fetch(`${apiBaseUrl}/api/v1/agent/run_on_active_tab`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      setStatus('Failed');
      setLog({ status: resp.status, body: data });
      return;
    }

    setStatus('Done');
    setLog(data);
  } catch (e) {
    setStatus('Error');
    setLog(String(e && e.message ? e.message : e));
  }
});
