async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) throw new Error('No active tab');
  return tab;
}

function setStatus(s) {
  document.getElementById('status').textContent = s;
}

function setLog(obj) {
  const el = document.getElementById('log');
  el.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

async function getApiBaseUrl() {
  const { apiBaseUrl } = await chrome.storage.local.get({ apiBaseUrl: 'http://127.0.0.1:8001' });
  return apiBaseUrl;
}

function isRestrictedUrl(url) {
  const u = String(url || '').toLowerCase();
  return u.startsWith('chrome://') || u.startsWith('chrome-extension://') || u.startsWith('edge://') || u.startsWith('about:') || u.startsWith('devtools://');
}

function generateMarker() {
  try { return crypto.randomUUID(); } catch { return `marker_${Date.now()}_${Math.random().toString(16).slice(2)}`; }
}

async function injectMarkerBestEffort(tabId, marker) {
  await chrome.scripting.executeScript({
    target: { tabId },
    world: 'MAIN',
    func: (m) => {
      window.__SECURE_AGENT_MARKER = m;
      window.__AGENT_MARKER = m;
      let meta = document.querySelector('meta[name="secure-agent-marker"]');
      if (!meta) {
        meta = document.createElement('meta');
        meta.setAttribute('name', 'secure-agent-marker');
        document.head && document.head.appendChild(meta);
      }
      meta.setAttribute('content', m);
    },
    args: [marker]
  });
}

async function pollStatus(apiBaseUrl) {
  try {
    const resp = await fetch(`${apiBaseUrl}/api/v1/task-status`);
    const data = await resp.json().catch(() => ({}));
    if (resp.ok) {
      setStatus(`Status: ${data.status} | step ${data.current_step ?? '-'} / ${data.max_steps ?? '-'}`);
      setLog(data);
    }
  } catch {
    // ignore polling errors
  }
}

let pollTimer = null;

async function refreshTabMeta() {
  try {
    const tab = await getActiveTab();
    document.getElementById('tabMeta').textContent = `${tab.title || ''} — ${tab.url || ''}`;
  } catch {
    document.getElementById('tabMeta').textContent = 'No tab';
  }
}

document.getElementById('run').addEventListener('click', async () => {
  const runBtn = document.getElementById('run');
  runBtn.disabled = true;
  try {
    await refreshTabMeta();
    const tab = await getActiveTab();
    if (isRestrictedUrl(tab.url)) throw new Error(`Restricted page: ${tab.url}`);

    // bring tab to front
    try {
      await chrome.tabs.update(tab.id, { active: true });
      await chrome.windows.update(tab.windowId, { focused: true });
    } catch {}

    const apiBaseUrl = await getApiBaseUrl();
    const task = document.getElementById('task').value.trim();
    if (!task) throw new Error('Enter an objective');

    const marker = generateMarker();
    try { await injectMarkerBestEffort(tab.id, marker); } catch {}

    setStatus('Starting…');
    setLog('Sending request…');

    const resp = await fetch(`${apiBaseUrl}/api/v1/agent/run_on_active_tab`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ task, tabId: tab.id, tabUrl: tab.url || '', marker })
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      setStatus('API Error');
      setLog({ status: resp.status, body: data });
      return;
    }

    setStatus('Running…');
    setLog(data);

    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => pollStatus(apiBaseUrl), 1000);
  } catch (e) {
    setStatus('Error');
    setLog(String(e && e.message ? e.message : e));
  } finally {
    runBtn.disabled = false;
  }
});

document.getElementById('stop').addEventListener('click', async () => {
  try {
    const apiBaseUrl = await getApiBaseUrl();
    const resp = await fetch(`${apiBaseUrl}/api/v1/stop-task`, { method: 'POST' });
    const data = await resp.json().catch(() => ({}));
    setStatus('Stopped');
    setLog(data);
  } catch (e) {
    setStatus('Error');
    setLog(String(e && e.message ? e.message : e));
  }
});

refreshTabMeta();
setInterval(refreshTabMeta, 1500);
