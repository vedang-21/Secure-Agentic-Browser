// Helper to get current tab info
async function getActiveTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) throw new Error('No active tab found');
    return tab;
}

// UI Update Helpers
function updateUI(status, logMsg) {
    document.getElementById('status').textContent = status;
    const logEl = document.getElementById('log');
    logEl.textContent = typeof logMsg === 'string' ? logMsg : JSON.stringify(logMsg, null, 2);
}

function generateMarker() {
    // Use Web Crypto if available; fallback to a simple random string.
    try {
        return crypto.randomUUID();
    } catch {
        return `marker_${Date.now()}_${Math.random().toString(16).slice(2)}`;
    }
}

function isRestrictedUrl(url) {
    const u = String(url || '').toLowerCase();
    return (
        u.startsWith('chrome://') ||
        u.startsWith('chrome-extension://') ||
        u.startsWith('edge://') ||
        u.startsWith('about:') ||
        u.startsWith('devtools://')
    );
}

async function getApiBaseUrl() {
    // Default to the FastAPI server port used by main.py
    const { apiBaseUrl } = await chrome.storage.local.get({ apiBaseUrl: 'http://127.0.0.1:8001' });
    return apiBaseUrl;
}

async function captureActiveTabDom(tabId) {
    const [{ result }] = await chrome.scripting.executeScript({
        target: { tabId },
        world: 'MAIN',
        func: () => {
            return {
                url: location.href,
                title: document.title,
                html: document.documentElement ? document.documentElement.outerHTML : ''
            };
        }
    });
    return result;
}

// Main Execution Logic
document.getElementById('executeBtn').addEventListener('click', async () => {
    const taskInput = document.getElementById('task');
    const task = taskInput.value.trim();

    if (!task) {
        updateUI('Error', 'Please enter a command in the search bar.');
        return;
    }

    try {
        updateUI('Starting...', 'Fetching active tab metadata...');
        const tab = await getActiveTab();

        const apiBaseUrl = await getApiBaseUrl();
        const marker = generateMarker();

        // Try to inject marker unless on a restricted URL (Chrome blocks script injection there).
        if (isRestrictedUrl(tab.url)) {
            updateUI('Note', `Restricted page (${tab.url}). Skipping marker injection.`);
        } else {
            try {
                updateUI('Starting...', `Injecting marker into tab... (${marker})`);
                await chrome.scripting.executeScript({
                    target: { tabId: tab.id },
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
            } catch (e) {
                // Some pages (Chrome Web Store, internal pages) still block injection.
                updateUI('Note', `Marker injection blocked (${String(e && e.message ? e.message : e)}). Continuing without marker.`);
            }
        }

        const payload = {
            task: task,
            tabId: tab.id,
            tabUrl: tab.url || '',
            marker: marker
        };

        updateUI('Processing...', `Sending task to agent at ${apiBaseUrl}`);

        const response = await fetch(`${apiBaseUrl}/api/v1/agent/run_on_active_tab`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            updateUI('API Error', { status: response.status, body: data });
            return;
        }

        updateUI('Success', data);
    } catch (err) {
        updateUI('System Error', err && err.message ? err.message : String(err));
    }
});

// Scan Button logic
document.getElementById('analyzeBtn').addEventListener('click', async () => {
    try {
        updateUI('Scanning...', 'Extracting DOM from active tab...');
        const tab = await getActiveTab();

        if (isRestrictedUrl(tab.url)) {
            updateUI('Error', `Cannot analyze restricted page: ${tab.url}`);
            return;
        }

        const apiBaseUrl = await getApiBaseUrl();
        const dom = await captureActiveTabDom(tab.id);

        // Prefer a dedicated endpoint if present; otherwise fall back to a general analyze.
        const payload = {
            tabId: tab.id,
            tabUrl: tab.url || dom.url || '',
            title: dom.title || '',
            page_content: dom.html,
            goal: document.getElementById('task').value.trim() || ''
        };

        updateUI('Scanning...', `Sending DOM to analyzer at ${apiBaseUrl}...`);

        // Try common endpoints in order.
        const endpoints = [
            '/api/v1/firewall/analyze_page',
            '/api/v1/firewall/analyze',
            '/api/v1/agent/analyze_page'
        ];

        let response = null;
        let data = null;
        let lastErr = null;

        for (const ep of endpoints) {
            try {
                response = await fetch(`${apiBaseUrl}${ep}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                data = await response.json().catch(() => ({}));
                if (response.ok) {
                    updateUI('Analysis Complete', data);
                    return;
                }
            } catch (e) {
                lastErr = e;
            }
        }

        if (response) {
            updateUI('API Error', { status: response.status, body: data });
            return;
        }

        updateUI('System Error', lastErr && lastErr.message ? lastErr.message : String(lastErr));
    } catch (err) {
        updateUI('System Error', err && err.message ? err.message : String(err));
    }
});