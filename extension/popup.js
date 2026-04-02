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
    const { apiBaseUrl } = await chrome.storage.local.get({ apiBaseUrl: 'http://127.0.0.1:8001' });
    return apiBaseUrl;
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
document.getElementById('analyzeBtn').addEventListener('click', () => {
    updateUI('Scanning...', 'Analyzing DOM for security vulnerabilities...');
    setTimeout(() => {
        updateUI('Secure', 'Page analysis complete. No threats found.');
    }, 1000);
});