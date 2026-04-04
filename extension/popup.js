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

function getDashboardUrl() {
    return chrome.runtime.getURL('dashboard.html');
}

async function openDashboard() {
    const url = getDashboardUrl();
    const tabs = await chrome.tabs.query({});
    const existing = tabs.find(t => t.url === url);
    if (existing && existing.id) {
        await chrome.tabs.update(existing.id, { active: true });
        return;
    }
    await chrome.tabs.create({ url });
}

// Open side panel when the popup is opened/clicked.
(async () => {
    try {
        const tab = await getActiveTab();
        await chrome.sidePanel.open({ tabId: tab.id });
    } catch {
        // ignore
    }
})();

// Keep popup as a lightweight launcher. Side panel is the persistent UI.
// Replace execute behavior: open dashboard tab

document.getElementById('executeBtn').addEventListener('click', async () => {
    updateUI('Info', 'Overlay panel is enabled. Open any normal webpage and use the in-page Agent panel (top-right).');
});

document.getElementById('analyzeBtn').addEventListener('click', async () => {
    updateUI('Info', 'Overlay panel is enabled. Use the in-page Agent panel (top-right) for runs; analysis can be added next.');
});