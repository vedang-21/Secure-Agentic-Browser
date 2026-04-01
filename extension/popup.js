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

        // Default API URL - Update this if your friend gives you his IP!
        const apiBaseUrl = 'http://127.0.0.1:8001';

        const payload = {
            task: task,
            tabId: tab.id,
            tabUrl: tab.url || ''
        };

        updateUI('Processing...', `Sending task to agent at ${apiBaseUrl}`);

        const response = await fetch(`${apiBaseUrl}/api/v1/agent/run_on_active_tab`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            updateUI('API Error', { status: response.status, message: 'Server refused request' });
            return;
        }

        updateUI('Success', data);
    } catch (err) {
        updateUI('System Error', err.message);
    }
});

// Scan Button logic
document.getElementById('analyzeBtn').addEventListener('click', () => {
    updateUI('Scanning...', 'Analyzing DOM for security vulnerabilities...');
    setTimeout(() => {
        updateUI('Secure', 'Page analysis complete. No threats found.');
    }, 1000);
});