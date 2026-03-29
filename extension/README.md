# Test Chrome Extension: Active Tab Agent Runner

This is a minimal MV3 extension that provides a popup with an input box. It calls the local FastAPI server to run the agent **on the currently active tab** via CDP.

## Load the extension
1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select this folder: `Agentic-AI/extension`

## Run
1. Start the agent server (`main.py`) so it listens on `http://127.0.0.1:8000`
2. Ensure Chrome is running with remote debugging enabled (the server will attach via CDP)
3. Open any tab
4. Click the extension icon → type a task → **Run**

## Notes
- This is a test harness. The extension itself does not bypass security.
- All actions are still decided and executed by the Python agent; security checks happen server-side via `analysers/` and `firewall/`.
