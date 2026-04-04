async function getApiBaseUrl() {
  const { apiBaseUrl } = await chrome.storage.local.get({ apiBaseUrl: 'http://127.0.0.1:8001' });
  return apiBaseUrl;
}

function withTimeout(ms) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(new Error('timeout')), ms);
  return { controller, cancel: () => clearTimeout(t) };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      // Log every message so we can confirm delivery.
      console.log('[secure-agent] onMessage', {
        type: msg && msg.type,
        fromTabId: sender && sender.tab ? sender.tab.id : undefined,
        fromUrl: sender && sender.tab ? sender.tab.url : undefined,
      });

      if (!msg || !msg.type) {
        sendResponse({ ok: false, error: 'Invalid message (missing type)' });
        return;
      }

      if (msg.type === 'RUN_ON_ACTIVE_TAB') {
        const apiBaseUrl = await getApiBaseUrl();
        const tabId = sender && sender.tab ? sender.tab.id : undefined;
        const tabUrl = (msg.payload && msg.payload.tabUrl) || (sender.tab && sender.tab.url) || '';
        const marker = msg.payload && msg.payload.marker;
        const task = msg.payload && msg.payload.task;

        const resp = await fetch(`${apiBaseUrl}/api/v1/agent/run_on_active_tab`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ task, tabId, tabUrl, marker })
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          sendResponse({ ok: false, error: { status: resp.status, body: data } });
          return;
        }
        sendResponse({ ok: true, data });
        return;
      }

      if (msg.type === 'ANALYZE_PAGE') {
        const apiBaseUrl = await getApiBaseUrl();
        const payload = msg.payload || {};

        const bytes = JSON.stringify(payload).length;
        console.log('[secure-agent] ANALYZE_PAGE ->', `${apiBaseUrl}/api/v1/firewall/analyze_page`, { bytes });

        const { controller, cancel } = withTimeout(30000);
        try {
          const resp = await fetch(`${apiBaseUrl}/api/v1/firewall/analyze_page`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
            signal: controller.signal
          });
          const data = await resp.json().catch(() => ({}));
          if (!resp.ok) {
            console.warn('[secure-agent] ANALYZE_PAGE error', resp.status, data);
            sendResponse({ ok: false, error: { status: resp.status, body: data } });
            return;
          }
          console.log('[secure-agent] ANALYZE_PAGE ok');
          sendResponse({ ok: true, data });
          return;
        } catch (e) {
          console.warn('[secure-agent] ANALYZE_PAGE thrown', e);
          sendResponse({ ok: false, error: String(e && e.message ? e.message : e) });
          return;
        } finally {
          cancel();
        }
      }

      if (msg.type === 'STOP_TASK') {
        const apiBaseUrl = await getApiBaseUrl();
        const resp = await fetch(`${apiBaseUrl}/api/v1/stop-task`, { method: 'POST' });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          sendResponse({ ok: false, error: { status: resp.status, body: data } });
          return;
        }
        sendResponse({ ok: true, data });
        return;
      }

      // Unknown message type
      sendResponse({ ok: false, error: `Unknown message type: ${msg.type}` });
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message ? e.message : e) });
    }
  })();

  // keep message channel open
  return true;
});
