(function () {
  const PANEL_ID = '__secure_agent_panel__';
  if (document.getElementById(PANEL_ID)) return;

  const style = document.createElement('style');
  style.textContent = `
    :root {
      --sap-bg: #000;
      --sap-bg2: #0a0a0a;
      --sap-panel: rgba(0,0,0,0.96);
      --sap-border: #333;
      --sap-border-strong: #ff6b35;
      --sap-accent: #ff8c42;
      --sap-accent2: #ffa500;
      --sap-text: #ffffff;
      --sap-muted: #aaa;
      --sap-code: #ccc;
    }

    #${PANEL_ID} {
      position: fixed;
      top: 12px;
      right: 12px;
      width: 360px;
      max-height: calc(100vh - 24px);
      z-index: 2147483647;
      background: linear-gradient(180deg, var(--sap-bg) 0%, var(--sap-bg2) 100%);
      color: var(--sap-text);
      border: 2px solid var(--sap-border-strong);
      font-family: 'Segoe UI', system-ui, -apple-system, Roboto, Arial;
      box-shadow: 0 10px 30px rgba(0,0,0,0.65);
    }
    #${PANEL_ID} * { box-sizing: border-box; }

    #${PANEL_ID} header {
      padding: 12px 12px;
      border-bottom: 2px solid #333;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      background: #050505;
      position: relative;
    }
    #${PANEL_ID} header::after {
      content: '';
      position: absolute;
      bottom: -2px;
      left: 0;
      width: 100%;
      height: 2px;
      background: linear-gradient(90deg, var(--sap-border-strong), var(--sap-accent), var(--sap-accent2));
      box-shadow: 0 0 8px rgba(255, 107, 53, 0.6);
    }

    #${PANEL_ID} header .title {
      font-weight: 800;
      font-size: 12px;
      letter-spacing: 1px;
      text-transform: uppercase;
    }

    #${PANEL_ID} header button {
      background: #0a0a0a;
      color: #fff;
      border: 2px solid #333;
      padding: 6px 10px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }
    #${PANEL_ID} header button:hover {
      border-color: var(--sap-border-strong);
      box-shadow: 0 0 10px rgba(255, 107, 53, 0.35);
    }

    #${PANEL_ID} .body { padding: 12px; display: grid; gap: 10px; }

    #${PANEL_ID} input[type=text] {
      width: 100%;
      padding: 12px 12px;
      border: 2px solid #333;
      background: #0a0a0a;
      color: #fff;
      font-size: 13px;
      font-weight: 600;
      outline: none;
      box-shadow: inset 0 2px 5px rgba(0, 0, 0, 0.5);
    }
    #${PANEL_ID} input[type=text]::placeholder { color: #666; }
    #${PANEL_ID} input[type=text]:focus {
      border-color: var(--sap-accent);
      box-shadow: 0 0 12px rgba(255, 140, 66, 0.5), inset 0 0 5px rgba(255, 140, 66, 0.2);
    }

    #${PANEL_ID} .row { display: flex; gap: 8px; }
    #${PANEL_ID} .row button {
      flex: 1;
      background: #0a0a0a;
      color: #bbb;
      border: 2px solid #333;
      padding: 10px 10px;
      cursor: pointer;
      font-weight: 800;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .6px;
      box-shadow: inset 0 2px 5px rgba(0, 0, 0, 0.5), 0 2px 4px rgba(0, 0, 0, 0.5);
    }
    #${PANEL_ID} .row button:hover {
      color: #fff;
      border-color: var(--sap-border-strong);
      box-shadow: 0 0 10px rgba(255, 107, 53, 0.35), inset 0 0 10px rgba(255, 107, 53, 0.15);
    }
    #${PANEL_ID} .row button:active {
      color: var(--sap-accent2);
      border-color: var(--sap-accent2);
      box-shadow: 0 0 15px rgba(255, 165, 0, 0.45), inset 0 0 15px rgba(255, 165, 0, 0.2);
    }

    #${PANEL_ID} .status {
      font-size: 12px;
      color: var(--sap-accent);
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: .8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    #${PANEL_ID} .status::before {
      content: '■';
      font-size: 10px;
      color: var(--sap-border-strong);
      text-shadow: 0 0 8px var(--sap-border-strong);
    }

    #${PANEL_ID} pre {
      margin: 0;
      padding: 10px;
      background: #000;
      border: 1px solid #222;
      white-space: pre-wrap;
      word-break: break-word;
      overflow: auto;
      max-height: 45vh;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      color: var(--sap-code);
    }

    #${PANEL_ID} .hint { font-size: 11px; color: var(--sap-muted); line-height: 1.35; }
    #${PANEL_ID} .minimized .body { display: none; }
  `;
  document.documentElement.appendChild(style);

  const panel = document.createElement('div');
  panel.id = PANEL_ID;
  panel.innerHTML = `
    <header>
      <div class="title">Agent</div>
      <div style="display:flex; gap:6px;">
        <button id="__sap_min">–</button>
        <button id="__sap_close">×</button>
      </div>
    </header>
    <div class="body">
      <div class="hint">Runs via your local agent server. Actions happen in this tab; logs show here.</div>
      <input id="__sap_task" type="text" placeholder="Enter objective…" />
      <div class="row">
        <button id="__sap_run">Run</button>
        <button id="__sap_analyze">Analyze</button>
      </div>
      <div class="row">
        <button id="__sap_stop">Stop</button>
        <button id="__sap_clear">Clear</button>
      </div>
      <div class="status" id="__sap_status">Idle</div>
      <pre id="__sap_log">—</pre>
    </div>
  `;
  document.documentElement.appendChild(panel);

  const state = {
    apiBaseUrl: 'http://127.0.0.1:8001',
    pollTimer: null,
    minimized: false,
  };

  function setStatus(s) {
    const el = panel.querySelector('#__sap_status');
    if (el) el.textContent = s;
  }

  function setLog(obj) {
    const el = panel.querySelector('#__sap_log');
    if (!el) return;
    el.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  }

  function formatAnalysisResult(apiData) {
    // apiData is the background response's `data` object
    const report = apiData && apiData.report ? apiData.report : null;
    if (!report) return typeof apiData === 'string' ? apiData : JSON.stringify(apiData, null, 2);

    const action = report.action || 'UNKNOWN';
    const risk = typeof report.risk_score === 'number' ? report.risk_score : null;
    const conf = typeof report.confidence === 'number' ? report.confidence : null;
    const perf = report.performance || {};

    const dom = report.detailed_analysis && report.detailed_analysis.dom ? report.detailed_analysis.dom : {};
    const nlp = report.detailed_analysis && report.detailed_analysis.nlp ? report.detailed_analysis.nlp : {};
    const llm = report.detailed_analysis && report.detailed_analysis.llm ? report.detailed_analysis.llm : null;

    const suspiciousForms = Array.isArray(dom.suspicious_forms) ? dom.suspicious_forms.length : 0;
    const obfuscationAlerts = Array.isArray(dom.obfuscation_alerts) ? dom.obfuscation_alerts.length : 0;

    const threats = Array.isArray(nlp.threats) ? nlp.threats.join(', ') : '';
    const severity = nlp.severity || '';

    const lines = [];
    lines.push('Security report');
    lines.push('================');
    lines.push(`Action: ${action}`);
    if (risk !== null) lines.push(`Risk: ${(risk * 100).toFixed(0)}%`);
    if (conf !== null) lines.push(`Confidence: ${(conf * 100).toFixed(0)}%`);
    if (apiData.tabUrl) lines.push(`URL: ${apiData.tabUrl}`);
    if (apiData.title) lines.push(`Title: ${apiData.title}`);
    lines.push('');

    lines.push('Findings');
    lines.push('--------');
    lines.push(`• Suspicious forms: ${suspiciousForms}`);
    lines.push(`• Obfuscation alerts: ${obfuscationAlerts}`);
    if (severity || threats) lines.push(`• Text signals: ${severity || 'n/a'}${threats ? ` (${threats})` : ''}`);
    lines.push(`• LLM review: ${llm ? `${llm.threat_type || 'flagged'} (${Math.round((llm.confidence || 0) * 100)}%)` : 'not used'}`);
    lines.push('');

    if (report.explanation) {
      lines.push('Explanation');
      lines.push('-----------');
      // Keep the explainer output (already user-facing) but trim very long text.
      const exp = String(report.explanation);
      lines.push(exp.length > 1800 ? exp.slice(0, 1800) + '\n…' : exp);
      lines.push('');
    }

    if (perf && (perf.latency_ms !== undefined || perf.layers_used !== undefined)) {
      lines.push('Performance');
      lines.push('-----------');
      if (perf.latency_ms !== undefined) lines.push(`Latency: ${perf.latency_ms} ms`);
      if (perf.layers_used !== undefined) lines.push(`Layers used: ${perf.layers_used}`);
      lines.push('');
    }

    // Debug JSON (optional)
    lines.push('Debug (raw JSON)');
    lines.push('----------------');
    lines.push(JSON.stringify(apiData, null, 2));

    return lines.join('\n');
  }

  function generateMarker() {
    try { return crypto.randomUUID(); } catch { return `marker_${Date.now()}_${Math.random().toString(16).slice(2)}`; }
  }

  async function loadApiBaseUrl() {
    try {
      const { apiBaseUrl } = await chrome.storage.local.get({ apiBaseUrl: 'http://127.0.0.1:8001' });
      state.apiBaseUrl = apiBaseUrl;
    } catch {
      state.apiBaseUrl = 'http://127.0.0.1:8001';
    }
  }

  function formatTaskStatus(data) {
    if (!data || typeof data !== 'object') return String(data || '');

    const status = data.status || 'unknown';
    const step = data.current_step ?? null;
    const max = data.max_steps ?? null;
    const req = (data.user_request || '').trim();

    const parts = [];
    parts.push('Agent run');
    parts.push('========');
    if (req) parts.push(`Objective: ${req}`);
    parts.push(`Status: ${status}`);
    if (step !== null || max !== null) parts.push(`Progress: ${step ?? '?'} / ${max ?? '?'}`);

    // If backend ever returns result/error in status, show them.
    if (data.error) {
      parts.push('');
      parts.push('Error');
      parts.push('-----');
      parts.push(String(data.error));
    }
    if (data.result) {
      parts.push('');
      parts.push('Latest result');
      parts.push('-------------');
      parts.push(typeof data.result === 'string' ? data.result : JSON.stringify(data.result, null, 2));
    }

    // Keep raw JSON visible but not the default noise.
    parts.push('');
    parts.push('Debug (raw JSON)');
    parts.push('----------------');
    parts.push(JSON.stringify(data, null, 2));
    return parts.join('\n');
  }

  async function pollStatus() {
    try {
      const resp = await fetch(`${state.apiBaseUrl}/api/v1/task-status`);
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) return;
      const step = data.current_step ?? '-';
      const max = data.max_steps ?? '-';
      setStatus(`Status: ${data.status} | step ${step}/${max}`);
      setLog(formatTaskStatus(data));
    } catch {
      // ignore
    }
  }

  async function runOnThisTab() {
    await loadApiBaseUrl();

    const task = (panel.querySelector('#__sap_task')?.value || '').trim();
    if (!task) {
      setStatus('Error');
      setLog('Enter an objective');
      return;
    }

    const marker = generateMarker();

    // Inject marker into this page's DOM (best-effort)
    try {
      (window).__SECURE_AGENT_MARKER = marker;
      (window).__AGENT_MARKER = marker;
      let meta = document.querySelector('meta[name="secure-agent-marker"]');
      if (!meta) {
        meta = document.createElement('meta');
        meta.setAttribute('name', 'secure-agent-marker');
        document.head && document.head.appendChild(meta);
      }
      meta.setAttribute('content', marker);
    } catch {
      // ignore
    }

    setStatus('Starting…');
    setLog('Sending request…');

    // Ask background to call the local API (avoids page CORS/CSP issues)
    chrome.runtime.sendMessage(
      {
        type: 'RUN_ON_ACTIVE_TAB',
        payload: {
          task,
          tabUrl: location.href,
          marker,
        }
      },
      (resp) => {
        if (!resp || !resp.ok) {
          setStatus('API Error');
          setLog(resp && resp.error ? resp.error : 'Failed to call agent API');
          return;
        }
        setStatus('Running…');
        setLog(resp.data);
        if (state.pollTimer) clearInterval(state.pollTimer);
        state.pollTimer = setInterval(pollStatus, 1000);
      }
    );
  }

  async function analyzeThisPage() {
    await loadApiBaseUrl();

    const goal = (panel.querySelector('#__sap_task')?.value || '').trim();
    const html = document.documentElement ? document.documentElement.outerHTML : '';
    const title = document.title || '';

    setStatus('Analyzing…');
    setLog('Sending page HTML to firewall…');

    chrome.runtime.sendMessage(
      {
        type: 'ANALYZE_PAGE',
        payload: {
          page_content: html,
          goal,
          tabUrl: location.href,
          title,
        }
      },
      (resp) => {
        if (!resp || !resp.ok) {
          setStatus('API Error');
          setLog(resp && resp.error ? resp.error : 'Failed to call analyzer');
          return;
        }
        setStatus('Analysis Complete');
        setLog(formatAnalysisResult(resp.data));
      }
    );
  }

  function stop() {
    loadApiBaseUrl().then(() => {
      chrome.runtime.sendMessage({ type: 'STOP_TASK' }, (resp) => {
        if (!resp || !resp.ok) {
          setStatus('Error');
          setLog(resp && resp.error ? resp.error : 'Failed');
          return;
        }
        setStatus('Stopped');
        setLog(resp.data);
      });
    });
  }

  function clearLog() {
    setStatus('Idle');
    setLog('—');
  }

  panel.querySelector('#__sap_run')?.addEventListener('click', runOnThisTab);
  panel.querySelector('#__sap_analyze')?.addEventListener('click', analyzeThisPage);
  panel.querySelector('#__sap_stop')?.addEventListener('click', stop);
  panel.querySelector('#__sap_clear')?.addEventListener('click', clearLog);
  panel.querySelector('#__sap_close')?.addEventListener('click', () => {
    if (state.pollTimer) clearInterval(state.pollTimer);
    panel.remove();
    style.remove();
  });
  panel.querySelector('#__sap_min')?.addEventListener('click', () => {
    state.minimized = !state.minimized;
    panel.classList.toggle('minimized', state.minimized);
  });

  // initial status poll
  loadApiBaseUrl().then(() => pollStatus());
})();
