# Secure Agentic Browser (Agentic-AI)

A local-first **agentic browser + security firewall** stack:

- A FastAPI backend that runs an autonomous web agent **on your current Chrome tab** (CDP attach).
- A Chrome extension that injects a **persistent in-page overlay panel** (modern “AI browser” UX).
- A multi-layer **page threat analyzer** (DOM + NLP + optional LLM) with “block/confirm/allow” recommendations.
- **Persistent agent memory** (SQLite + FTS5) for RAG-style recall across runs.

> Everything runs locally: the extension talks to `http://127.0.0.1:8001`.

---

## What you can do

### 1) Run an autonomous agent on the active tab
- Open any normal webpage.
- Use the in-page overlay (top-right): **Run**.
- The backend attaches to the active Chrome tab and executes steps safely.

### 2) Analyze the current page for threats
- Use **Analyze** in the overlay.
- Sends page HTML to the local firewall and returns a human-readable security report.

---

## Demo UX (Overlay)

The extension injects a floating panel on normal http(s) pages:

- **Run**: start agent run on this tab
- **Analyze**: run page threat analysis (DOM/NLP + optional LLM)
- **Stop**: stop current run
- **Clear**: clear panel output

If you don’t see the overlay:
- You’re likely on a restricted page (`chrome://*`, Web Store, etc.)
- Reload extension and refresh the page

---

## Architecture (high level)

- `main.py` → FastAPI server
- `src/agent/*` → planner + action execution + CDP attach
- `firewall/*` + `analysers/*` → multi-layer threat analysis + risk scoring
- `src/memory/sqlite_memory.py` → persistent memory (SQLite + FTS5)
- `extension/` → MV3 extension (content script overlay + service worker proxy)

---

## Setup

### 0) Prereqs
- macOS + Google Chrome installed
- Python 3.11+
- A Gemini key if you want the LLM firewall layer

### 1) Install Python deps
```bash
python3 -m pip install -r config/requirements.txt
```

### 2) (Optional) Install Playwright browsers
This project primarily uses **System Chrome**, but Playwright may still be used by some utilities/tests.
```bash
playwright install
```

### 3) Configure environment
Create a `.env` (or export env vars) for keys and tuning.

Minimum (LLM features):
```bash
GOOGLE_API_KEY=your_key
```

Optional knobs:
```bash
# Server
SERVER_PORT=8001

# Firewall
FIREWALL_LLM_THRESHOLD=0.4

# Memory
AGENT_MEMORY_DB=agent_memory.db
```

### 4) Start the API server
```bash
python3 main.py
```

Health check:
- `GET http://127.0.0.1:8001/api/v1/health`

---

## Install the Chrome extension

1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Open any normal webpage → overlay appears top-right

Notes:
- The extension uses a MV3 service worker (`extension/background.js`) to proxy requests to the local API.
- If you change extension files, hit **Reload** in `chrome://extensions`.

---

## API endpoints (used by the extension)

### Run agent on the active tab
`POST /api/v1/agent/run_on_active_tab`
```json
{
  "task": "go to amazon and search for nothing phones",
  "tabId": 123,
  "tabUrl": "https://example.com",
  "marker": "uuid",
  "max_steps": 15
}
```

### Poll status
`GET /api/v1/task-status`

### Stop current run
`POST /api/v1/stop-task`

### Analyze current page
`POST /api/v1/firewall/analyze_page`
```json
{
  "page_content": "<html>…</html>",
  "goal": "optional agent goal",
  "tabUrl": "https://example.com",
  "title": "Page title"
}
```

---

## Threat analysis (Firewall)

The `SecurityMediator` runs a layered inspection:

1. **DOM Analyzer** (fast): forms, scripts, redirects, obfuscation
2. **NLP Classifier** (fast-ish): visible + hidden text signals
3. **LLM Reasoner** (optional): used when risk crosses a threshold
4. **Risk Calculator**: produces a final score + action

The response includes:
- `risk_score` (0..1)
- `action`: `ALLOW | CONFIRM | BLOCK`
- an explanation string
- a detailed breakdown

### Force LLM layer on every analysis
Set:
```bash
export FIREWALL_LLM_THRESHOLD=0.0
```
(Requires `GOOGLE_API_KEY`.)

---

## Persistent memory (SQLite + FTS5)

The agent stores lightweight “RAG-style” memories in `agent_memory.db`:
- step summaries (action + outcome)
- URL + title
- truncated page snapshots
- safety metadata (trusted / risk_score when available)

Retrieval is **trust/risk-aware** (prefers trusted + low-risk + same domain/task).

Configure DB location:
```bash
export AGENT_MEMORY_DB=/absolute/path/to/agent_memory.db
```

---

## Troubleshooting

### Overlay doesn’t show
- Must be a normal `http(s)` page (not `chrome://*`, Web Store, etc.)
- Reload extension in `chrome://extensions`
- Refresh the page

### Analyze/Run does nothing
- Confirm server is up:
  - `curl http://127.0.0.1:8001/api/v1/health`
- Check Extension → **Service worker** console for logs

### LLM isn’t used
- Ensure `GOOGLE_API_KEY` (or `GEMINI_API_KEY`) is set
- Lower the threshold:
  - `FIREWALL_LLM_THRESHOLD=0.0`

---

## Repo map

- `extension/` – Chrome extension (overlay UI + background proxy)
- `src/agent/` – agent runtime + CDP attach + safe execution loop
- `firewall/` + `analysers/` – page analysis + LLM firewall
- `src/memory/` – SQLite memory (FTS5)
- `scripts/run_dom_threat_check.py` – CLI test harness for DOM threat analysis

---

## License

Educational/research use. Only automate sites where you have authorization.