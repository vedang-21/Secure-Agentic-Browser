# TODO — Secure Agentic Browser (CDP + Extension + Hosting + Dashboard)

This file is a prioritized roadmap for implementing **CDP control of the active tab**, integrating a **browser extension UI**, and preparing for **hosted deployment (Fly.io)** and a **security dashboard**.

> Priority legend:
> - **P0** = must-have for hackathon demo
> - **P1** = strong demo enhancement / next step
> - **P2** = post-demo / production hardening

---

## P0 — Hackathon Demo (CDP + Extension → Agent → Visible automation)

### 1) CDP attach to *active tab* (macOS)
- [ ] Add `.env` settings:
  - [ ] `CHROME_CDP_URL=http://127.0.0.1:9222`
  - [ ] (Optional) `USE_CHROME_CDP=true` to toggle CDP vs launch
- [ ] Update browser initialization (async Playwright) to use CDP:
  - [ ] In `src/agent/action_executor.py` (or the real executor currently used), replace `launch(...)` with `connect_over_cdp(CHROME_CDP_URL)`
  - [ ] Select **active tab** consistently:
    - [ ] Pick first context (`browser.contexts[0]`)
    - [ ] Pick last page (`context.pages[-1]`) as the tab to automate
    - [ ] Fallback: if there are no pages, create a new one
  - [ ] Ensure `page.goto("https://google.com")` works reliably
- [ ] Add clear logs for CDP:
  - [ ] Log CDP URL
  - [ ] Log chosen tab URL + title
  - [ ] Log reconnection/fallback behavior

### 2) Demo runbook (so CDP is deterministic)
- [ ] Document the exact demo steps in `README.md` (short section):
  - [ ] Start Chrome with remote debugging
  - [ ] Load extension
  - [ ] Open demo tab last (so "active tab" selection works)
  - [ ] Start backend server

### 3) Extension → Backend (minimal UI)
Use the existing `browser_extension_example/` as a starter.
- [ ] Ensure extension can call the API from any page:
  - [ ] Confirm `fetch("http://localhost:8001/..." )` works with CORS
- [ ] Add/confirm one main endpoint:
  - [ ] `POST /agent_execute` with `{ "task": "..." }`
- [ ] Add a simple status endpoint surfaced in extension:
  - [ ] show: current step, last proposed action, firewall result

### 4) Harden the “search flow” for demos
- [ ] Ensure executor supports search submit behavior:
  - [ ] `type_and_submit` or `press("Enter")` after typing
  - [ ] Add small waits after navigation/click/submit
- [ ] Ensure LLM prompt encourages: navigate → type_and_submit → extract → finish

---

## P1 — Demo polish (looks impressive, low-to-medium complexity)

### 5) Action overlay / highlight (extension content-script)
- [ ] When the agent clicks/types, briefly highlight the element on the page:
  - [ ] Outline element with CSS (2s)
  - [ ] Optional tooltip: “Agent: clicking Search”

### 6) “Decision Pipeline” panel in extension
- [ ] Show a timeline:
  - [ ] page observed (URL/title)
  - [ ] proposed action JSON
  - [ ] firewall allowed/blocked + reason
  - [ ] execution result

### 7) Safety interstitials
- [ ] If firewall blocks:
  - [ ] show “Blocked for safety” with reason + risk factors
- [ ] If firewall warns (allowed but risky):
  - [ ] show warning banner and let user abort

---

## P2 — Hosting on Fly.io (Option A: Hosted planner + Local runner)

> Key rule: **do not expose CDP to the internet**.

### 8) Split architecture (planner vs runner)
- [ ] Runner (local) responsibilities:
  - [ ] connect to Chrome CDP
  - [ ] collect `page_context`
  - [ ] execute actions
- [ ] Planner (hosted) responsibilities:
  - [ ] LLM decide next action
  - [ ] call external firewall
  - [ ] orchestrate loop

### 9) Runner ↔ Hosted orchestration channel
- [ ] Implement outbound connection from runner to cloud:
  - [ ] WebSocket (recommended) or HTTPS long-poll fallback
- [ ] Pairing/auth:
  - [ ] runner generates pairing code
  - [ ] extension links to runner session

### 10) Deploy planner to Fly.io
- [ ] Add Dockerfile / Fly config
- [ ] Add secrets handling (Fly secrets)
- [ ] Add auth (JWT/session token)

---

## P2 — Security dashboard (future)

### 11) Collect firewall telemetry
- [ ] Emit event on every firewall decision (allowed/blocked)
- [ ] Store stats:
  - [ ] count blocked
  - [ ] recent blocks (last N)
  - [ ] top risk factors

### 12) Expose dashboard endpoints
- [ ] `GET /api/v1/security/stats`
- [ ] `GET /api/v1/security/recent-blocks?limit=50`

### 13) Dashboard UI
- [ ] Simple web UI (or extension page):
  - [ ] blocked count
  - [ ] recent blocks table
  - [ ] risk factors bar chart

---

## Notes / Constraints
- CDP demo assumes Chrome is started with:
  - `--remote-debugging-port=9222`
  - a dedicated `--user-data-dir` recommended for predictable behavior
- For a prerecorded demo, “active tab” selection is reliable if you open the demo tab last.
