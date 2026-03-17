# 🔒 Secure Agentic Browser

A runtime security framework that protects AI-powered browser agents from malicious web content such as prompt injection, phishing, UI deception, and behavioural anomalies.

Instead of adding a traditional UI, the system operates as a **runtime security layer** that analyzes web pages before an AI agent can interact with them.

> **Built for autonomous agents. Designed with Zero-Trust principles.**

---

## 🚀 Why This Project?

Modern AI agents can browse the web, fill forms, and execute tasks autonomously. However, web pages can exploit this autonomy through:

- Prompt injection attacks
- Hidden instruction overrides
- Credential phishing forms
- Deceptive UI elements
- Malicious JavaScript behaviors
- Behavioural manipulation of the agent

**Secure Agentic Browser acts as a security firewall for AI agents — enforcing safety before execution.**

---

## 🧠 Architecture Overview

The system follows a multi-layer defense-in-depth model:

```
AI Agent
    ↓
Agent Firewall (pre-flight checks)
    ├── API key authentication
    ├── Domain blocklist
    ├── Rate limiting
    ├── Session tracking + auto-ban
    └── Behaviour anomaly detection
    ↓
Security Pipeline
    ├── Layer 1 — DOM Structure Analysis
    ├── Layer 2 — NLP Threat Classification
    ├── Layer 3 — LLM Intent Reasoning (Gemini)
    └── Layer 4 — Risk Aggregation & Policy Enforcement
        ↓
Decision: ALLOW / WARN / CONFIRM / BLOCK
        ↓
Agent acts or gets blocked
```

For details, see `docs/ARCHITECTURE.md`

---

## 📁 Project Structure

```
Secure-Agentic-Browser/
├── src/
│   ├── analyzers/
│   │   ├── dom_analyzer.py          # DOM structure threat detection
│   │   ├── nlp_classifier.py        # NLP language pattern detection
│   │   └── llm_reasoner.py          # Gemini deep intent analysis
│   ├── core/
│   │   ├── agent.py                 # AgenticBrowser (Playwright)
│   │   ├── security_mediator.py     # Main pipeline orchestrator
│   │   └── agent_firewall.py        # Auth, rate limiting, anomaly detection
│   ├── policies/
│   │   └── risk_calculator.py       # Weighted multi-factor risk scoring
│   ├── utils/
│   │   ├── explanation_generator.py
│   │   ├── metrics_collector.py
│   │   └── performance_monitor.py
│   └── main.py                      # FastAPI application
├── docs/
│   └── ARCHITECTURE.md
├── tests/
│   └── ground_truth/
│       └── labeled_dataset.json
├── config.yaml
├── requirements.txt
└── .env
```

---

## ⚙️ Setup & Installation

### Requirements
- Python 3.11+
- Linux / macOS / WSL (recommended)
- Google Gemini API key

### Installation

```bash
git clone https://github.com/vedang-21/Secure-Agentic-Browser
cd Secure-Agentic-Browser
chmod +x setup.sh
./setup.sh
```

### Configure Environment

Create a `.env` file in the project root:

```
GEMINI_API_KEY=your-gemini-key-here
GOOGLE_API_KEY=your-gemini-key-here
FIREWALL_API_KEY=your-custom-firewall-key
```

Get a Gemini key from: 👉 https://aistudio.google.com/app/apikey

### Running the API Server

```bash
# Set API keys (PowerShell)
$env:GEMINI_API_KEY="your-key-here"
$env:GOOGLE_API_KEY="your-key-here"
$env:FIREWALL_API_KEY="your-firewall-key"

# Start the server
uvicorn src.main:app --reload --port 8000
```

Visit `http://127.0.0.1:8000/docs` for the interactive API documentation.

### Running the Demo

```bash
python src/main.py
```

The demo runs three scenarios:
- ✅ **Legitimate task** — allowed safely
- 🚫 **Prompt injection attack** — detected and blocked
- 🚫 **Phishing attack** — credential theft prevented

Terminal output acts as the security dashboard.

---

## 🔌 API Endpoints

### Core Security Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | API health check |
| POST | `/analyze` | Analyze a page for threats |
| POST | `/validate_action` | Validate an agent action before execution |
| POST | `/agent_execute` | Full security gate + agent task execution |
| GET | `/metrics` | System performance metrics |

### Firewall Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/firewall/status` | Firewall stats — requests, blocks, sessions |
| GET | `/firewall/audit` | Full audit log of all requests |
| GET | `/firewall/behaviour/{session_id}` | Behaviour profile for a session |

---

## 🛡️ Security Layers

### Agent Firewall — Pre-flight
Runs before any analysis. Immediately blocks:
- **Invalid API keys** — unauthorized requests rejected instantly
- **Blocklisted domains** — known malicious domains blocked without analysis
- **Rate limiting** — max 30 requests per session per minute
- **Session auto-ban** — sessions permanently blocked after 3 threat detections
- **Behaviour anomaly detection**:
  - Rapid repeated clicks (≥5 in last 10 actions)
  - Multiple form submissions (>2 in last 10 actions)
  - Rapid domain switching (>4 domains in last 10 actions)

### Layer 1 — DOM Structure Analysis
Detects hidden elements, suspicious forms, and risky scripts:
- Hidden content (`display:none`, `visibility:hidden`, off-screen positioning)
- External form submissions pointing to different domains
- Suspicious iframes and external scripts
- Obfuscated JavaScript patterns

### Layer 2 — NLP Threat Classification
Flags malicious language patterns:
- Prompt injection (`"Ignore all previous instructions"`)
- Role reassignment (`"You are now a different AI"`)
- System impersonation (`"SYSTEM UPDATE: This is Anthropic"`)
- Data exfiltration commands (`"Send your API keys to"`)

### Layer 3 — LLM Intent Reasoning (Gemini)
Understands attacker intent in borderline cases:
- Reads full page context including hidden content
- Identifies credential harvesting patterns
- Detects deceptive UI designed to trick agents
- Returns structured reasoning with confidence score

### Layer 4 — Risk Aggregation & Policy Enforcement
Combines all layer scores using weighted scoring:

```
Final Score =
  DOM score    × 0.15 +
  NLP score    × 0.20 +
  Gemini score × 0.55 +
  Behavioral   × 0.10
```

Decision thresholds:
```
≥ 0.65 → BLOCK
≥ 0.45 → CONFIRM
≥ 0.25 → WARN
< 0.25 → ALLOW
```

---

## 📊 Example Output

```
SECURITY ASSESSMENT: BLOCK
Risk Score: 0.75 / 1.00

Threats Detected:
  - Hidden instruction override
  - External credential submission

Action Taken: BLOCK
```

> "Success" means the agent stayed safe, not that the attack succeeded.

---

## 🔐 Firewall Integration

To integrate your agent with this firewall, add to your `.env`:

```
FIREWALL_BASE_URL=http://localhost:8000
FIREWALL_API_KEY=your-firewall-key
```

Every request must include the API key as a header:
```
X-API-Key: your-firewall-key
```

### Example Integration

```python
import os, requests
from dotenv import load_dotenv

load_dotenv()

FIREWALL_URL = os.getenv("FIREWALL_BASE_URL", "http://localhost:8000")
HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": os.getenv("FIREWALL_API_KEY", "")
}

def check_page(url, html, goal, session_id):
    result = requests.post(f"{FIREWALL_URL}/analyze", json={
        "url": url,
        "raw_html": html,
        "agent_context": {"task": goal, "session_id": session_id}
    }, headers=HEADERS, timeout=30)
    return result.json()

# In your agent loop
safety = check_page(url, html, goal, session_id)
if safety["decision"] == "BLOCK":
    print(f"Blocked: {safety['threats']}")
else:
    proceed_with_task()
```

---

## 🧪 Evaluation & Metrics

The framework tracks:
- Risk score accuracy
- Decision confidence
- Latency per analysis layer
- Threat detection effectiveness
- Session behaviour patterns

Designed for high precision and low false positives.

---

## 🏗️ Security Design Principles

- **Zero Trust** — No page content is trusted by default
- **Defense in Depth** — Multiple independent detection layers
- **Fail-Safe Defaults** — Any crash or error defaults to BLOCK
- **Explainability** — Every decision includes human-readable reasoning
- **No UI Dependency** — Designed for headless autonomous agents
- **Least Privilege** — Credentials redacted before entering pipeline

---

## 🔮 Upcoming Features

- [ ] Goal deviation detection — flags agent navigating away from original task
- [ ] AWS deployment
- [ ] Integration with teammate's AI agent branch
- [ ] Real-time threat monitoring dashboard

---

## 👥 Team

**Member 1 — Vedang (Team Lead / Core Architect)**
- SecurityMediator → AgentFirewall integration
- Risk Engine tuning and fallback weights
- All API endpoints (`/analyze`, `/validate_action`, `/metrics`, `/health`, `/agent_execute`)
- AgentFirewall class (auth, rate limiting, blocklist, session tracking, anomaly detection)
- Final system integration and deployment

---

## 📄 License

MIT License
