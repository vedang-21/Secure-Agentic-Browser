# 🔐 Secure Agentic Browser

**Secure Agentic Browser** is a security framework that protects AI-powered browser agents from malicious web content such as **prompt injection**, **phishing**, **UI deception**, and **obfuscated attacks**.

Instead of adding a traditional UI, the system operates as a **runtime security layer** that analyzes web pages *before* an AI agent can interact with them.

> Built for autonomous agents. Designed with Zero-Trust principles.

---

## 🚀 Why This Project?

Modern AI agents can browse the web, fill forms, and execute tasks autonomously.  
However, web pages can exploit this autonomy through:

- Prompt injection attacks
- Hidden instruction overrides
- Credential phishing forms
- Deceptive UI elements
- Malicious JavaScript behaviors
- **Obfuscated payloads and advanced evasion**

**Secure Agentic Browser** acts as a **security firewall** for AI agents — enforcing safety before execution.

---

## 🧠 Architecture Overview

The system follows a **multi-layer defense-in-depth model**:

1. **DOM Structure Analysis** – Detects hidden elements, suspicious forms, risky scripts, **obfuscated code**, and **DOM anomalies**  
2. **NLP Threat Classification** – Flags malicious language patterns, **obfuscated text**, homoglyphs, and suspicious unicode  
3. **LLM Intent Reasoning (Gemini)** – Understands attacker intent, **reasons about obfuscation and evasion** in borderline cases  
4. **Risk Aggregation & Policy Enforcement** – Converts signals into enforceable actions  

➡️ Final decision: **ALLOW / WARN / CONFIRM / BLOCK**

For details, see [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)

---

## ⚙️ Setup & Installation

### Requirements
- Python **3.11+**
- Linux / macOS / WSL (recommended)
- Google Gemini API key

---

### The demo runs three scenarios:

Legitimate task – allowed safely

Prompt injection attack – detected and blocked

Phishing attack – credential theft prevented

**Obfuscated attack – detected and blocked**

Terminal output acts as the security dashboard.

📊 Example Output
SECURITY ASSESSMENT: BLOCK
Risk Score: 0.75 / 1.00

Threats Detected:
- Hidden instruction override
- External credential submission
- **Obfuscated JavaScript detected**
- **DOM anomaly: High script-to-element ratio**

Action Taken:
BLOCK
“Success” means the agent stayed safe, not that the attack succeeded.

## 🛡️ Security Design Principles
- Zero Trust – No page content is trusted by default
- Defense in Depth – Multiple independent detection layers
- Fail-Safe Defaults – Unsafe behavior is blocked
- Explainability – Every decision is human-readable
- No UI Dependency – Designed for headless agents

## 🧪 Evaluation & Metrics
The framework tracks:
- Risk score accuracy
- Decision confidence
- Latency per analysis layer
- Threat detection effectiveness
- **Obfuscation and anomaly detection rates**

> Designed for high precision and low false positives.
### Quick Setup

```bash
git clone https://github.com/vedang-21/secure-agentic-browser.git
cd secure-agentic-browser
chmod +x setup.sh
./setup.sh
Configure API Key
Edit .env:

GEMINI_API_KEY=your-gemini-api-key-here
Get a key from:
👉 https://makersuite.google.com/app/apikey

▶️ Running the Demo
python src/main.py
```

