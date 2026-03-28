# Test Directory for Secure Agentic Browser

This directory contains test scripts, demos, diagnostics, and integration checks.

## 📁 Layout (Dev Mode)

### Core
- **`quick_test.py`** - Comprehensive end-to-end system test
- **`test_agent.py`** - Basic agent functionality test
- **`test_secure_loop.py`** - Secure loop regression test

### API
- **`api/test_api_endpoints.py`** - API endpoint checks

### Demos
- **`demos/interactive_demo.py`** - Interactive demonstration (best for hackathon demos)
- **`demos/demo_agent_logging.py`** - Logging demo
- **`demos/demo_adaptive_agent.py`** - Adaptive browsing demo
- **`demos/example_browser_executor.py`** - Executor usage example

### Diagnostics
- **`diagnostics/diagnose_browser.py`** - Browser diagnostics
- **`diagnostics/syntax_check.py`** - Python syntax validation
- **`diagnostics/quick_fix.py`** - Installs/checks common prerequisites
- **`diagnostics/verify_fix.py`** - Env var verification
- **`diagnostics/verify_model_update.py`** - Gemini model verification
- **`diagnostics/test_macos_browser.py`** - macOS browser test
- **`diagnostics/ultra_simple_browser_test.py`** - Minimal browser config test

### Firewall
- **`firewall/mock_external_firewall.py`** - Mock external firewall server
- **`firewall/test_external_firewall.py`** - External firewall integration test

## 🚀 Quick Start

### Run the main end-to-end test
```bash
python3 tests/quick_test.py
```

### Run the interactive demo
```bash
python3 tests/demos/interactive_demo.py
```

### Browser troubleshooting
```bash
python3 tests/diagnostics/diagnose_browser.py
```

### Syntax verification
```bash
python3 tests/diagnostics/syntax_check.py
```

## 💡 Usage Tips

1. Start with `tests/quick_test.py` for overall system health.
2. Use `tests/demos/interactive_demo.py` during demos.
3. If the browser fails to launch or navigate, run `tests/diagnostics/diagnose_browser.py`.
4. If you change file paths or imports, run `tests/diagnostics/syntax_check.py`.