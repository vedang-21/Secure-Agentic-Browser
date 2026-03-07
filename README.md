# 🤖 Secure Agentic Browser - AI-Powered Browser Automation

A sophisticated Python AI agent system that provides secure, autonomous browser automation using **Google Gemini 2.5 Flash** for intelligent decision making and **System Chrome** integration for reliable browser control.

## ✨ Features

- **🧠 Autonomous AI Agent**: Gemini 2.5 Flash decides next actions based on current page state
- **🛡️ Advanced Security Firewall**: Multi-layered validation of all actions before execution
- **🍎 macOS Optimized**: Uses system Chrome for stability, avoiding bundled Chromium crashes
- **🏗️ Modular Architecture**: Clean separation of concerns with comprehensive testing
- **🌐 REST API**: Easy integration with browser extensions and external tools
- **⚡ Enhanced Actions**: navigate, click, type, type_and_submit, submit, extract, finish
- **📁 Organized Testing**: Comprehensive test suite in dedicated directory
- **🔧 Environment Management**: Secure .env configuration with automatic loading

## 🏗️ Architecture

```
📂 Secure Agentic Browser/
├── 🔧 src/
│   ├── 🤖 agent/
│   │   ├── agent_controller.py       # Main agent loop orchestration
│   │   ├── llm_planner.py           # Gemini 2.5 Flash decision making
│   │   ├── system_chrome_executor.py # System Chrome browser automation
│   │   ├── firewall_client.py       # Advanced security validation
│   │   └── macos_browser_executor.py # macOS optimized browser handling
│   └── 🌐 api/
│       └── agent_routes.py          # FastAPI REST endpoints
├── 🧪 tests/
│   ├── quick_test.py               # Comprehensive system test
│   ├── interactive_demo.py         # Interactive demonstration
│   ├── diagnose_browser.py         # Browser diagnostics
│   └── example_browser_executor.py # Usage examples
├── 🔧 Configuration Files
│   ├── .env                        # Environment variables (secure)
│   ├── .env.template              # Environment template
│   ├── requirements.txt           # Python dependencies
│   └── setup_and_test.sh         # Comprehensive setup script
├── 📚 Documentation
│   ├── ENVIRONMENT_SETUP.md       # Environment setup guide
│   └── QUICKSTART.md             # Quick start guide
└── main.py                        # FastAPI server entry point
```

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```bash
# Run the comprehensive setup script
./setup_and_test.sh

# Follow the interactive menu to:
# 1. Install all dependencies
# 2. Set up environment variables  
# 3. Start the server
# 4. Run tests
```

### Option 2: Manual Setup
```bash
# 1. Install Dependencies
pip install fastapi uvicorn playwright google-generativeai httpx pydantic python-dotenv requests

# 2. Install Playwright Browsers
playwright install

# 3. Configure Environment (choose one):

# Option A: Create .env file
cp .env.template .env
# Edit .env and add: GOOGLE_API_KEY=your_actual_api_key

# Option B: Export environment variable
export GOOGLE_API_KEY="your_gemini_api_key_here"

# 4. Start the server
python main.py
```

### Option 3: Interactive Environment Setup
```bash
# Run the setup script for guided configuration
python setup_env.py
```

## 🧪 Testing

### Run All Tests
```bash
# From project root
python tests/quick_test.py

# Or use the test runner
python run_tests.py
```

### Interactive Demo
```bash
python tests/interactive_demo.py
```

### Browser Diagnostics
```bash
python tests/diagnose_browser.py
```

## 💻 Usage

### Start the Server

```bash
python main.py
```

The server will start on `http://localhost:8001`

### API Endpoints

#### Execute Agent Task
```bash
POST /api/v1/agent_execute
{
  "task": "Go to Google and search for 'AI agents'"
}
```

#### Check Task Status
```bash
GET /api/v1/task-status
```

## 🎯 Supported Actions

- **navigate**: Go to a URL
  ```json
  {"action": "navigate", "url": "https://example.com"}
  ```

- **click**: Click an element
  ```json
  {"action": "click", "selector": "#submit-button"}
  ```

- **type**: Type text into input field
  ```json
  {"action": "type", "selector": "input[name='search']", "text": "search query"}
  ```

- **type_and_submit**: Type and immediately submit (perfect for search boxes)
  ```json
  {"action": "type_and_submit", "selector": "input[name='q']", "text": "AI agents"}
  ```

- **submit**: Submit a form or press Enter
  ```json
  {"action": "submit", "selector": "input[name='search']"}
  ```

- **extract**: Extract data from page
  ```json
  {"action": "extract", "selector": ".results"}
  ```

- **finish**: Complete the task
  ```json
  {"action": "finish", "summary": "Task completed successfully"}
  ```

## 🛡️ Security Features

The firewall validates actions against:
- **Blocked domains and dangerous URLs**: Prevents navigation to malicious sites
- **JavaScript URL protection**: Blocks `javascript:` URLs and inline scripts  
- **File operation restrictions**: Prevents unauthorized file system access
- **Input validation**: Sanitizes all user inputs and selectors
- **Risk factor analysis**: Multi-layered security assessment
- **External firewall API integration**: Optional external security validation

## ⚙️ Configuration

### Environment Variables (.env file)
```bash
# Required
GOOGLE_API_KEY=your_actual_gemini_api_key_here

# Optional - Browser Settings
BROWSER_HEADLESS=false
BROWSER_TIMEOUT=30000

# Optional - Server Settings  
SERVER_HOST=0.0.0.0
SERVER_PORT=8001
LOG_LEVEL=INFO

# Optional - Agent Settings
MAX_STEPS_PER_TASK=20
AGENT_TIMEOUT=300
DEFAULT_WAIT_TIME=2

# Optional - Firewall Settings
USE_EXTERNAL_FIREWALL=false
FIREWALL_API_URL=http://localhost:3001/api/validate
ENABLE_FIREWALL=true
STRICT_MODE=true
```

### Firewall Customization
- Configure blocked domains in `src/agent/firewall_client.py`
- Set external firewall API URL for additional validation
- Customize security rules and risk factors
- Enable/disable strict mode for different security levels

### External Firewall Integration

The system supports seamless integration with external firewall APIs:

#### **Current Setup (Local Firewall)**
```env
USE_EXTERNAL_FIREWALL=false
```
- Uses built-in security rules for immediate protection
- Validates against dangerous URLs, sensitive fields, and suspicious patterns
- Always active as the first line of defense

#### **Future Setup (External Firewall)**
When your team's firewall API is ready on localhost:
```env
USE_EXTERNAL_FIREWALL=true
FIREWALL_API_URL=http://localhost:3001/api/validate
FIREWALL_API_KEY=your_firewall_api_key
```

#### **External Firewall API Specification**

**Input Format (what your firewall receives):**
```json
{
  "action": {
    "action": "type",
    "selector": "input[name='password']",
    "text": "mypassword"
  },
  "page_context": {
    "url": "https://example.com/login",
    "title": "Login Page",
    "html_content": "<html>...</html>",
    "visible_text": "Login to your account...",
    "javascript_present": true,
    "forms": [{"action": "/login", "method": "post", "https": true}],
    "inputs": [{"type": "password", "name": "password", "selector": "input[name='password']"}],
    "links": [...],
    "meta_data": {...},
    "security_headers": {...},
    "cookies": [...],
    "page_size": 45000
  }
}
```

**Expected Response Format:**
```json
{
  "allowed": true,
  "reason": "Action passed all security checks", 
  "source": "external",
  "confidence": 0.95,
  "risk_factors": ["https_secure_connection", "trusted_domain"],
  "risk_level": "low",
  "analysis": {
    "domain_reputation": "good",
    "ssl_check": "valid",
    "content_safety": "clean", 
    "form_analysis": "secure"
  },
  "timestamp": "2024-03-06T10:30:45Z",
  "processing_time_ms": 250
}
```

#### **Testing External Firewall**
```bash
# Start mock firewall server (for testing)
python tests/mock_external_firewall.py

# Test integration
python tests/test_external_firewall.py

# Run with external firewall enabled
USE_EXTERNAL_FIREWALL=true python main.py
```

## 🛠️ Development

The system is designed to be modular and extensible:

- **Agent Controller**: Orchestrates the main agent loop
- **LLM Planner**: Uses Gemini 2.5 Flash to decide next actions
- **System Chrome Executor**: Handles browser automation with system Chrome
- **Firewall Client**: Provides security validation
- **API Routes**: Exposes REST endpoints for external integration

### Example Usage

```python
from src.agent.agent_controller import AgentController, AgentTask

# Create agent
agent = AgentController()

# Create task
task = AgentTask(
    task_id="example-task",
    user_request="Go to Wikipedia and find information about AI",
    max_steps=15
)

# Execute task
result = await agent.execute_task(task)
print(result)
```

## 🌐 Browser Extension Integration

The API is designed to work with browser extensions. Extensions can:
1. Send user requests to `/api/v1/agent_execute`
2. Monitor progress via `/api/v1/task-status`  
3. Get page state and execution logs
4. Integrate with the security firewall

## 🔧 Troubleshooting

### Common Issues

#### Browser Crashes on macOS
- The system uses system Chrome instead of bundled Chromium
- Ensure Google Chrome is installed at `/Applications/Google Chrome.app`
- Run browser diagnostics: `python tests/diagnose_browser.py`

#### API Key Issues
- Make sure `GOOGLE_API_KEY` is set in `.env` file
- Verify the key format starts with `AIzaSy`
- Get a key from: https://makersuite.google.com/app/apikey

#### Import Errors
- Install all dependencies: `pip install -r requirements.txt`
- Install Playwright browsers: `playwright install`
- Run system diagnostics: `python diagnose_system.py`

### Running Tests
```bash
# Quick system test
python tests/quick_test.py

# Interactive demo
python tests/interactive_demo.py

# Browser diagnostics
python tests/diagnose_browser.py

# Full system check
python diagnose_system.py
```

## 📊 Monitoring & Logs

- **Console Output**: Real-time colored logging
- **Log Files**: `agent_execution.log` for persistent logs
- **API Status**: Health check at `http://localhost:8001/`
- **Task Monitoring**: Real-time status via `/api/v1/task-status`

## 📄 License

This project is for educational and research purposes. Please ensure you have proper authorization before automating interactions with websites.