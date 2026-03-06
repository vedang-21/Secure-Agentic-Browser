# Secure Agentic Browser - AI-Powered Browser Automation

A Python AI agent system that provides secure, autonomous browser automation using Google Gemini API for decision making and Playwright for browser control.

## Features

- **Autonomous Agent Loop**: AI decides next actions based on current page state
- **Security Firewall**: Validates all actions before execution
- **Modular Architecture**: Clean separation of concerns
- **REST API**: Easy integration with browser extensions
- **Support for Multiple Actions**: navigate, click, type, extract, finish

## Architecture

```
src/
├── agent/
│   ├── agent_controller.py    # Main agent loop orchestration
│   ├── llm_planner.py        # Gemini AI decision making
│   ├── action_executor.py    # Playwright browser automation
│   └── firewall_client.py    # Security validation
├── api/
│   └── agent_routes.py       # FastAPI REST endpoints
└── main.py                   # FastAPI server entry point
```

## Installation

1. **Install Dependencies**:
```bash
pip install fastapi uvicorn playwright google-generativeai httpx pydantic
```

2. **Install Playwright Browsers**:
```bash
playwright install
```

3. **Set Environment Variables**:
```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
```

## Usage

### Start the Server

```bash
python main.py
```

The server will start on `http://localhost:8000`

### API Endpoints

#### Execute Agent Task
```bash
POST /api/v1/execute-task
{
  "user_request": "Go to Google and search for 'AI agents'",
  "max_steps": 20
}
```

#### Check Task Status
```bash
GET /api/v1/task-status
```

#### Stop Current Task
```bash
POST /api/v1/stop-task
```

#### Execute Single Action (for browser extensions)
```bash
POST /api/v1/browser/execute-action
{
  "action": "navigate",
  "target": "https://google.com",
  "value": "",
  "reasoning": "Navigate to Google homepage"
}
```

#### Get Page State
```bash
GET /api/v1/browser/page-state
```

## Supported Actions

- **navigate**: Go to a URL
  ```json
  {"action": "navigate", "target": "https://example.com", "value": ""}
  ```

- **click**: Click an element
  ```json
  {"action": "click", "target": "#submit-button", "value": ""}
  ```

- **type**: Type text into input field
  ```json
  {"action": "type", "target": "input[name='search']", "value": "search query"}
  ```

- **extract**: Extract data from page
  ```json
  {"action": "extract", "target": ".results", "value": ""}
  ```

- **finish**: Complete the task
  ```json
  {"action": "finish", "target": "", "value": "Task completed successfully"}
  ```

## Security Features

The firewall validates actions against:
- Blocked domains and dangerous URLs
- Sensitive input field protection
- File operation restrictions
- External firewall API integration

## Configuration

### Environment Variables
- `GEMINI_API_KEY`: Your Google Gemini API key (required)

### Firewall Settings
- Configure blocked domains in `firewall_client.py`
- Set firewall API URL for external validation
- Customize security rules as needed

## Development

The system is designed to be modular and extensible:

- **Agent Controller**: Orchestrates the main agent loop
- **LLM Planner**: Uses Gemini to decide next actions
- **Action Executor**: Handles browser automation with Playwright
- **Firewall Client**: Provides security validation
- **API Routes**: Exposes REST endpoints for external integration

## Example Usage

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

## Browser Extension Integration

The API is designed to work with browser extensions. Extensions can:
1. Send user requests to `/api/v1/execute-task`
2. Monitor progress via `/api/v1/task-status`
3. Execute individual actions via `/api/v1/browser/execute-action`
4. Get page state for context via `/api/v1/browser/page-state`

## License

This project is for educational and research purposes. Please ensure you have proper authorization before automating interactions with websites.