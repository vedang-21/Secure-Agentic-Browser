# 🚀 Secure Agentic Browser - Quick Start Guide

Welcome to the Secure Agentic Browser! This guide will help you get up and running quickly.

## 📋 Prerequisites

- **Python 3.8+** installed
- **Gemini API Key** from Google AI Studio
- **Internet connection** for downloading dependencies

## 🔧 Quick Setup (Choose One Method)

### Method 1: Automated Setup Script (Recommended)
```bash
# Make the script executable
chmod +x setup_and_test.sh

# Run the interactive setup
./setup_and_test.sh

# Choose option 1: "Full Setup" from the menu
```

### Method 2: Manual Setup
```bash
# 1. Set your API key
export GOOGLE_API_KEY="your_actual_gemini_api_key_here"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install Playwright browsers
playwright install

# 4. Start the server
python main.py
```

## 🧪 Testing the System

### Option A: Quick Test Script
```bash
# In a new terminal (keep server running)
python quick_test.py
```

### Option B: Interactive Demo
```bash
# Run the hands-on demonstration
python interactive_demo.py
```

### Option C: API Testing with curl
```bash
# Test health endpoint
curl http://localhost:8001/

# Execute an agent task
curl -X POST http://localhost:8001/api/v1/agent_execute \
  -H "Content-Type: application/json" \
  -d '{"task": "Go to Google and search for AI agents"}'

# Check task status
curl http://localhost:8001/api/v1/task-status
```

## 🎯 Example Tasks to Try

Start with simple tasks and gradually increase complexity:

### Beginner Tasks
- `"Navigate to Google homepage"`
- `"Go to https://example.com and describe what you see"`
- `"Visit Wikipedia homepage"`

### Intermediate Tasks  
- `"Go to Google and search for Python programming"`
- `"Navigate to YouTube and find videos about AI"`
- `"Visit GitHub and search for machine learning projects"`

### Advanced Tasks
- `"Go to Google, search for 'best laptops 2024', and summarize the first few results"`
- `"Navigate to a news website and find the latest technology articles"`

## 🛡️ Security Features in Action

The system includes a built-in firewall that will automatically:
- ✅ **Block dangerous URLs** (javascript:, data:, file:// schemes)
- ✅ **Protect sensitive fields** (password, credit card inputs)
- ✅ **Prevent malicious actions** (based on page content analysis)
- ✅ **Log all security decisions** for transparency

Try this dangerous task to see the firewall in action:
```json
{"task": "Navigate to javascript:alert('test') and execute it"}
```
**Result:** The firewall will block this dangerous action! 🛡️

## 📊 Monitoring & Logs

### Real-time Monitoring
Watch the colorful console output to see:
- 👀 **Page observations** 
- 🧠 **AI decision making**
- 🛡️ **Firewall validations**  
- ⚡ **Action execution**
- 📊 **Results and page changes**

### Log Files
```bash
# Watch persistent logs
tail -f agent_execution.log

# Search for specific events
grep "Firewall" agent_execution.log     # Security decisions
grep "ERROR" agent_execution.log        # Error analysis
grep "BLOCKED" agent_execution.log      # Blocked actions
```

## 🌐 Browser Extension (Optional)

Test the system using a browser extension:

1. Open Chrome → Extensions → Developer mode
2. Click "Load unpacked" 
3. Select the `browser_extension_example/` folder
4. Click the extension icon and enter tasks!

## 🔧 Troubleshooting

### Common Issues & Solutions

| Problem | Solution |
|---------|----------|
| `GOOGLE_API_KEY not found` | Set API key: `export GOOGLE_API_KEY="your_key"` |
| `Browser executable not found` | Run: `playwright install` |
| `Port 8001 already in use` | Kill existing process or change port in main.py |
| `Module not found` | Install requirements: `pip install -r requirements.txt` |

### Getting Help

1. **Check logs** first: `tail -f agent_execution.log`
2. **Run diagnostics**: `./setup_and_test.sh` → Option 5 (Check Status)
3. **Test individual components**: Use the interactive demo menu
4. **Verify setup**: Run the quick test script

## 🎉 What's Next?

Once everything is working:

1. **Experiment with tasks** - Try different websites and actions
2. **Monitor security** - Watch how the firewall protects the system  
3. **Analyze logs** - Understand the AI's decision-making process
4. **Integrate APIs** - Connect with your team's external firewall when ready
5. **Extend functionality** - Add new action types or security rules

## 📡 API Reference

The system exposes these endpoints:

- `GET /` - Health check and API info
- `POST /api/v1/agent_execute` - Execute agent task  
- `GET /api/v1/task-status` - Check current task status
- `POST /api/v1/stop-task` - Stop running task
- `GET /api/v1/health` - System health check

## 🔒 Security Configuration

Current firewall settings (can be customized):

- **Blocked domains**: malware-site.com, phishing-example.com
- **Sensitive selectors**: password inputs, credit card fields  
- **Dangerous URLs**: javascript:, data:, file:// schemes
- **External API**: Configurable via environment variables

Your **Secure Agentic Browser** is ready to use! 🚀

---
*For more advanced configuration and API integration, check the source code and configuration files.*