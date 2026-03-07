# Configuration Directory

This directory contains all configuration files for the Secure Agentic Browser.

## 📁 Files

### **Core Configuration**
- **`.env.template`** - Environment variables template
- **`requirements.txt`** - Python package dependencies 
- **`setup_config.py`** - Interactive configuration setup script

## 🚀 Quick Setup

### **Automated Setup**
```bash
# Run the configuration setup script
python config/setup_config.py
```

### **Manual Setup**
```bash
# Copy template to root directory
cp config/.env.template .env

# Edit with your values
nano .env

# Install dependencies
pip install -r config/requirements.txt
```

## ⚙️ Configuration Options

### **Required Settings**
```env
# Google Gemini API Key (Required)
GOOGLE_API_KEY=your_actual_gemini_api_key_here
```

### **Browser Settings**
```env
# Browser Configuration
BROWSER_HEADLESS=false          # true for headless mode
BROWSER_TIMEOUT=30000           # Browser timeout in milliseconds
```

### **Server Settings**
```env
# Server Configuration
SERVER_HOST=0.0.0.0            # Server host
SERVER_PORT=8001               # Server port
LOG_LEVEL=INFO                 # Logging level
```

### **Agent Settings**
```env
# Agent Behavior
MAX_STEPS_PER_TASK=20          # Maximum steps per task
AGENT_TIMEOUT=300              # Agent timeout in seconds
DEFAULT_WAIT_TIME=2            # Wait time between actions
```

### **Firewall Settings**
```env
# External Firewall Integration
USE_EXTERNAL_FIREWALL=false    # Enable external firewall API
FIREWALL_API_URL=http://localhost:3001/api/validate
FIREWALL_API_KEY=your_firewall_api_key

# Security Settings
ENABLE_FIREWALL=true           # Enable firewall validation
STRICT_MODE=true               # Enable strict security mode
ALLOW_JAVASCRIPT_URLS=false    # Allow javascript: URLs
```

### **Development Settings**
```env
# Debug and Development
DEBUG_MODE=false               # Enable debug mode
VERBOSE_LOGGING=false          # Enable verbose logging
SAVE_SCREENSHOTS=false         # Save screenshots during execution
SCREENSHOT_DIR=./screenshots   # Screenshot directory
```

## 🔒 Security Notes

- **Never commit `.env` files** to version control
- **Keep API keys secure** and rotate them regularly
- **Use environment-specific configurations** for different deployments
- **Enable firewall protection** for production use

## 📚 Related Documentation

- **[Environment Setup Guide](../docs/ENVIRONMENT_SETUP.md)** - Detailed setup instructions
- **[Firewall Integration](../docs/FIREWALL_INTEGRATION.md)** - External firewall setup
- **[Quick Start Guide](../docs/QUICKSTART.md)** - Getting started quickly

## 🆘 Troubleshooting

### **Common Issues**

1. **Missing API Key**
   ```
   Error: GOOGLE_API_KEY environment variable is required
   ```
   **Solution:** Set your Gemini API key in the `.env` file

2. **Import Errors**
   ```
   ImportError: No module named 'fastapi'
   ```
   **Solution:** Install dependencies with `pip install -r config/requirements.txt`

3. **Browser Launch Issues**
   ```
   playwright._impl._api_types.Error: Executable doesn't exist
   ```
   **Solution:** Install Playwright browsers with `playwright install`

### **Getting Help**

- Check the [documentation](../docs/) for detailed guides
- Review the [README](../README.md) for system overview
- Run tests to diagnose issues: `python tests/quick_test.py`
