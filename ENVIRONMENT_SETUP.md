# 🔧 Environment Setup Guide

This guide will help you set up your environment variables securely without exposing sensitive data.

## 🚀 Quick Setup (Recommended)

### Option 1: Automated Setup Script
```bash
python setup_env.py
```

This will:
- ✅ Install `python-dotenv` package
- ✅ Create `.env` file with your configuration  
- ✅ Verify the setup works correctly
- ✅ Show usage instructions

### Option 2: Manual Setup
```bash
# 1. Copy the template
cp .env.template .env

# 2. Edit the .env file
nano .env  # or use your preferred editor

# 3. Add your API key
GOOGLE_API_KEY=your_actual_gemini_api_key_here
```

## 📋 Required Configuration

### 🔑 Google Gemini API Key (Required)
1. Visit: https://makersuite.google.com/app/apikey
2. Create or select a project  
3. Generate an API key
4. Add it to your `.env` file:
   ```
   GOOGLE_API_KEY=AIzaSyABC123...your_actual_key_here
   ```

## 🔒 Security Features

### ✅ What's Protected:
- **`.env` file** - Automatically ignored by git
- **API keys and secrets** - Never committed to version control
- **Local configuration** - Stays on your machine
- **Backup files** - Temporary files ignored

### 🛡️ .gitignore Protection:
The `.gitignore` file protects:
```
.env
*.key
*api_key*
*secret*
*token*
credentials.json
```

## ⚙️ Configuration Options

### 🌐 Browser Settings
```env
BROWSER_HEADLESS=false          # Show browser window
BROWSER_TIMEOUT=30000           # 30 second timeout
```

### 🖥️ Server Settings  
```env
SERVER_HOST=0.0.0.0            # Listen on all interfaces
SERVER_PORT=8001                # Default port
LOG_LEVEL=INFO                  # Logging level
```

### 🛡️ Firewall Settings
```env
USE_EXTERNAL_FIREWALL=false     # Use local firewall
FIREWALL_API_URL=http://localhost:3001/api/validate
FIREWALL_API_KEY=your_firewall_key
```

### 🤖 Agent Settings
```env
MAX_STEPS_PER_TASK=20          # Maximum steps per task
AGENT_TIMEOUT=300              # 5 minute timeout
DEFAULT_WAIT_TIME=2            # Wait between actions
```

## 🧪 Testing Your Setup

### Verify Environment Loading:
```bash
python -c "
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
    key = os.getenv('GOOGLE_API_KEY')
    if key and len(key) > 10:
        print('✅ Environment loaded successfully!')
        print(f'🔑 API key found (ends with: ...{key[-8:]})')
    else:
        print('❌ API key not found or invalid')
except ImportError:
    print('❌ python-dotenv not installed')
    print('💡 Run: pip install python-dotenv')
"
```

### Test the Complete System:
```bash
# Start server (loads .env automatically)
python main.py

# Run tests (in another terminal)
python tests/quick_test.py
```

## 🔧 Troubleshooting

### Issue: "python-dotenv not found"
```bash
# Install the package
pip install python-dotenv

# Or reinstall requirements
pip install -r requirements.txt
```

### Issue: "API key not found"
1. Check your `.env` file exists in project root
2. Verify the API key format: `GOOGLE_API_KEY=AIzaSy...`
3. No quotes around the key value
4. No spaces around the `=` sign

### Issue: "Module not found" in tests
```bash
# Make sure you're in the project root
cd /path/to/Agentic-AI

# Run tests from project root
python tests/quick_test.py
```

### Issue: ".env file not loading"
Check file location:
```bash
# Should be in project root, same level as main.py
ls -la .env main.py

# File should exist and have content
cat .env | head -5
```

## 💡 Best Practices

### ✅ DO:
- Keep `.env` file in project root
- Use descriptive variable names
- Set appropriate timeout values
- Test configuration changes

### ❌ DON'T:
- Commit `.env` to version control  
- Share API keys in chat/email
- Use production keys for testing
- Put quotes around values (usually)

## 🎯 Example .env File

```env
# Working example configuration
GOOGLE_API_KEY=AIzaSyBOurActualKeyHere123456789
BROWSER_HEADLESS=false
SERVER_PORT=8001
USE_EXTERNAL_FIREWALL=false
MAX_STEPS_PER_TASK=15
LOG_LEVEL=INFO
```

## 🚀 Next Steps

Once your environment is set up:

1. **Start the system:**
   ```bash
   python main.py
   ```

2. **Run tests:**
   ```bash
   python tests/quick_test.py
   ```

3. **Try interactive demo:**
   ```bash
   python tests/interactive_demo.py
   ```

4. **Use setup script for everything:**
   ```bash
   ./setup_and_test.sh
   ```

Your environment is now secure and ready! 🎉