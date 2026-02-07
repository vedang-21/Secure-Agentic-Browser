#!/usr/bin/env bash
set -e

echo "🚀 Setting up Secure Agentic Browser"
echo "==================================="

# -------------------------------
# Check Python version
# -------------------------------
if ! command -v python3 &>/dev/null; then
  echo "❌ python3 not found. Please install Python 3.11+"
  exit 1
fi

PY_VERSION=$(python3 - <<EOF
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
EOF
)

echo "🐍 Python version detected: $PY_VERSION"

# -------------------------------
# Create virtual environment
# -------------------------------
if [ ! -d "venv" ]; then
  echo "📦 Creating virtual environment..."
  python3 -m venv venv
else
  echo "📦 Virtual environment already exists"
fi

# -------------------------------
# Activate virtual environment
# -------------------------------
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# -------------------------------
# Upgrade pip
# -------------------------------
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# -------------------------------
# Install dependencies
# -------------------------------
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

# -------------------------------
# Install Playwright browsers
# -------------------------------
echo "🌐 Installing Playwright Chromium..."
playwright install chromium

# -------------------------------
# Create .env template
# -------------------------------
if [ ! -f ".env" ]; then
  echo "📝 Creating .env file..."
  cat > .env <<EOF
# ============================================
# Secure Agentic Browser - Environment Config
# ============================================

# Google Gemini API Key
# Get from: https://makersuite.google.com/app/apikey
GEMINI_API_KEY=your-gemini-api-key-here

# Logging
LOG_LEVEL=INFO
EOF
else
  echo "📝 .env already exists (not overwritten)"
fi

# -------------------------------
# Final message
# -------------------------------
echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1️⃣  Activate venv (if not active):"
echo "    source venv/bin/activate"
echo ""
echo "2️⃣  Edit .env and add your Gemini API key"
echo ""
echo "3️⃣  Run the demo:"
echo "    python src/main.py"
echo ""
echo "🎉 Happy hacking!"
