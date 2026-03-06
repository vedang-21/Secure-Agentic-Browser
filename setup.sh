#!/bin/bash

# Setup script for Secure Agentic Browser

echo "Setting up Secure Agentic Browser..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed. Please install Python 3.8+ and try again."
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install Playwright browsers
echo "Installing Playwright browsers..."
playwright install

# Check if GEMINI_API_KEY is set
if [ -z "$GEMINI_API_KEY" ]; then
    echo ""
    echo "⚠️  WARNING: GEMINI_API_KEY environment variable is not set!"
    echo "Please set it with: export GEMINI_API_KEY='your_api_key_here'"
    echo "You can get a Gemini API key from: https://makersuite.google.com/app/apikey"
    echo ""
else
    echo "✅ GEMINI_API_KEY is configured"
fi

echo ""
echo "🚀 Setup complete!"
echo ""
echo "To start the server:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Set your Gemini API key: export GEMINI_API_KEY='your_key'"
echo "3. Run the server: python main.py"
echo ""
echo "The server will be available at: http://localhost:8000"
echo "API documentation will be available at: http://localhost:8000/docs"