#!/bin/bash

# Secure Agentic Browser Setup and Test Script
# This script helps you set up and test the complete system

set -e  # Exit on any error

echo "🚀 Secure Agentic Browser - Setup & Test Script"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Always run from repo root
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VENV_DIR="$ROOT_DIR/venv"

ensure_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        print_info "Creating virtual environment at venv/ ..."
        python3 -m venv "$VENV_DIR"
        print_success "Virtual environment created"
    fi

    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
}

# Check if Python is installed
check_python() {
    echo "🐍 Checking Python installation..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        print_success "Python ${PYTHON_VERSION} found"
        return 0
    else
        print_error "Python 3 is not installed"
        print_info "Please install Python 3.8 or higher"
        return 1
    fi
}

# Install requirements (in venv)
install_requirements() {
    echo "📚 Installing Python requirements (venv)..."
    ensure_venv

    if [ -f "config/requirements.txt" ]; then
        python -m pip install -q --upgrade pip
        python -m pip install -q -r config/requirements.txt
        print_success "Python requirements installed"
    else
        print_warning "config/requirements.txt not found, installing basic packages..."
        python -m pip install -q --upgrade pip
        python -m pip install -q fastapi uvicorn playwright google-generativeai httpx pydantic requests
    fi
}

# Install Playwright browsers (in venv)
install_playwright() {
    echo "🌐 Installing Playwright browsers..."
    ensure_venv
    python -m playwright install
    print_success "Playwright browsers installed"
}

# Check environment variables
check_env_vars() {
    echo "🔑 Checking environment variables..."

    if [ -z "$GOOGLE_API_KEY" ] && [ -z "$GEMINI_API_KEY" ]; then
        print_error "Neither GOOGLE_API_KEY nor GEMINI_API_KEY is set"
        print_info "Set it with: export GOOGLE_API_KEY='your_actual_api_key'"

        echo "Would you like to set it now (for this session only)? (y/n)"
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo "Enter your Gemini API key:"
            read -r api_key
            export GOOGLE_API_KEY="$api_key"
            print_success "API key set for this session"
        else
            print_warning "Continuing without API key (agent execution will fail)"
        fi
    else
        print_success "API key is set"
    fi

    if [ "${USE_EXTERNAL_FIREWALL:-false}" = "true" ]; then
        print_warning "USE_EXTERNAL_FIREWALL=true — ensure your external firewall is running at FIREWALL_API_URL"
        print_info "If you don't have it running, set USE_EXTERNAL_FIREWALL=false in .env to avoid warnings"
    fi
}

# Start the server in background (use run_agent.sh)
start_server() {
    echo "🖥️  Starting Secure Agentic Browser server..."

    if pgrep -f "uvicorn main:app" > /dev/null || pgrep -f "python.*main.py" > /dev/null; then
        print_warning "Server might already be running"
    fi

    if [ ! -f "./run_agent.sh" ]; then
        print_error "run_agent.sh not found"
        print_info "Expected to find ./run_agent.sh in project root"
        return 1
    fi

    # Start server in background
    ./run_agent.sh &
    SERVER_PID=$!

    echo "⏳ Waiting for server to start..."
    sleep 5

    if kill -0 $SERVER_PID 2>/dev/null; then
        print_success "Server started with PID $SERVER_PID"
        echo $SERVER_PID > server.pid

        if command -v curl &> /dev/null; then
            if curl -s http://localhost:8001/ > /dev/null; then
                print_success "Server is responding on port 8001"
            else
                print_warning "Server started but not responding yet"
            fi
        else
            print_info "curl not found, cannot test server health"
        fi
        return 0
    else
        print_error "Failed to start server"
        return 1
    fi
}

# Stop the server
stop_server() {
    echo "🛑 Stopping server..."
    if [ -f "server.pid" ]; then
        SERVER_PID=$(cat server.pid)
        if kill $SERVER_PID 2>/dev/null; then
            print_success "Server stopped"
            rm server.pid
        else
            print_warning "Server was not running or already stopped"
        fi
    else
        pkill -f "uvicorn main:app" || true
        pkill -f "python.*main.py" || true
        print_info "No server.pid found; attempted to stop any running server processes"
    fi
}

# Run tests (in venv)
run_tests() {
    echo "🧪 Running test suite..."
    ensure_venv

    if [ -f "tests/quick_test.py" ]; then
        python tests/quick_test.py
    else
        print_error "tests/quick_test.py not found"
        print_info "Check if tests directory exists and has test files"
    fi
}

# Run interactive demo (in venv)
run_demo() {
    echo "🎮 Running interactive demo..."
    ensure_venv

    if [ -f "tests/demos/interactive_demo.py" ]; then
        python tests/demos/interactive_demo.py
    else
        print_error "tests/demos/interactive_demo.py not found"
    fi
}

# Cleanup function
cleanup() {
    echo ""
    print_info "Cleaning up..."
    stop_server
    exit 0
}

trap cleanup SIGINT SIGTERM

show_menu() {
    echo ""
    echo "🎯 What would you like to do?"
    echo "=============================="
    echo "1. 🔧 Full Setup (create venv + install dependencies)"
    echo "2. 🚀 Start Server"
    echo "3. 🧪 Run Tests"
    echo "4. 🎮 Run Interactive Demo"
    echo "5. 📊 Check System Status"
    echo "6. 🛑 Stop Server"
    echo "7. 🚪 Exit"
    echo "=============================="
}

check_status() {
    echo "📊 System Status Check"
    echo "======================"

    if pgrep -f "uvicorn main:app" > /dev/null || pgrep -f "python.*main.py" > /dev/null; then
        print_success "Server is running"
        if command -v curl &> /dev/null; then
            if curl -s http://localhost:8001/ > /dev/null; then
                print_success "Server is responding"
            else
                print_warning "Server is running but not responding"
            fi
        fi
    else
        print_info "Server is not running"
    fi

    check_env_vars

    echo "📁 Checking key files..."
    key_files=("main.py" "src/agent/agent_controller.py" "src/agent/firewall_client.py" "config/requirements.txt" "run_agent.sh")
    for file in "${key_files[@]}"; do
        if [ -f "$file" ]; then
            print_success "$file exists"
        else
            print_error "$file missing"
        fi
    done

    if [ -d "$VENV_DIR" ]; then
        print_success "venv/ exists"
    else
        print_warning "venv/ not found (run Full Setup)"
    fi
}

full_setup() {
    echo "🔧 Running full setup..."
    echo "======================="

    check_python || exit 1
    install_requirements
    install_playwright
    check_env_vars

    print_success "Setup completed!"
    print_info "You can now start the server and run tests"
}

main() {
    echo ""
    print_info "Current directory: $(pwd)"

    if [ ! -f "main.py" ]; then
        print_error "main.py not found. Make sure you're in the project root directory"
        exit 1
    fi

    while true; do
        show_menu
        echo -n "👉 Enter your choice (1-7): "
        read -r choice

        case $choice in
            1)
                full_setup
                ;;
            2)
                start_server
                ;;
            3)
                run_tests
                ;;
            4)
                run_demo
                ;;
            5)
                check_status
                ;;
            6)
                stop_server
                ;;
            7)
                print_info "Goodbye!"
                cleanup
                ;;
            *)
                print_error "Invalid choice. Please try again."
                ;;
        esac

        echo ""
        echo "Press Enter to continue..."
        read -r
    done
}

main "$@"