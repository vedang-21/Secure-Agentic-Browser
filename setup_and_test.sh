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

# Check if pip is available
check_pip() {
    echo "📦 Checking pip..."
    if command -v pip3 &> /dev/null || command -v pip &> /dev/null; then
        print_success "pip is available"
        return 0
    else
        print_error "pip is not installed"
        print_info "Please install pip"
        return 1
    fi
}

# Install requirements
install_requirements() {
    echo "📚 Installing Python requirements..."
    if [ -f "requirements.txt" ]; then
        python3 -m pip install -r requirements.txt
        print_success "Python requirements installed"
    else
        print_warning "requirements.txt not found, installing basic packages..."
        python3 -m pip install fastapi uvicorn playwright google-generativeai httpx pydantic requests
    fi
}

# Install Playwright browsers
install_playwright() {
    echo "🌐 Installing Playwright browsers..."
    playwright install
    print_success "Playwright browsers installed"
}

# Check environment variables
check_env_vars() {
    echo "🔑 Checking environment variables..."
    
    if [ -z "$GEMINI_API_KEY" ]; then
        print_error "GEMINI_API_KEY is not set"
        print_info "Set it with: export GEMINI_API_KEY='your_actual_api_key'"
        
        echo "Would you like to set it now? (y/n)"
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo "Enter your Gemini API key:"
            read -r api_key
            export GEMINI_API_KEY="$api_key"
            print_success "API key set for this session"
            print_info "Add 'export GEMINI_API_KEY=\"$api_key\"' to your ~/.bashrc or ~/.zshrc"
        else
            print_warning "Continuing without API key (some features may not work)"
        fi
    else
        print_success "GEMINI_API_KEY is set"
    fi
}

# Start the server in background
start_server() {
    echo "🖥️  Starting Secure Agentic Browser server..."
    
    if pgrep -f "python.*main.py" > /dev/null; then
        print_warning "Server might already be running"
    fi
    
    # Start server in background
    python3 main.py &
    SERVER_PID=$!
    
    # Wait for server to start
    echo "⏳ Waiting for server to start..."
    sleep 5
    
    # Check if server is running
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_success "Server started with PID $SERVER_PID"
        echo $SERVER_PID > server.pid
        
        # Test server health
        if command -v curl &> /dev/null; then
            if curl -s http://localhost:8001/ > /dev/null; then
                print_success "Server is responding on port 8001"
                return 0
            else
                print_warning "Server started but not responding yet"
                return 0
            fi
        else
            print_info "curl not found, cannot test server health"
            return 0
        fi
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
        # Try to find and kill any main.py process
        pkill -f "python.*main.py" || print_info "No server process found"
    fi
}

# Run tests
run_tests() {
    echo "🧪 Running test suite..."
    
    if [ -f "quick_test.py" ]; then
        python3 quick_test.py
    else
        print_error "quick_test.py not found"
        print_info "Running basic server test..."
        
        if command -v curl &> /dev/null; then
            if curl -s http://localhost:8001/ > /dev/null; then
                print_success "Server health check passed"
            else
                print_error "Server health check failed"
            fi
        fi
    fi
}

# Run interactive demo
run_demo() {
    echo "🎮 Running interactive demo..."
    
    if [ -f "interactive_demo.py" ]; then
        python3 interactive_demo.py
    else
        print_error "interactive_demo.py not found"
    fi
}

# Cleanup function
cleanup() {
    echo ""
    print_info "Cleaning up..."
    stop_server
    exit 0
}

# Set up signal handling
trap cleanup SIGINT SIGTERM

# Main menu
show_menu() {
    echo ""
    echo "🎯 What would you like to do?"
    echo "=============================="
    echo "1. 🔧 Full Setup (install dependencies)"
    echo "2. 🚀 Start Server"
    echo "3. 🧪 Run Tests"
    echo "4. 🎮 Run Interactive Demo"
    echo "5. 📊 Check System Status"
    echo "6. 🛑 Stop Server"
    echo "7. 🚪 Exit"
    echo "=============================="
}

# System status check
check_status() {
    echo "📊 System Status Check"
    echo "======================"
    
    # Check if server is running
    if pgrep -f "python.*main.py" > /dev/null; then
        print_success "Server is running"
        
        # Test server response
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
    
    # Check environment
    check_env_vars
    
    # Check key files
    echo "📁 Checking key files..."
    
    key_files=("main.py" "src/agent/agent_controller.py" "src/agent/firewall_client.py" "requirements.txt")
    for file in "${key_files[@]}"; do
        if [ -f "$file" ]; then
            print_success "$file exists"
        else
            print_error "$file missing"
        fi
    done
}

# Full setup process
full_setup() {
    echo "🔧 Running full setup..."
    echo "======================="
    
    check_python || exit 1
    check_pip || exit 1
    install_requirements
    install_playwright
    check_env_vars
    
    print_success "Setup completed!"
    print_info "You can now start the server and run tests"
}

# Main script logic
main() {
    echo ""
    print_info "Current directory: $(pwd)"
    
    # Check if we're in the right directory
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

# Run main function
main "$@"