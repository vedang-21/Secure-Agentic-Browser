#!/usr/bin/env python3
"""
Comprehensive System Diagnostic
Diagnose and fix all issues preventing the system from working
"""

import os
import sys
import subprocess
import importlib
from pathlib import Path

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🔍 {title}")
    print('='*60)

def print_result(test_name, passed, message=""):
    """Print test result."""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{test_name:.<40} {status}")
    if message and not passed:
        print(f"   💡 {message}")

def check_python_environment():
    """Check Python and virtual environment."""
    print_header("PYTHON ENVIRONMENT")
    
    results = {}
    
    # Python version
    py_version = sys.version_info
    python_ok = py_version >= (3, 8)
    results['python'] = python_ok
    print_result("Python 3.8+", python_ok, f"Current: {py_version.major}.{py_version.minor}")
    
    # Virtual environment
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    results['venv'] = in_venv
    print_result("Virtual Environment", in_venv, "Run: python -m venv venv && source venv/bin/activate")
    
    return all(results.values())

def check_required_packages():
    """Check if all required packages are installed."""
    print_header("REQUIRED PACKAGES")
    
    packages = {
        'fastapi': 'pip install fastapi',
        'uvicorn': 'pip install uvicorn',
        'playwright': 'pip install playwright',
        'google.generativeai': 'pip install google-generativeai',
        'httpx': 'pip install httpx',
        'pydantic': 'pip install pydantic',
        'requests': 'pip install requests',
        'dotenv': 'pip install python-dotenv'
    }
    
    results = {}
    missing_packages = []
    
    for package, install_cmd in packages.items():
        try:
            if package == 'google.generativeai':
                import google.generativeai
            elif package == 'dotenv':
                import dotenv
            else:
                importlib.import_module(package)
            
            results[package] = True
            print_result(package, True)
            
        except ImportError:
            results[package] = False
            missing_packages.append(install_cmd)
            print_result(package, False, install_cmd)
    
    if missing_packages:
        print(f"\n💡 Install missing packages:")
        print("pip install fastapi uvicorn playwright google-generativeai httpx pydantic requests python-dotenv")
    
    return all(results.values())

def check_environment_variables():
    """Check environment variables."""
    print_header("ENVIRONMENT VARIABLES")
    
    # Load .env file
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print_result("dotenv loading", True)
    except ImportError:
        print_result("dotenv loading", False, "pip install python-dotenv")
        return False
    
    # Check API key
    api_key = os.getenv("GOOGLE_API_KEY")
    api_key_ok = api_key and len(api_key) > 20 and api_key.startswith("AIzaSy")
    
    print_result("GOOGLE_API_KEY", api_key_ok, "Check your .env file")
    
    if api_key_ok:
        print(f"   🔑 API key found: ...{api_key[-8:]}")
    
    return api_key_ok

def check_playwright_browsers():
    """Check if Playwright browsers are installed."""
    print_header("PLAYWRIGHT BROWSERS")
    
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            # Try to get browser executable path
            browser_path = p.chromium.executable_path
            browser_exists = Path(browser_path).exists()
            
            print_result("Chromium browser", browser_exists, "Run: playwright install")
            
            if browser_exists:
                print(f"   📁 Browser path: {browser_path}")
            
            return browser_exists
            
    except ImportError:
        print_result("Playwright", False, "pip install playwright")
        return False
    except Exception as e:
        print_result("Browser check", False, f"Error: {str(e)}")
        return False

def check_file_structure():
    """Check if all required files exist."""
    print_header("PROJECT FILE STRUCTURE")
    
    required_files = [
        "main.py",
        "src/agent/agent_controller.py",
        "src/agent/llm_planner.py", 
        "src/agent/firewall_client.py",
        "src/api/agent_routes.py",
        ".env",
        "requirements.txt"
    ]
    
    results = {}
    
    for file_path in required_files:
        exists = Path(file_path).exists()
        results[file_path] = exists
        print_result(file_path, exists, f"File missing: {file_path}")
    
    return all(results.values())

def test_imports():
    """Test if core modules can be imported."""
    print_header("MODULE IMPORTS")
    
    modules = [
        ("src.agent.llm_planner", "LLM Planner"),
        ("src.agent.firewall_client", "Firewall Client"),
        ("src.agent.agent_controller", "Agent Controller"),
        ("src.api.agent_routes", "API Routes")
    ]
    
    results = {}
    
    for module_name, display_name in modules:
        try:
            importlib.import_module(module_name)
            results[module_name] = True
            print_result(display_name, True)
            
        except ImportError as e:
            results[module_name] = False
            print_result(display_name, False, str(e))
        except Exception as e:
            results[module_name] = False
            print_result(display_name, False, f"Error: {str(e)}")
    
    return all(results.values())

def test_basic_browser():
    """Test basic browser functionality."""
    print_header("BROWSER TEST")
    
    try:
        import asyncio
        from playwright.async_api import async_playwright
        
        async def browser_test():
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto("data:text/html,<h1>Test</h1>")
            title = await page.title()
            await browser.close()
            await playwright.stop()
            return "Test" in title
        
        result = asyncio.run(browser_test())
        print_result("Basic Browser", result, "Browser failed to start")
        return result
        
    except Exception as e:
        print_result("Basic Browser", False, str(e))
        return False

def generate_fix_script():
    """Generate a script to fix common issues."""
    fix_script = """#!/bin/bash
# Auto-generated fix script for Secure Agentic Browser

echo "🔧 Fixing Secure Agentic Browser Issues..."

# Install required packages
echo "📦 Installing required packages..."
pip install fastapi uvicorn playwright google-generativeai httpx pydantic requests python-dotenv

# Install Playwright browsers
echo "🌐 Installing Playwright browsers..."
playwright install

# Verify installation
echo "✅ Installation complete!"

echo "🧪 Run this to test:"
echo "python diagnose_system.py"
"""
    
    with open("fix_system.sh", "w") as f:
        f.write(fix_script)
    
    # Make executable
    os.chmod("fix_system.sh", 0o755)
    
    print(f"\n💡 Generated fix_system.sh - run with: ./fix_system.sh")

def main():
    """Run complete system diagnostic."""
    print("🔍 COMPREHENSIVE SYSTEM DIAGNOSTIC")
    print("="*60)
    print("This will check everything needed for the Secure Agentic Browser")
    
    # Run all checks
    checks = [
        ("Python Environment", check_python_environment),
        ("Required Packages", check_required_packages),
        ("Environment Variables", check_environment_variables),
        ("File Structure", check_file_structure), 
        ("Module Imports", test_imports),
        ("Playwright Browsers", check_playwright_browsers),
        ("Basic Browser Test", test_basic_browser)
    ]
    
    results = {}
    
    for check_name, check_func in checks:
        try:
            result = check_func()
            results[check_name] = result
        except Exception as e:
            print(f"❌ {check_name} failed with error: {str(e)}")
            results[check_name] = False
    
    # Summary
    print_header("DIAGNOSTIC SUMMARY")
    
    passed = 0
    total = len(results)
    
    for check_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{check_name:.<40} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} checks passed")
    
    # Recommendations
    if passed == total:
        print("\n🎉 All checks passed! Your system should work perfectly.")
        print("\n🚀 Try running:")
        print("   python main.py")
        
    elif passed >= total * 0.7:  # 70% or more passed
        print("\n⚠️  Most checks passed. Try running the system:")
        print("   python main.py")
        print("\n   If issues persist, fix the failed checks above.")
        
    else:
        print("\n🔧 Multiple issues found. To fix automatically:")
        generate_fix_script()
        print("   ./fix_system.sh")
        print("\n   Or install manually:")
        print("   pip install -r requirements.txt")
        print("   playwright install")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️ Diagnostic interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Diagnostic failed: {str(e)}")
        sys.exit(1)