#!/usr/bin/env python3
"""
Quick Fix Script for Secure Agentic Browser
This script will install missing packages and fix common issues
"""

import subprocess
import sys
import os
from pathlib import Path

def install_package(package):
    """Install a Python package using pip."""
    try:
        print(f"📦 Installing {package}...")
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", package
        ], capture_output=True, text=True, check=True)
        
        print(f"✅ {package} installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package}: {e.stderr}")
        return False

def install_playwright_browsers():
    """Install Playwright browser binaries."""
    try:
        print("🌐 Installing Playwright browsers...")
        result = subprocess.run([
            "playwright", "install"
        ], capture_output=True, text=True, check=True)
        
        print("✅ Playwright browsers installed")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install browsers: {e.stderr}")
        return False
    except FileNotFoundError:
        print("❌ Playwright command not found. Install playwright first.")
        return False

def check_api_key():
    """Check if API key is configured."""
    env_file = Path(".env")
    
    if not env_file.exists():
        print("❌ .env file not found")
        return False
    
    try:
        with open(".env", "r") as f:
            content = f.read()
        
        if "GOOGLE_API_KEY=" in content and "your_actual_gemini_api_key_here" not in content:
            # Extract API key to validate format
            for line in content.split('\n'):
                if line.startswith('GOOGLE_API_KEY=') and not line.startswith('#'):
                    api_key = line.split('=', 1)[1].strip()
                    if len(api_key) > 20 and api_key.startswith('AIzaSy'):
                        print("✅ API key configured correctly")
                        return True
        
        print("❌ API key not configured or invalid")
        return False
        
    except Exception as e:
        print(f"❌ Error checking API key: {e}")
        return False

def main():
    """Run the complete fix process."""
    print("🔧 QUICK FIX - Secure Agentic Browser")
    print("="*50)
    print("This will install missing dependencies and fix common issues")
    
    # Step 1: Install core packages
    print("\n1️⃣ Installing core packages...")
    packages = [
        "fastapi>=0.104.1",
        "uvicorn>=0.24.0", 
        "playwright>=1.40.0",
        "google-generativeai>=0.3.0",
        "httpx>=0.25.0",
        "pydantic>=2.5.0",
        "python-dotenv>=1.0.0",
        "requests>=2.31.0"
    ]
    
    failed_packages = []
    
    for package in packages:
        if not install_package(package):
            failed_packages.append(package)
    
    if failed_packages:
        print(f"\n❌ Failed to install: {', '.join(failed_packages)}")
        print("💡 Try running manually: pip install -r requirements.txt")
    else:
        print("\n✅ All packages installed successfully")
    
    # Step 2: Install Playwright browsers
    print("\n2️⃣ Installing browser binaries...")
    browsers_ok = install_playwright_browsers()
    
    # Step 3: Check API key
    print("\n3️⃣ Checking API key configuration...")
    api_key_ok = check_api_key()
    
    # Step 4: Test imports
    print("\n4️⃣ Testing imports...")
    test_imports = True
    
    try:
        import fastapi
        import uvicorn
        import playwright
        import google.generativeai
        import httpx
        import pydantic
        import dotenv
        import requests
        print("✅ All imports successful")
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        test_imports = False
    
    # Summary
    print("\n" + "="*50)
    print("📊 QUICK FIX SUMMARY")
    print("="*50)
    
    checks = [
        ("Core packages", len(failed_packages) == 0),
        ("Browser binaries", browsers_ok),
        ("API key", api_key_ok),
        ("Module imports", test_imports)
    ]
    
    passed = 0
    for check_name, result in checks:
        status = "✅ PASS" if result else "❌ FAIL" 
        print(f"{check_name:.<30} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{len(checks)} checks passed")
    
    # Next steps
    if passed == len(checks):
        print("\n🎉 System is ready!")
        print("🚀 Try running:")
        print("   python main.py")
        print("   python tests/quick_test.py")
        
    elif api_key_ok and test_imports:
        print("\n⚠️  System mostly ready, but browsers may have issues")
        print("🚀 Try running:")
        print("   python main.py")
        print("💡 If browser issues persist, run: playwright install --force")
        
    else:
        print("\n🔧 Issues remain:")
        
        if not api_key_ok:
            print("   • Configure your API key in .env file")
            print("     GOOGLE_API_KEY=your_actual_key_here")
        
        if not test_imports:
            print("   • Some packages failed to install")
            print("     Try: pip install -r requirements.txt")
        
        if not browsers_ok:
            print("   • Browser installation failed")
            print("     Try: playwright install --force")
    
    return passed == len(checks)

if __name__ == "__main__":
    try:
        success = main()
        
        print(f"\n🎯 For detailed diagnostics, run:")
        print(f"   python diagnose_system.py")
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n\n⏹️ Fix interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Fix failed: {str(e)}")
        sys.exit(1)