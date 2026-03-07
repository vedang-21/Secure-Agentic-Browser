#!/usr/bin/env python3
"""
Ultra-Simple Browser Test
Last resort test with absolutely minimal configuration
"""

import asyncio
import subprocess
import sys
import os

def check_playwright_installation():
    """Check if Playwright is properly installed."""
    print("🔍 Checking Playwright installation...")
    
    try:
        result = subprocess.run([sys.executable, "-c", "import playwright; print(playwright.__version__)"], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"✅ Playwright installed: version {version}")
            return True
        else:
            print(f"❌ Playwright import failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Playwright check timed out")
        return False
    except Exception as e:
        print(f"❌ Error checking Playwright: {e}")
        return False

def check_browser_binaries():
    """Check if browser binaries are installed."""
    print("\n🔍 Checking browser binaries...")
    
    try:
        result = subprocess.run([sys.executable, "-c", 
                               "from playwright.async_api import async_playwright; import asyncio; "
                               "async def check(): p = await async_playwright().start(); "
                               "print('Browsers available'); await p.stop(); "
                               "asyncio.run(check())"], 
                              capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("✅ Browser binaries are available")
            return True
        else:
            print(f"❌ Browser check failed: {result.stderr}")
            if "executable doesn't exist" in result.stderr:
                print("💡 Run: playwright install")
            return False
            
    except Exception as e:
        print(f"❌ Error checking browsers: {e}")
        return False

async def test_ultra_minimal_browser():
    """Test browser with absolutely no custom arguments."""
    print("\n🧪 Testing Ultra-Minimal Browser Configuration")
    print("=" * 50)
    
    try:
        from playwright.async_api import async_playwright
        
        print("1. Starting Playwright...")
        playwright = await async_playwright().start()
        
        print("2. Launching browser (NO custom arguments)...")
        # Absolutely minimal - no args, let Playwright handle everything
        browser = await playwright.chromium.launch(
            headless=True  # Use headless for maximum compatibility
        )
        
        print("3. Creating page...")
        page = await browser.new_page()
        
        print("4. Testing simple navigation...")
        await page.goto("data:text/html,<h1>Test Page</h1><p>Browser working!</p>")
        
        print("5. Extracting content...")
        title = await page.title()
        content = await page.inner_text("body")
        
        print(f"✅ Success! Title: '{title}', Content: '{content[:50]}'")
        
        # Quick cleanup
        await browser.close()
        await playwright.stop()
        
        return True
        
    except Exception as e:
        print(f"❌ Ultra-minimal test failed: {e}")
        
        # Specific error analysis
        error_str = str(e).lower()
        if "executable" in error_str:
            print("💡 Browser executable issue - try: playwright install")
        elif "permission" in error_str:
            print("💡 Permission issue - try running with sudo/admin")
        elif "timeout" in error_str:
            print("💡 Timeout - browser may be slow to start")
        elif "connection" in error_str:
            print("💡 Connection issue - check firewall/antivirus")
        else:
            print("💡 Unknown error - check system resources")
        
        return False

def suggest_fixes():
    """Suggest potential fixes based on common issues."""
    print("\n🔧 TROUBLESHOOTING SUGGESTIONS")
    print("=" * 50)
    
    print("If browser tests keep failing, try these steps:")
    print("")
    print("1️⃣ INSTALLATION ISSUES:")
    print("   pip install --upgrade playwright")
    print("   playwright install chromium")
    print("")
    print("2️⃣ SYSTEM ISSUES (macOS specific):")
    print("   • Update macOS to latest version")
    print("   • Install Xcode command line tools: xcode-select --install")
    print("   • Check available disk space (need ~1GB for browsers)")
    print("")
    print("3️⃣ PERMISSION ISSUES:")
    print("   • Run with: sudo python diagnose_browser.py")
    print("   • Check System Preferences > Security & Privacy")
    print("")
    print("4️⃣ ALTERNATIVE APPROACHES:")
    print("   • Use headless mode: headless=True")
    print("   • Try different browser: firefox or webkit")
    print("   • Use Docker container for isolation")
    print("")
    print("5️⃣ LAST RESORT:")
    print("   • Restart your computer")
    print("   • Disable antivirus temporarily")
    print("   • Try on a different user account")

async def main():
    """Run comprehensive browser diagnostics."""
    print("🔍 ULTRA-SIMPLE BROWSER DIAGNOSTICS")
    print("=" * 50)
    print("This test uses the most minimal browser configuration possible.")
    print("")
    
    # Step 1: Check Playwright
    if not check_playwright_installation():
        print("\n❌ Playwright is not properly installed")
        print("💡 Fix: pip install playwright")
        return False
    
    # Step 2: Check browsers
    if not check_browser_binaries():
        print("\n❌ Browser binaries are missing")
        print("💡 Fix: playwright install")
        return False
    
    # Step 3: Test ultra-minimal browser
    browser_works = await test_ultra_minimal_browser()
    
    # Results
    print("\n" + "=" * 50)
    if browser_works:
        print("🎉 SUCCESS! Browser is working with minimal configuration")
        print("✅ You can proceed with your agent system")
        print("\n💡 Recommendation: Use headless=True for stability")
    else:
        print("❌ Browser still not working even with minimal configuration")
        suggest_fixes()
    
    return browser_works

if __name__ == "__main__":
    print("🧪 Starting Ultra-Simple Browser Test...")
    
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏹️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)