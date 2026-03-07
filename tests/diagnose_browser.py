#!/usr/bin/env python3
"""
Simple Browser Test - Diagnose browser initialization issues
This script tests browser startup with minimal configuration
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Setup simple logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

async def test_basic_playwright():
    """Test basic Playwright installation and browser launch."""
    print("🧪 Testing Basic Playwright Browser Launch")
    print("=" * 60)
    
    try:
        # Test 1: Import Playwright
        print("1️⃣ Testing Playwright import...")
        from playwright.async_api import async_playwright
        print("   ✅ Playwright imported successfully")
        
        # Test 2: Start Playwright
        print("2️⃣ Starting Playwright...")
        playwright = await async_playwright().start()
        print("   ✅ Playwright started successfully")
        
        # Test 3: Launch browser with minimal config
        print("3️⃣ Launching browser with minimal configuration...")
        browser = await playwright.chromium.launch(
            headless=False,  # Visible browser for debugging
            # NO CUSTOM ARGS - Let Playwright use defaults
        )
        print("   ✅ Browser launched successfully")
        
        # Test 4: Create context and page
        print("4️⃣ Creating browser context and page...")
        context = await browser.new_context()
        page = await context.new_page()
        print("   ✅ Page created successfully")
        
        # Test 5: Navigate to simple page
        print("5️⃣ Testing navigation to example.com...")
        await page.goto("https://example.com", wait_until="domcontentloaded")
        title = await page.title()
        print(f"   ✅ Navigation successful - Title: {title}")
        
        # Test 6: Get page content
        print("6️⃣ Testing page content extraction...")
        content = await page.inner_text("body")
        print(f"   ✅ Content extracted: {len(content)} characters")
        
        # Cleanup
        print("7️⃣ Cleaning up...")
        await page.close()
        await context.close()
        await browser.close()
        await playwright.stop()
        print("   ✅ Cleanup completed")
        
        print("\n🎉 ALL BROWSER TESTS PASSED!")
        print("✅ Playwright and Chrome are working correctly")
        return True
        
    except ImportError as e:
        print(f"   ❌ Playwright import failed: {e}")
        print("   💡 Try: pip install playwright")
        return False
        
    except Exception as e:
        error_msg = str(e)
        print(f"   ❌ Browser test failed: {error_msg}")
        
        # Provide specific troubleshooting
        if "browser executable" in error_msg.lower():
            print("   💡 Browser not found - Try: playwright install")
        elif "permission" in error_msg.lower():
            print("   💡 Permission issue - Try running as admin")
        elif "timeout" in error_msg.lower():
            print("   💡 Timeout issue - Browser may be slow to start")
        else:
            print("   💡 General browser error - See full error above")
        
        return False

async def test_with_minimal_args():
    """Test browser with minimal safe arguments."""
    print("\n" + "=" * 60)
    print("🔧 Testing Browser with Minimal Safe Arguments")
    print("=" * 60)
    
    try:
        from playwright.async_api import async_playwright
        
        playwright = await async_playwright().start()
        
        # Try with just essential flags
        safe_args = [
            "--disable-blink-features=AutomationControlled",  # Hide automation
            "--disable-extensions",  # Disable extensions
        ]
        
        print("🚀 Launching with minimal safe arguments...")
        browser = await playwright.chromium.launch(
            headless=False,
            args=safe_args
        )
        
        context = await browser.new_context()
        page = await context.new_page()
        
        await page.goto("https://httpbin.org/get")
        content = await page.content()
        
        print(f"✅ Success with minimal args! Content: {len(content)} chars")
        
        # Cleanup
        await page.close()
        await context.close()
        await browser.close()
        await playwright.stop()
        
        return True
        
    except Exception as e:
        print(f"❌ Minimal args test failed: {e}")
        return False

async def test_headless_mode():
    """Test if headless mode works better."""
    print("\n" + "=" * 60)
    print("👻 Testing Headless Browser Mode")
    print("=" * 60)
    
    try:
        from playwright.async_api import async_playwright
        
        playwright = await async_playwright().start()
        
        print("🚀 Launching in headless mode...")
        browser = await playwright.chromium.launch(
            headless=True,  # Headless mode
            args=["--disable-blink-features=AutomationControlled"]
        )
        
        context = await browser.new_context()
        page = await context.new_page()
        
        await page.goto("https://example.com")
        title = await page.title()
        
        print(f"✅ Headless mode works! Title: {title}")
        
        # Cleanup
        await page.close()
        await context.close()
        await browser.close()
        await playwright.stop()
        
        return True
        
    except Exception as e:
        print(f"❌ Headless test failed: {e}")
        return False

def check_system_info():
    """Check system information."""
    print("\n" + "=" * 60)
    print("🖥️  SYSTEM INFORMATION")
    print("=" * 60)
    
    print(f"Platform: {sys.platform}")
    print(f"Python: {sys.version}")
    
    # Check if Chrome is installed
    chrome_paths = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium-browser"
    ]
    
    print("\n🔍 Checking for Chrome/Chromium...")
    chrome_found = False
    for path in chrome_paths:
        if Path(path).exists():
            print(f"✅ Found: {path}")
            chrome_found = True
    
    if not chrome_found:
        print("❌ Chrome/Chromium not found in common locations")
        print("💡 Install Chrome: https://www.google.com/chrome/")
    
    # Check Playwright installation
    try:
        import playwright
        print(f"✅ Playwright version: {playwright.__version__}")
    except ImportError:
        print("❌ Playwright not installed")
        print("💡 Install with: pip install playwright")

async def run_all_tests():
    """Run all browser tests."""
    print("🧪 COMPREHENSIVE BROWSER DIAGNOSTICS")
    print("=" * 60)
    
    # System check
    check_system_info()
    
    # Test results
    results = {}
    
    # Test 1: Basic Playwright
    results["Basic Playwright"] = await test_basic_playwright()
    
    # Test 2: Minimal args (only if basic test passed)
    if results["Basic Playwright"]:
        results["Minimal Args"] = await test_with_minimal_args()
    else:
        results["Minimal Args"] = False
    
    # Test 3: Headless mode
    results["Headless Mode"] = await test_headless_mode()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name:.<30} {status}")
    
    passed_count = sum(results.values())
    total_count = len(results)
    
    print(f"\nOverall: {passed_count}/{total_count} tests passed")
    
    if passed_count > 0:
        print("\n🎉 At least one browser configuration works!")
        if results.get("Basic Playwright"):
            print("✅ Your system can run browsers - the issue may be in specific configurations")
        if results.get("Headless Mode"):
            print("💡 Consider using headless mode for stability")
    else:
        print("\n🔧 All browser tests failed. Troubleshooting steps:")
        print("1. Install Playwright: pip install playwright")
        print("2. Install browsers: playwright install")
        print("3. Install Chrome manually if needed")
        print("4. Try running as administrator")
        print("5. Check for antivirus interference")
    
    return passed_count > 0

if __name__ == "__main__":
    print("🔍 Starting Browser Diagnostics...")
    success = asyncio.run(run_all_tests())
    
    print("\n" + "=" * 60)
    if success:
        print("✅ Browser diagnostics completed - at least one mode works!")
        print("🚀 You can proceed with testing your agent system")
    else:
        print("❌ Browser diagnostics failed - fix issues above first")
    
    sys.exit(0 if success else 1)