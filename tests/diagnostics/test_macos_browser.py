#!/usr/bin/env python3
"""
Test macOS-Optimized Browser
This script tests the new browser executor without problematic Linux flags
"""

import asyncio
import logging
import os
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def test_macos_browser():
    """Test the macOS-optimized browser executor."""
    
    print("🍎 Testing macOS-Optimized Browser Executor")
    print("=" * 60)
    print("This test uses browser flags optimized for macOS:")
    print("✅ Removed: --no-sandbox (can break on macOS)")
    print("✅ Removed: --disable-dev-shm-usage (Linux-specific)")
    print("✅ Added: macOS-safe performance flags")
    print("=" * 60)
    
    try:
        # Import the macOS-optimized browser
        from src.agent.macos_browser_executor import MacOSBrowserExecutor
        
        print("\n🧪 Creating macOS browser executor...")
        executor = MacOSBrowserExecutor()
        
        print("🌐 Initializing browser (should be more stable on macOS)...")
        await executor.initialize_browser()
        
        print("✅ Browser initialized successfully!")
        print("📍 Testing navigation...")
        
        # Test navigation to a simple page
        await executor.navigate("https://example.com")
        print("✅ Navigation successful!")
        
        # Get page content
        print("📄 Testing page content extraction...")
        content = await executor.get_page_content()
        print(f"✅ Page content extracted: {len(content)} characters")
        
        # Show preview
        preview = content[:200] + "..." if len(content) > 200 else content
        print(f"📝 Content preview: {preview}")
        
        print("\n🎉 macOS Browser Test PASSED!")
        print("🚀 The browser should now work more reliably on macOS")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        print("\n🔧 If this still fails, try:")
        print("   • Make sure Playwright is installed: pip install playwright")
        print("   • Install browsers: playwright install")
        print("   • Check if Chrome is installed")
        return False
        
    finally:
        try:
            await executor.cleanup()
            print("🧹 Browser cleanup completed")
        except:
            pass

async def compare_browsers():
    """Compare old vs new browser settings."""
    print("\n" + "=" * 60)
    print("📊 BROWSER CONFIGURATION COMPARISON")
    print("=" * 60)
    
    print("❌ OLD (Linux/Docker flags - problematic on macOS):")
    print("   --no-sandbox")
    print("   --disable-dev-shm-usage") 
    print("   --disable-blink-features=AutomationControlled")
    
    print("\n✅ NEW (macOS-optimized flags):")
    print("   --disable-blink-features=AutomationControlled")
    print("   --disable-extensions")
    print("   --disable-plugins")
    print("   --disable-background-timer-throttling")
    print("   --disable-renderer-backgrounding")
    print("   (Removed problematic sandbox and shm flags)")
    
    print("\n🎯 Benefits:")
    print("   • More stable on macOS")
    print("   • Fewer browser crashes")
    print("   • Better compatibility")
    print("   • Improved performance")

async def main():
    """Run the macOS browser test."""
    
    # Check if we're on macOS
    if sys.platform != 'darwin':
        print("⚠️  This test is optimized for macOS")
        print(f"   Current platform: {sys.platform}")
        print("   The optimizations may still help on other platforms")
    
    success = await test_macos_browser()
    await compare_browsers()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 macOS Browser optimization successful!")
        print("🚀 Your agent should now work more reliably")
        print("\n💡 Next steps:")
        print("   • Run: python main.py")
        print("   • Test with: python quick_test.py") 
        print("   • Try: python interactive_demo.py")
    else:
        print("🔧 Browser test failed - may need further troubleshooting")
    
    return success

if __name__ == "__main__":
    print("🍎 Starting macOS Browser Optimization Test...")
    success = asyncio.run(main())
    sys.exit(0 if success else 1)