#!/usr/bin/env python3

"""
Example usage of the BrowserExecutor class
"""

import asyncio
from src.agent.action_executor import BrowserExecutor

async def example_usage():
    """Demonstrate how to use BrowserExecutor"""
    
    # Create executor instance
    executor = BrowserExecutor()
    
    try:
        print("🚀 Starting browser automation example...")
        
        # Navigate to Google
        print("📍 Navigating to Google...")
        content = await executor.execute({
            "action": "navigate",
            "url": "https://google.com"
        })
        print(f"Page content preview: {content[:200]}...")
        
        # Type in search box
        print("⌨️  Typing search query...")
        content = await executor.execute({
            "action": "type",
            "selector": "input[name='q']",
            "text": "best laptops under 60000"
        })
        
        # Click search button
        print("🔍 Clicking search...")
        content = await executor.execute({
            "action": "click",
            "selector": "input[type='submit']"
        })
        
        # Wait a moment for results
        await asyncio.sleep(3)
        
        # Extract search results
        print("📊 Extracting search results...")
        results = await executor.execute({
            "action": "extract",
            "selector": "h3"
        })
        
        print(f"Search results: {results[:500]}...")
        
        print("✅ Example completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    finally:
        # Clean up
        await executor.cleanup()

if __name__ == "__main__":
    asyncio.run(example_usage())