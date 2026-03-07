#!/usr/bin/env python3
"""
Demo script to showcase the enhanced agent loop with post-action page reading.
This demonstrates how the agent reads the page after every action to adapt to changes.
"""

import asyncio
import logging
import os
import uuid
from src.agent.agent_controller import AgentController, AgentTask

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

async def demo_adaptive_agent():
    """Demonstrate the enhanced agent loop with page content adaptation."""
    
    # Check if Gemini API key is set
    if not os.getenv("GOOGLE_API_KEY"):
        print("❌ Please set GOOGLE_API_KEY environment variable")
        print("   export GOOGLE_API_KEY='your_gemini_api_key'")
        return
    
    print("\n" + "=" * 100)
    print("🧠 ADAPTIVE AGENT DEMONSTRATION - Enhanced Page Reading")
    print("=" * 100)
    print("This demo showcases the improved agent loop that:")
    print("• 📖 Reads page content BEFORE each decision")
    print("• ⚡ Executes actions based on current page state")
    print("• 🔄 Reads UPDATED page content AFTER each action")
    print("• 🧠 Uses fresh page content for next AI decision")
    print("• 🎯 Adapts to dynamic page changes")
    print("=" * 100)
    
    # Create agent controller
    agent = AgentController()
    
    # Create a task that will involve multiple page changes
    task = AgentTask(
        task_id=str(uuid.uuid4()),
        user_request="Go to Google, search for 'artificial intelligence', and click on the first result",
        max_steps=8
    )
    
    try:
        print(f"\n🚀 Starting adaptive agent demonstration...")
        print(f"📝 Task: {task.user_request}")
        print(f"🔄 Watch how the agent reads and adapts to page changes:")
        print("-" * 100)
        
        # Execute the enhanced agent loop
        result = await agent.execute_task(task)
        
        print("\n" + "=" * 100)
        print("🎉 ADAPTIVE AGENT DEMONSTRATION COMPLETED!")
        print("=" * 100)
        
        # Analyze page adaptation
        if result.get('steps_log'):
            print(f"📊 Page Adaptation Analysis:")
            
            for step in result['steps_log']:
                if step['status'] == 'executed':
                    step_num = step['step']
                    action_type = step.get('action', {}).get('action', 'unknown')
                    
                    page_before = step.get('page_before', '')
                    page_after = step.get('page_after', '')
                    
                    # Check if page content changed
                    content_changed = page_before != page_after
                    change_indicator = "🔄 CHANGED" if content_changed else "📋 UNCHANGED"
                    
                    print(f"   Step {step_num} ({action_type}): {change_indicator}")
                    
                    if content_changed:
                        before_length = len(page_before)
                        after_length = len(page_after)
                        print(f"      📏 Content length: {before_length} → {after_length} chars")
        
        print(f"\n📈 Execution Summary:")
        print(f"   • Status: {result.get('status', 'unknown')}")
        print(f"   • Steps: {result.get('steps_completed', 0)}")
        print(f"   • Final result: {result.get('result', {}).get('summary', 'No summary')}")
        print("=" * 100)
        
    except KeyboardInterrupt:
        print("\n⏹️  Demo interrupted by user")
        await agent.stop_current_task()
    except Exception as e:
        print(f"\n❌ Demo failed with error: {str(e)}")
        logging.exception("Demo execution failed")
    finally:
        # Clean up resources
        await agent.cleanup()
        print("🧹 Demo cleanup completed")

async def demo_page_content_reading():
    """Demonstrate direct page content reading capabilities."""
    print("\n" + "=" * 100)
    print("📖 PAGE CONTENT READING DEMONSTRATION")
    print("=" * 100)
    
    agent = AgentController()
    
    try:
        # Initialize browser
        await agent.browser_executor.initialize_browser()
        
        # Navigate to a test page
        print("🌐 Navigating to Google...")
        await agent.browser_executor.navigate("https://google.com")
        
        # Read initial page content
        print("\n📄 Reading initial page content:")
        initial_content = await agent._observe_page_content()
        print(f"Initial content preview: {initial_content[:200]}...")
        
        # Simulate typing in search box
        print("\n⌨️  Typing in search box...")
        await agent.browser_executor.type("input[name='q']", "machine learning")
        
        # Read updated page content
        print("\n📄 Reading page content after typing:")
        updated_content = await agent._observe_page_content()
        print(f"Updated content preview: {updated_content[:200]}...")
        
        # Check if content changed
        if initial_content != updated_content:
            print("✅ Page content successfully updated after typing!")
        else:
            print("⚠️  Page content appears unchanged")
        
        print("\n📊 Page Reading Summary:")
        print(f"   • Initial content length: {len(initial_content)} characters")
        print(f"   • Updated content length: {len(updated_content)} characters")
        print(f"   • Content changed: {'Yes' if initial_content != updated_content else 'No'}")
        
    except Exception as e:
        print(f"❌ Page reading test error: {str(e)}")
    finally:
        await agent.cleanup()

if __name__ == "__main__":
    print("🚀 Starting Enhanced Agent Loop Demonstrations")
    
    # Run adaptive agent demo
    asyncio.run(demo_adaptive_agent())
    
    # Run page reading demo  
    asyncio.run(demo_page_content_reading())
    
    print("\n🎉 All demonstrations completed!")
    print("\n💡 Key improvements:")
    print("   • Agent now reads page content after every action")
    print("   • AI gets fresh page state for each decision")
    print("   • Better adaptation to dynamic web pages")
    print("   • More accurate action planning based on current page")