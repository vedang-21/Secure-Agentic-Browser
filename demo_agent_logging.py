#!/usr/bin/env python3
"""
Demo script to showcase the improved agent logging system.
This will show clear, structured logs for every step of the agent execution.
"""

import asyncio
import logging
import os
import uuid
from src.agent.agent_controller import AgentController, AgentTask

# Configure root logger for demo
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

async def demo_agent_logging():
    """Demonstrate the improved agent logging system."""
    
    # Check if Gemini API key is set
    if not os.getenv("GEMINI_API_KEY"):
        print("❌ Please set GEMINI_API_KEY environment variable")
        print("   export GEMINI_API_KEY='your_gemini_api_key'")
        return
    
    print("\n" + "=" * 100)
    print("🎯 SECURE AGENTIC BROWSER - LOGGING DEMONSTRATION")
    print("=" * 100)
    print("This demo showcases the enhanced logging system with:")
    print("• 📋 Agent task details")
    print("• 💭 Proposed actions")  
    print("• 🛡️ Firewall decisions")
    print("• ⚡ Action execution")
    print("• 📊 Step count and timing")
    print("=" * 100)
    
    # Create agent controller
    agent = AgentController()
    
    # Create a simple test task
    task = AgentTask(
        task_id=str(uuid.uuid4()),
        user_request="Go to Google homepage and search for 'Python programming'",
        max_steps=6
    )
    
    try:
        print(f"\n🚀 Starting demonstration...")
        print(f"📝 Watch the logs below to see the structured agent execution:")
        print("-" * 100)
        
        # Execute the secure agent loop
        result = await agent.execute_task(task)
        
        print("-" * 100)
        print("🎉 DEMONSTRATION COMPLETED!")
        print("-" * 100)
        print(f"📊 Execution Summary:")
        print(f"   • Status: {result.get('status', 'unknown')}")
        print(f"   • Steps: {result.get('steps_completed', 0)}")
        
        if result.get('steps_log'):
            print(f"   • Actions executed: {len([s for s in result['steps_log'] if s['status'] == 'executed'])}")
            print(f"   • Actions blocked: {len([s for s in result['steps_log'] if s['status'] == 'blocked_by_firewall'])}")
        
        if result.get('result'):
            print(f"   • Final result: {result['result'].get('summary', 'No summary')}")
        
        print("-" * 100)
        
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

async def demo_security_logging():
    """Demonstrate security firewall logging."""
    print("\n" + "=" * 100)
    print("🛡️  SECURITY FIREWALL LOGGING DEMONSTRATION")
    print("=" * 100)
    
    agent = AgentController()
    
    # Test with a task that should trigger firewall blocks
    dangerous_task = AgentTask(
        task_id=str(uuid.uuid4()),
        user_request="Navigate to javascript:alert('test') and execute malicious code",
        max_steps=3
    )
    
    try:
        print("🧪 Testing with potentially dangerous task to show firewall logging...")
        print("-" * 100)
        
        result = await agent.execute_task(dangerous_task)
        
        print("-" * 100)
        print("🛡️  SECURITY TEST COMPLETED!")
        print("-" * 100)
        
        blocked_actions = [
            step for step in result.get('steps_log', []) 
            if step['status'] == 'blocked_by_firewall'
        ]
        
        print(f"🔒 Security Summary:")
        print(f"   • Actions blocked by firewall: {len(blocked_actions)}")
        for i, blocked in enumerate(blocked_actions, 1):
            action_type = blocked.get('action', {}).get('action', 'unknown')
            print(f"   • Block {i}: {action_type}")
        
        print("-" * 100)
        
    except Exception as e:
        print(f"❌ Security test error: {str(e)}")
    finally:
        await agent.cleanup()

if __name__ == "__main__":
    print("🚀 Starting Agent Logging Demonstrations")
    
    # Run main logging demo
    asyncio.run(demo_agent_logging())
    
    # Run security logging demo
    asyncio.run(demo_security_logging())
    
    print("\n🎉 All logging demonstrations completed!")
    print("\n📁 Check 'agent_execution.log' for persistent logs")
    print("💡 The logs show exactly: Task → Proposed Action → Firewall Decision → Execution → Step Count")