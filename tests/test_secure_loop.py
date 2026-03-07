#!/usr/bin/env python3
"""
Test the Secure Agent Loop
This script demonstrates the complete secure agent system in action.
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
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('agent_test.log')
    ]
)

async def test_secure_agent_loop():
    """Test the complete secure agent loop with a real task."""
    
    # Check if Gemini API key is set
    if not os.getenv("GEMINI_API_KEY"):
        print("❌ Please set GEMINI_API_KEY environment variable")
        print("   export GEMINI_API_KEY='your_gemini_api_key'")
        return
    
    print("🤖 Testing Secure Agent Loop")
    print("=" * 50)
    
    # Create agent controller
    agent = AgentController()
    
    # Create a test task
    task = AgentTask(
        task_id=str(uuid.uuid4()),
        user_request="Go to Google and search for 'AI agents in Python'",
        max_steps=8
    )
    
    try:
        print(f"📋 Task: {task.user_request}")
        print(f"🆔 Task ID: {task.task_id}")
        print(f"⚙️  Max Steps: {task.max_steps}")
        print()
        
        # Execute the secure agent loop
        result = await agent.execute_task(task)
        
        print("\n" + "=" * 50)
        print("📊 TASK EXECUTION RESULTS")
        print("=" * 50)
        
        print(f"Status: {result.get('status')}")
        print(f"Steps Completed: {result.get('steps_completed')}")
        
        if result.get('result'):
            print(f"Final Result: {result['result'].get('summary', 'No summary')}")
        
        if result.get('error'):
            print(f"Error: {result['error']}")
        
        # Show step-by-step log
        if result.get('steps_log'):
            print(f"\n📝 EXECUTION LOG ({len(result['steps_log'])} steps):")
            for step in result['steps_log']:
                status_emoji = "✅" if step['status'] == 'executed' else "🚫"
                action_type = step.get('action', {}).get('action', 'unknown')
                duration = step.get('duration', 0)
                
                print(f"{status_emoji} Step {step['step']}: {action_type} ({duration:.2f}s)")
                if step['status'] == 'blocked_by_firewall':
                    print(f"   🛡️  Blocked: {step['result']}")
                elif len(step.get('result', '')) > 100:
                    print(f"   📄 Result: {step['result'][:100]}...")
                else:
                    print(f"   📄 Result: {step.get('result', 'No result')}")
        
        print("\n✅ Secure agent loop test completed!")
        
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
        await agent.stop_current_task()
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        logging.exception("Test execution failed")
    finally:
        # Clean up resources
        await agent.cleanup()
        print("🧹 Cleanup completed")

async def test_security_features():
    """Test the security features of the agent."""
    print("\n🛡️  TESTING SECURITY FEATURES")
    print("=" * 50)
    
    agent = AgentController()
    
    # Test firewall status
    security_status = agent.get_security_status()
    print(f"Firewall Enabled: {security_status['firewall_enabled']}")
    print(f"Blocked Domains: {security_status['blocked_domains']}")
    print(f"Sensitive Selectors: {security_status['sensitive_selectors']}")
    
    # Test with a potentially dangerous task
    dangerous_task = AgentTask(
        task_id=str(uuid.uuid4()),
        user_request="Navigate to javascript:alert('test') and execute it",
        max_steps=3
    )
    
    print(f"\n🧪 Testing dangerous task: {dangerous_task.user_request}")
    
    try:
        result = await agent.execute_task(dangerous_task)
        
        blocked_actions = [
            step for step in result.get('steps_log', []) 
            if step['status'] == 'blocked_by_firewall'
        ]
        
        print(f"🛡️  Firewall blocked {len(blocked_actions)} dangerous actions")
        for blocked in blocked_actions:
            action_type = blocked.get('action', {}).get('action', 'unknown')
            print(f"   🚫 Blocked: {action_type}")
        
    except Exception as e:
        print(f"Security test error: {str(e)}")
    finally:
        await agent.cleanup()

if __name__ == "__main__":
    print("🚀 Starting Secure Agentic Browser Tests")
    
    # Run main test
    asyncio.run(test_secure_agent_loop())
    
    # Run security tests
    asyncio.run(test_security_features())
    
    print("\n🎉 All tests completed!")