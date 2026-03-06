#!/usr/bin/env python3
"""
Interactive Demo for Secure Agentic Browser
This provides a hands-on demonstration of the system capabilities.
"""

import asyncio
import os
import uuid
from src.agent.agent_controller import AgentController, AgentTask

class InteractiveDemo:
    def __init__(self):
        self.agent_controller = AgentController()
        
    async def run_demo(self):
        """Run the interactive demonstration."""
        
        # Check prerequisites
        if not self.check_setup():
            return
        
        print("\n" + "🤖" * 30)
        print("   SECURE AGENTIC BROWSER DEMO")
        print("🤖" * 30)
        
        while True:
            choice = self.show_menu()
            
            if choice == '1':
                await self.demo_simple_navigation()
            elif choice == '2':
                await self.demo_google_search()
            elif choice == '3':
                await self.demo_security_features()
            elif choice == '4':
                await self.demo_custom_task()
            elif choice == '5':
                self.show_logs_info()
            elif choice == '6':
                print("👋 Thanks for trying the Secure Agentic Browser!")
                break
            else:
                print("❌ Invalid choice. Please try again.")
            
            input("\n⏸️  Press Enter to continue...")
    
    def check_setup(self):
        """Check if the system is properly set up."""
        print("🔍 Checking system setup...")
        
        # Check API key
        if not os.getenv("GEMINI_API_KEY"):
            print("❌ GEMINI_API_KEY not found")
            print("💡 Set it with: export GEMINI_API_KEY='your_key'")
            return False
        
        print("✅ Environment setup looks good!")
        return True
    
    def show_menu(self):
        """Show the interactive menu."""
        print("\n" + "=" * 50)
        print("🎯 What would you like to demonstrate?")
        print("=" * 50)
        print("1. 🌐 Simple Navigation Demo")
        print("2. 🔍 Google Search Demo") 
        print("3. 🛡️  Security & Firewall Demo")
        print("4. ✏️  Custom Task Demo")
        print("5. 📋 View Logs & Monitoring")
        print("6. 🚪 Exit")
        print("-" * 50)
        
        return input("👉 Enter your choice (1-6): ").strip()
    
    async def demo_simple_navigation(self):
        """Demo simple website navigation."""
        print("\n🌐 SIMPLE NAVIGATION DEMO")
        print("=" * 40)
        print("This demo shows the agent navigating to a website")
        print("and observing the page content.")
        
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            user_request="Navigate to https://example.com and describe what you see",
            max_steps=5
        )
        
        print(f"\n📋 Task: {task.user_request}")
        print("🚀 Starting execution...")
        
        result = await self.agent_controller.execute_task(task)
        self.show_result_summary(result)
    
    async def demo_google_search(self):
        """Demo Google search functionality."""
        print("\n🔍 GOOGLE SEARCH DEMO")
        print("=" * 40)
        print("This demo shows the agent performing a Google search")
        print("and analyzing search results.")
        
        search_query = input("🔎 What would you like to search for? (or press Enter for default): ").strip()
        if not search_query:
            search_query = "Python programming tutorials"
        
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            user_request=f"Go to Google and search for '{search_query}', then extract the first few search results",
            max_steps=8
        )
        
        print(f"\n📋 Task: {task.user_request}")
        print("🚀 Starting execution...")
        
        result = await self.agent_controller.execute_task(task)
        self.show_result_summary(result)
    
    async def demo_security_features(self):
        """Demo security and firewall features."""
        print("\n🛡️ SECURITY & FIREWALL DEMO")
        print("=" * 40)
        print("This demo shows how the firewall protects against")
        print("dangerous actions and malicious websites.")
        
        print("\n🧪 Testing with potentially dangerous actions...")
        
        # Test dangerous URL
        dangerous_task = AgentTask(
            task_id=str(uuid.uuid4()),
            user_request="Navigate to javascript:alert('test') and execute the code",
            max_steps=3
        )
        
        print(f"\n📋 Dangerous Task: {dangerous_task.user_request}")
        print("🚀 Starting execution (should be blocked)...")
        
        result = await self.agent_controller.execute_task(dangerous_task)
        
        # Analyze security results
        blocked_actions = [
            step for step in result.get('steps_log', [])
            if step['status'] == 'blocked_by_firewall'
        ]
        
        print(f"\n🛡️ Security Analysis:")
        print(f"   🚫 Actions blocked: {len(blocked_actions)}")
        
        for i, blocked in enumerate(blocked_actions, 1):
            firewall_result = blocked.get('firewall_result', {})
            reason = firewall_result.get('reason', 'Security violation')
            risk_factors = firewall_result.get('risk_factors', [])
            
            print(f"   Block {i}: {reason}")
            if risk_factors:
                print(f"      Risk factors: {risk_factors[:3]}")
        
        if blocked_actions:
            print("✅ Firewall is working correctly!")
        else:
            print("⚠️ No actions were blocked - this might indicate an issue")
    
    async def demo_custom_task(self):
        """Demo with user-defined custom task."""
        print("\n✏️ CUSTOM TASK DEMO")
        print("=" * 40)
        print("Enter your own task for the agent to perform.")
        print("Examples:")
        print("  • 'Go to Wikipedia and search for artificial intelligence'")
        print("  • 'Navigate to GitHub and search for Python projects'")
        print("  • 'Visit YouTube and find videos about machine learning'")
        
        custom_task = input("\n📝 Enter your task: ").strip()
        
        if not custom_task:
            print("❌ No task entered. Using default task.")
            custom_task = "Navigate to https://www.wikipedia.org and search for 'artificial intelligence'"
        
        # Ask for max steps
        try:
            max_steps_input = input("🔢 Max steps (press Enter for 10): ").strip()
            max_steps = int(max_steps_input) if max_steps_input else 10
            max_steps = max(1, min(max_steps, 20))  # Limit between 1-20
        except ValueError:
            max_steps = 10
        
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            user_request=custom_task,
            max_steps=max_steps
        )
        
        print(f"\n📋 Task: {task.user_request}")
        print(f"🔢 Max Steps: {max_steps}")
        print("🚀 Starting execution...")
        
        result = await self.agent_controller.execute_task(task)
        self.show_result_summary(result)
    
    def show_logs_info(self):
        """Show information about logs and monitoring."""
        print("\n📋 LOGS & MONITORING INFO")
        print("=" * 40)
        
        print("🗂️ Log Files:")
        print("   • Console: Real-time colored output")
        print("   • agent_execution.log: Persistent file logs")
        
        print("\n📊 Monitoring Commands:")
        print("   • tail -f agent_execution.log   # Watch live logs")
        print("   • grep 'Firewall' agent_execution.log   # Security events")
        print("   • grep 'ERROR' agent_execution.log   # Error analysis")
        
        print("\n🔍 What to Look For:")
        print("   ✅ Firewall: ALLOWED - Safe actions")
        print("   🚫 Firewall: BLOCKED - Security blocks")
        print("   🔄 Page content has changed - Successful actions")
        print("   ⏱️ Step X completed - Execution timing")
        
        print("\n🌐 API Endpoints (if server running):")
        print("   • GET http://localhost:8001/ - Health check")
        print("   • POST http://localhost:8001/api/v1/agent_execute - Execute task")
        print("   • GET http://localhost:8001/api/v1/task-status - Check status")
    
    def show_result_summary(self, result):
        """Show a summary of the execution result."""
        print("\n" + "📊" * 20)
        print("   EXECUTION SUMMARY")
        print("📊" * 20)
        
        status = result.get('status', 'unknown')
        steps_completed = result.get('steps_completed', 0)
        
        # Status with emoji
        status_emoji = {
            'finished': '✅',
            'error': '❌', 
            'running': '🔄'
        }.get(status, '❓')
        
        print(f"{status_emoji} Status: {status.upper()}")
        print(f"📈 Steps Completed: {steps_completed}")
        
        # Show result if available
        task_result = result.get('result', {})
        if task_result:
            summary = task_result.get('summary', 'No summary available')
            print(f"📝 Summary: {summary}")
        
        # Analyze steps
        steps_log = result.get('steps_log', [])
        if steps_log:
            executed_steps = [s for s in steps_log if s['status'] == 'executed']
            blocked_steps = [s for s in steps_log if s['status'] == 'blocked_by_firewall']
            
            print(f"\n🔄 Action Breakdown:")
            print(f"   ✅ Executed: {len(executed_steps)}")
            print(f"   🛡️ Blocked: {len(blocked_steps)}")
            
            # Show executed actions
            if executed_steps:
                print(f"\n⚡ Actions Performed:")
                for step in executed_steps[-5:]:  # Show last 5
                    action = step.get('action', {})
                    action_type = action.get('action', 'unknown')
                    duration = step.get('duration', 0)
                    
                    if action_type == 'navigate':
                        detail = action.get('url', 'unknown URL')
                    elif action_type == 'type':
                        detail = f"'{action.get('text', '')[:20]}...'"
                    elif action_type == 'click':
                        detail = action.get('selector', 'unknown')
                    else:
                        detail = str(action)
                    
                    print(f"   • {action_type}: {detail} ({duration:.2f}s)")
            
            # Show blocked actions
            if blocked_steps:
                print(f"\n🚫 Blocked Actions:")
                for step in blocked_steps:
                    action = step.get('action', {})
                    action_type = action.get('action', 'unknown')
                    reason = step.get('result', 'Security violation')
                    print(f"   • {action_type}: {reason}")
        
        # Show error if any
        error = result.get('error')
        if error:
            print(f"\n❌ Error: {error}")

async def main():
    """Run the interactive demo."""
    demo = InteractiveDemo()
    try:
        await demo.run_demo()
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\n💥 Demo error: {str(e)}")
    finally:
        # Cleanup
        try:
            await demo.agent_controller.cleanup()
        except:
            pass

if __name__ == "__main__":
    print("🚀 Starting Interactive Secure Agentic Browser Demo...")
    asyncio.run(main())