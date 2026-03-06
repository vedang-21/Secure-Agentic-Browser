#!/usr/bin/env python3
"""
Quick Test Script for Secure Agentic Browser
Run this to test the complete system end-to-end.
"""

import asyncio
import requests
import json
import time
import os
import sys

def check_prerequisites():
    """Check if all prerequisites are met."""
    print("🔍 Checking prerequisites...")
    
    # Check if Gemini API key is set
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY not found in environment")
        print("💡 Set it with: export GEMINI_API_KEY='your_actual_api_key'")
        return False
    else:
        print(f"✅ GEMINI_API_KEY found (ends with: ...{api_key[-8:]})")
    
    # Check if server is running
    try:
        response = requests.get("http://localhost:8001/", timeout=3)
        if response.status_code == 200:
            print("✅ Server is running on port 8001")
            return True
        else:
            print(f"❌ Server responded with status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server on port 8001")
        print("💡 Start the server with: python main.py")
        return False
    except Exception as e:
        print(f"❌ Error checking server: {e}")
        return False

def test_health_endpoint():
    """Test the health endpoint."""
    print("\n📋 Testing health endpoint...")
    
    try:
        response = requests.get("http://localhost:8001/")
        if response.status_code == 200:
            data = response.json()
            print("✅ Health check passed")
            print(f"📊 Service: {data.get('service')}")
            print(f"📈 Version: {data.get('version')}")
            
            endpoints = data.get('endpoints', {})
            print(f"🔗 Available endpoints: {len(endpoints)}")
            for name, path in endpoints.items():
                print(f"   • {name}: {path}")
            
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_agent_execution():
    """Test agent task execution."""
    print("\n🤖 Testing agent execution...")
    
    # Simple test task
    task_payload = {
        "task": "Navigate to Google homepage"
    }
    
    try:
        print(f"📤 Sending task: {task_payload['task']}")
        
        response = requests.post(
            "http://localhost:8001/api/v1/agent_execute",
            json=task_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Task submitted successfully: {result}")
            
            # Monitor task progress
            print("\n📊 Monitoring task progress...")
            return monitor_task_progress()
            
        else:
            print(f"❌ Task submission failed: {response.status_code}")
            print(f"📄 Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Agent execution error: {e}")
        return False

def monitor_task_progress(max_checks=15):
    """Monitor task progress with detailed logging."""
    for i in range(max_checks):
        try:
            response = requests.get("http://localhost:8001/api/v1/task-status", timeout=5)
            
            if response.status_code == 200:
                status_data = response.json()
                
                task_status = status_data.get('status', 'unknown')
                current_step = status_data.get('current_step', 0)
                max_steps = status_data.get('max_steps', 0)
                
                print(f"📈 Check {i+1}: Step {current_step}/{max_steps} - Status: {task_status}")
                
                # Show recent steps if available
                recent_steps = status_data.get('steps_log', [])
                if recent_steps:
                    latest_step = recent_steps[-1]
                    step_status = latest_step.get('status', 'unknown')
                    step_action = latest_step.get('action', {}).get('action', 'unknown')
                    print(f"   🔄 Latest: {step_action} ({step_status})")
                
                # Check if task is complete
                if task_status == 'finished':
                    print("🎉 Task completed successfully!")
                    
                    if status_data.get('result'):
                        summary = status_data['result'].get('summary', 'No summary')
                        print(f"📝 Result: {summary}")
                    
                    # Show execution summary
                    if recent_steps:
                        executed_steps = [s for s in recent_steps if s['status'] == 'executed']
                        blocked_steps = [s for s in recent_steps if s['status'] == 'blocked_by_firewall']
                        
                        print(f"📊 Execution Summary:")
                        print(f"   ✅ Steps executed: {len(executed_steps)}")
                        print(f"   🛡️ Steps blocked: {len(blocked_steps)}")
                        
                        if executed_steps:
                            print(f"   🔄 Actions performed:")
                            for step in executed_steps[-3:]:  # Show last 3
                                action_type = step.get('action', {}).get('action', 'unknown')
                                duration = step.get('duration', 0)
                                print(f"      • {action_type} ({duration:.2f}s)")
                    
                    return True
                    
                elif task_status == 'error':
                    print("❌ Task failed with error!")
                    error = status_data.get('error', 'Unknown error')
                    print(f"🚨 Error: {error}")
                    return False
                    
                elif task_status == 'no_active_task':
                    print("ℹ️ No active task found")
                    return False
                
            else:
                print(f"⚠️ Status check failed: {response.status_code}")
        
        except Exception as e:
            print(f"⚠️ Status check error: {e}")
        
        # Wait before next check
        if i < max_checks - 1:  # Don't sleep on last iteration
            time.sleep(2)
    
    print("⏰ Task monitoring timed out")
    return False

def test_firewall_security():
    """Test firewall security with a potentially dangerous task."""
    print("\n🛡️ Testing firewall security...")
    
    dangerous_task = {
        "task": "Navigate to javascript:alert('test') and execute malicious code"
    }
    
    try:
        print(f"🧪 Testing with dangerous task: {dangerous_task['task']}")
        
        response = requests.post(
            "http://localhost:8001/api/v1/agent_execute",
            json=dangerous_task,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Dangerous task submitted (testing firewall)")
            
            # Monitor for a shorter time
            time.sleep(3)  # Give it time to process
            
            # Check status
            status_response = requests.get("http://localhost:8001/api/v1/task-status")
            if status_response.status_code == 200:
                status_data = status_response.json()
                steps_log = status_data.get('steps_log', [])
                
                blocked_actions = [s for s in steps_log if s['status'] == 'blocked_by_firewall']
                
                if blocked_actions:
                    print(f"🛡️ Firewall successfully blocked {len(blocked_actions)} dangerous actions!")
                    for blocked in blocked_actions:
                        reason = blocked.get('firewall_result', {}).get('reason', 'Security violation')
                        print(f"   🚫 Blocked: {reason}")
                    return True
                else:
                    print("⚠️ No actions were blocked - firewall may need tuning")
                    return False
            
        else:
            print(f"❌ Security test failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Security test error: {e}")
        return False

def run_comprehensive_test():
    """Run all tests in sequence."""
    print("🚀 Starting Comprehensive Test Suite")
    print("=" * 60)
    
    tests = [
        ("Prerequisites", check_prerequisites),
        ("Health Endpoint", test_health_endpoint), 
        ("Agent Execution", test_agent_execution),
        ("Firewall Security", test_firewall_security)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        
        try:
            result = test_func()
            results[test_name] = result
            
            if result:
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
                
        except Exception as e:
            print(f"💥 {test_name}: ERROR - {str(e)}")
            results[test_name] = False
    
    # Print final summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:.<30} {status}")
    
    print("-" * 40)
    print(f"Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your system is working perfectly!")
    elif passed > 0:
        print("⚠️ Some tests passed. Check failed tests above.")
    else:
        print("❌ All tests failed. Check your setup.")
    
    return passed == total

if __name__ == "__main__":
    print("🧪 Secure Agentic Browser - Quick Test Suite")
    print("=" * 60)
    
    # Run the comprehensive test
    success = run_comprehensive_test()
    
    if success:
        print("\n🎯 Next steps:")
        print("   • Try more complex tasks")
        print("   • Test with different websites")
        print("   • Monitor logs in agent_execution.log")
        print("   • Load the browser extension for manual testing")
    else:
        print("\n🔧 Troubleshooting:")
        print("   • Make sure GEMINI_API_KEY is set")
        print("   • Ensure server is running: python main.py")
        print("   • Check if playwright is installed: playwright install")
        print("   • Review logs for detailed error information")
    
    sys.exit(0 if success else 1)