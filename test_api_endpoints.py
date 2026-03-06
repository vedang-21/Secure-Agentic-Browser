#!/usr/bin/env python3
"""
Test the /agent_execute endpoint
"""

import requests
import json
import time

def test_agent_execute_endpoint():
    """Test the new /agent_execute endpoint"""
    
    base_url = "http://localhost:8001/api/v1"
    
    print("🧪 Testing /agent_execute endpoint")
    print("=" * 50)
    
    # Test data
    test_request = {
        "task": "Find best laptop under 60000"
    }
    
    try:
        print(f"📤 Sending request: {test_request}")
        
        # Send POST request to /agent_execute
        response = requests.post(
            f"{base_url}/agent_execute",
            json=test_request,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Success: {result}")
            
            if result.get("status") == "started":
                print("🚀 Agent task started successfully!")
                
                # Monitor task status
                print("\n📊 Monitoring task status...")
                for i in range(5):
                    time.sleep(2)
                    try:
                        status_response = requests.get(f"{base_url}/task-status")
                        if status_response.status_code == 200:
                            status_data = status_response.json()
                            print(f"   Status: {status_data.get('status', 'unknown')}")
                            print(f"   Step: {status_data.get('current_step', 0)}/{status_data.get('max_steps', 0)}")
                        else:
                            print(f"   Status check failed: {status_response.status_code}")
                    except Exception as e:
                        print(f"   Status check error: {str(e)}")
            
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - make sure the server is running:")
        print("   python main.py")
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")

def test_all_endpoints():
    """Test all available endpoints"""
    
    base_url = "http://localhost:8001/api/v1"
    
    print("\n🔍 Testing all endpoints")
    print("=" * 50)
    
    endpoints = [
        ("GET", "/health", None),
        ("POST", "/agent_execute", {"task": "Go to Google homepage"}),
        ("GET", "/task-status", None),
        ("POST", "/stop-task", None)
    ]
    
    for method, endpoint, data in endpoints:
        try:
            print(f"\n{method} {endpoint}")
            
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}", timeout=5)
            else:
                response = requests.post(
                    f"{base_url}{endpoint}",
                    json=data,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
            
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"Response: {json.dumps(result, indent=2)}")
            else:
                print(f"Error: {response.text}")
                
        except Exception as e:
            print(f"Failed: {str(e)}")

if __name__ == "__main__":
    print("🚀 Agent API Endpoint Tests")
    
    # Test the main endpoint
    test_agent_execute_endpoint()
    
    # Test all endpoints
    test_all_endpoints()
    
    print("\n✅ Tests completed!")
    print("\nTo start the server:")
    print("  export GEMINI_API_KEY='your_key'")
    print("  python main.py")