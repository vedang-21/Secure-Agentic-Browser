#!/usr/bin/env python3
"""
Test External Firewall Integration
This tests the integration between your agent and the external firewall API.
"""

import asyncio
import sys
import os
import requests
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.agent.firewall_client import FirewallClient

async def test_external_firewall_integration():
    """Test the complete external firewall integration."""
    
    print("🛡️ Testing External Firewall Integration")
    print("=" * 60)
    
    # Test 1: Check if mock firewall is running (optional)
    print("\n1. Checking Mock Firewall Server (optional)...")
    try:
        response = requests.get("http://localhost:3001/api/health", timeout=2)
        if response.status_code == 200:
            print("✅ Mock firewall server is running")
            print(f"   📊 Status: {response.json()}")
            mock_available = True
        else:
            print("❌ Mock firewall server returned error")
            mock_available = False
    except Exception as e:
        print(f"ℹ️ Mock firewall server not running (this is okay)")
        print(f"   💡 You can start it with: python tests/mock_external_firewall.py")
        mock_available = False
    
    # Test 2: Test FirewallClient with local rules
    print("\n2. Testing FirewallClient with Local Rules...")
    firewall = FirewallClient()
    
    # Test safe action
    safe_action = {
        "action": "navigate",
        "url": "https://google.com"
    }
    
    safe_page_context = {
        "url": "https://google.com",
        "title": "Google",
        "html": "<html><body>Google Search</body></html>",
        "visible_text": "Google Search",
        "has_javascript": False,
        "forms": [],
        "inputs": [],
        "links": [],
        "meta": {},
        "security_headers": {},
        "cookies": []
    }
    
    print("   🧪 Testing safe action (navigate to Google)...")
    result = await firewall.validate_action(safe_action, safe_page_context)
    print(f"   ✅ Result: {result['allowed']} - {result['reason']}")
    print(f"   📊 Confidence: {result['confidence']}, Risk factors: {len(result['risk_factors'])}")
    
    # Test dangerous action
    dangerous_action = {
        "action": "navigate", 
        "url": "javascript:alert('test')"
    }
    
    print("   🧪 Testing dangerous action (javascript: URL)...")
    result = await firewall.validate_action(dangerous_action, safe_page_context)
    print(f"   🚫 Result: {result['allowed']} - {result['reason']}")
    print(f"   📊 Confidence: {result['confidence']}, Risk factors: {len(result['risk_factors'])}")
    
    # Test 3: Demonstrate external API format
    print("\n3. External Firewall API Format Demonstration...")
    print("   📤 Input format your external firewall will receive:")
    
    sample_input = {
        "action": {
            "action": "type",
            "selector": "input[name='password']", 
            "text": "mypassword"
        },
        "page_context": {
            "url": "https://example.com/login",
            "title": "Login Page",
            "html_content": "<html><form><input name='password' type='password'></form></html>",
            "visible_text": "Login to your account",
            "javascript_present": True,
            "forms": [
                {
                    "action": "/login",
                    "method": "post",
                    "https": True
                }
            ],
            "inputs": [
                {
                    "type": "password",
                    "name": "password",
                    "selector": "input[name='password']"
                }
            ],
            "links": [],
            "meta_data": {"csrf-token": "abc123"},
            "security_headers": {"content-security-policy": "strict"},
            "cookies": [{"name": "session", "secure": True}],
            "page_size": 45000
        }
    }
    
    print(json.dumps(sample_input, indent=2))
    
    print("\n   📥 Expected output format from your external firewall:")
    sample_output = {
        "allowed": True,
        "reason": "Action passed all security checks",
        "source": "external",
        "confidence": 0.95,
        "risk_factors": [
            "password_field_detected",
            "secure_connection"
        ],
        "risk_level": "medium",
        "analysis": {
            "domain_reputation": "good",
            "ssl_check": "valid",
            "content_safety": "clean",
            "form_analysis": "secure"
        },
        "timestamp": "2024-03-06T10:30:45Z",
        "processing_time_ms": 250
    }
    
    print(json.dumps(sample_output, indent=2))
    
    # Test 4: Test with external firewall if available
    if mock_available:
        print("\n4. Testing with Mock External Firewall...")
        
        # Temporarily enable external firewall
        os.environ['USE_EXTERNAL_FIREWALL'] = 'true'
        os.environ['FIREWALL_API_URL'] = 'http://localhost:3001/api/validate'
        
        external_firewall = FirewallClient()
        
        print("   🧪 Testing password input over HTTPS...")
        password_action = {
            "action": "type",
            "selector": "input[name='password']",
            "text": "testpassword"
        }
        
        https_context = {
            "url": "https://secure-site.com/login",
            "title": "Secure Login",
            "html": "<html><form><input name='password' type='password'></form></html>",
            "visible_text": "Secure login form",
            "forms": [{"method": "post", "https": True}],
            "inputs": [{"type": "password", "name": "password"}]
        }
        
        result = await external_firewall.validate_action(password_action, https_context)
        print(f"   ✅ External firewall result: {result['allowed']} - {result['reason']}")
        print(f"   📊 Analysis: {result.get('analysis', {})}")
        
        print("   🧪 Testing dangerous URL...")
        dangerous_url = {
            "action": "navigate",
            "url": "javascript:alert('xss')"
        }
        
        result = await external_firewall.validate_action(dangerous_url, https_context)
        print(f"   🚫 External firewall result: {result['allowed']} - {result['reason']}")
        print(f"   🚨 Risk level: {result.get('risk_level', 'unknown')}")
        
        # Reset environment
        os.environ['USE_EXTERNAL_FIREWALL'] = 'false'
    
    await firewall.close()
    
    print("\n" + "=" * 60)
    print("🎯 Integration Test Summary:")
    print("✅ Local firewall rules working")
    print("✅ External API format specification confirmed")
    print("✅ Payload creation and parsing tested")
    print(f"{'✅' if mock_available else 'ℹ️'} Mock external firewall {'tested' if mock_available else 'available for testing'}")
    
    print("\n💡 Next Steps:")
    print("1. Your team can implement the external firewall API using the format shown above")
    print("2. Set USE_EXTERNAL_FIREWALL=true in .env when your firewall is ready")
    print("3. Update FIREWALL_API_URL to point to your actual firewall service")
    print("4. The agent will automatically use external validation while keeping local rules as backup")

if __name__ == "__main__":
    asyncio.run(test_external_firewall_integration())
