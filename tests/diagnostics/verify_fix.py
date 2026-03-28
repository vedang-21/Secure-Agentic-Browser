#!/usr/bin/env python3
"""
Simple test to verify the environment variable fix
"""

import os
import sys

def check_api_key():
    """Check if the API key is properly configured."""
    print("🔍 Checking API Key Configuration...")
    
    google_api_key = os.getenv("GOOGLE_API_KEY")
    gemini_api_key = os.getenv("GEMINI_API_KEY")  # Old name for reference
    
    if google_api_key:
        print(f"✅ GOOGLE_API_KEY is set (ends with: ...{google_api_key[-8:]})")
        return True
    elif gemini_api_key:
        print("⚠️  GEMINI_API_KEY found but GOOGLE_API_KEY is expected")
        print("💡 Please update to: export GOOGLE_API_KEY=\"your_key\"")
        return False
    else:
        print("❌ GOOGLE_API_KEY is not set")
        print("💡 Set it with: export GOOGLE_API_KEY=\"your_gemini_api_key\"")
        return False

def test_import():
    """Test if the agent components can be imported."""
    print("\n🧪 Testing imports...")
    
    try:
        from src.agent.agent_controller import AgentController, AgentTask
        print("✅ AgentController imported successfully")
        
        from src.agent.llm_planner import LLMPlanner
        print("✅ LLMPlanner imported successfully")
        
        from src.agent.firewall_client import FirewallClient
        print("✅ FirewallClient imported successfully")
        
        return True
    except ImportError as e:
        print(f"❌ Import error: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

def main():
    """Run all checks."""
    print("🔧 Environment Variable Fix Verification")
    print("=" * 50)
    
    api_check = check_api_key()
    import_check = test_import()
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    print(f"  API Key: {'✅ PASS' if api_check else '❌ FAIL'}")
    print(f"  Imports: {'✅ PASS' if import_check else '❌ FAIL'}")
    
    if api_check and import_check:
        print("\n🎉 All checks passed! You can now run the main system.")
        print("🚀 Try: python main.py")
        return True
    else:
        print("\n🔧 Please fix the issues above before running the system.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)