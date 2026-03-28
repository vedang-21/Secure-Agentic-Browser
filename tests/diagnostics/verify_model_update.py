#!/usr/bin/env python3
"""
Verify Gemini Model Update
Check if the model was     print("📊 Gemini Model Information:")
    print("=" * 40)
    print("🔄 Updated Model: gemini-2.5-flash")
    print("   • Latest generation Gemini model")
    print("   • Enhanced reasoning capabilities")
    print("   • Improved speed and efficiency")
    print("   • Better context understanding")
    print("")
    print("📜 Previous Models:")
    print("   • gemini-2.0-flash: Fast but older")
    print("   • gemini-pro: Stable but slower")ly changed to gemini-2.0-flash
"""

import os
import sys

def check_model_update():
    """Check if the Gemini model was updated correctly."""
    print("🔍 Checking Gemini Model Configuration...")
    
    llm_planner_path = "src/agent/llm_planner.py"
    
    try:
        with open(llm_planner_path, 'r') as file:
            content = file.read()
            
        # Check for the new model
        if 'gemini-2.5-flash' in content:
            print("✅ Model successfully updated to gemini-2.5-flash")
            
            # Check if old model is still there
            if 'gemini-pro' in content or 'gemini-2.0-flash' in content:
                print("⚠️  Warning: Multiple model references found")
                print("    This might indicate an incomplete update")
            
            return True
            
        elif 'gemini-pro' in content or 'gemini-2.0-flash' in content:
            if 'gemini-pro' in content:
                print("❌ Model is still using gemini-pro")
            else:
                print("❌ Model is still using gemini-2.0-flash")
            return False
            
        else:
            print("❓ Could not find model configuration")
            return False
            
    except FileNotFoundError:
        print(f"❌ File not found: {llm_planner_path}")
        return False
    except Exception as e:
        print(f"❌ Error reading file: {str(e)}")
        return False

def test_import():
    """Test if the LLM planner can still be imported."""
    print("\n🧪 Testing LLM Planner import...")
    
    try:
        # Set a dummy API key for import test
        os.environ["GOOGLE_API_KEY"] = "test_key_for_import"
        
        from src.agent.llm_planner import LLMPlanner
        print("✅ LLMPlanner imported successfully")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {str(e)}")
        return False
    except ValueError as e:
        # This is expected if no real API key is set
        if "GOOGLE_API_KEY" in str(e):
            print("✅ LLMPlanner structure is correct (API key validation working)")
            return True
        else:
            print(f"❌ Unexpected error: {str(e)}")
            return False
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False

def show_model_info():
    """Show information about the Gemini models."""
    print("\n📊 Gemini Model Information:")
    print("=" * 40)
    print("🔄 Updated Model: gemini-2.0-flash")
    print("   • Faster response times")
    print("   • Improved performance")
    print("   • Better reasoning capabilities")
    print("")
    print("📜 Previous Model: gemini-pro")
    print("   • Stable but slower")
    print("   • Good general performance")

def main():
    """Run all checks."""
    print("🚀 Gemini Model Update Verification")
    print("=" * 50)
    
    model_check = check_model_update()
    import_check = test_import()
    
    print("\n" + "=" * 50)
    print("📊 Verification Results:")
    print(f"  Model Update: {'✅ PASS' if model_check else '❌ FAIL'}")
    print(f"  Import Test:  {'✅ PASS' if import_check else '❌ FAIL'}")
    
    if model_check and import_check:
        print("\n🎉 Model update successful!")
        print("🚀 Your agent will now use Gemini 2.0 Flash")
        show_model_info()
        return True
    else:
        print("\n🔧 Issues detected. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)