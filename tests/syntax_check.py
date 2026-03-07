#!/usr/bin/env python3
"""
Quick syntax check for all Python files
"""

import ast
import os
import sys

def check_file_syntax(file_path):
    """Check if a Python file has valid syntax."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse the AST to check for syntax errors
        ast.parse(content, filename=file_path)
        return True, None
        
    except SyntaxError as e:
        return False, f"Syntax error: {str(e)} at line {e.lineno}"
    except Exception as e:
        return False, f"Error reading file: {str(e)}"

def main():
    """Check syntax of key files."""
    print("🔍 Checking Python file syntax...")
    print("=" * 50)
    
    # Key files to check
    files_to_check = [
        "main.py",
        "src/agent/llm_planner.py",
        "src/agent/agent_controller.py", 
        "src/agent/firewall_client.py",
        "src/agent/action_executor.py",
        "src/api/agent_routes.py"
    ]
    
    all_good = True
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            is_valid, error = check_file_syntax(file_path)
            
            if is_valid:
                print(f"✅ {file_path}")
            else:
                print(f"❌ {file_path}")
                print(f"   {error}")
                all_good = False
        else:
            print(f"⚠️  {file_path} (not found)")
    
    print("\n" + "=" * 50)
    if all_good:
        print("🎉 All files have valid syntax!")
        print("🚀 You can now run: python main.py")
    else:
        print("🔧 Fix the syntax errors above before running the server")
    
    return all_good

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)