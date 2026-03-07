#!/usr/bin/env python3
"""
Test Directory Validator
Checks all test files for syntax errors and missing imports after moving to tests folder
"""

import os
import ast
import sys
from pathlib import Path

def check_test_directory_structure():
    """Check if tests directory has all expected files."""
    print("📁 Checking test directory structure...")
    
    expected_files = [
        "quick_test.py",
        "interactive_demo.py", 
        "test_agent.py",
        "diagnose_browser.py",
        "ultra_simple_browser_test.py",
        "test_macos_browser.py",
        "syntax_check.py",
        "verify_fix.py",
        "verify_model_update.py",
        "demo_agent_logging.py",
        "demo_adaptive_agent.py", 
        "example_browser_executor.py"
    ]
    
    tests_dir = Path("tests")
    if not tests_dir.exists():
        print("❌ Tests directory does not exist!")
        return False, []
    
    missing_files = []
    present_files = []
    
    for file_name in expected_files:
        file_path = tests_dir / file_name
        if file_path.exists():
            present_files.append(file_name)
            print(f"✅ {file_name}")
        else:
            missing_files.append(file_name)
            print(f"❌ {file_name} - MISSING")
    
    print(f"\n📊 Summary: {len(present_files)}/{len(expected_files)} files present")
    
    return len(missing_files) == 0, present_files

def check_file_syntax(file_path):
    """Check if a Python file has valid syntax."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse the AST to check for syntax errors
        ast.parse(content, filename=str(file_path))
        return True, None
        
    except SyntaxError as e:
        return False, f"Syntax error: {str(e)} at line {e.lineno}"
    except Exception as e:
        return False, f"Error reading file: {str(e)}"

def check_import_paths(file_path):
    """Check if import paths are correct for tests directory."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        issues = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for relative imports that might be broken
            if 'from src.' in line or 'import src.' in line:
                # Should have sys.path modification for tests directory
                if 'sys.path.append' not in content:
                    issues.append(f"Line {i}: {line} - Missing sys.path.append for src imports")
            
            # Check for imports from parent directory without path adjustment
            if 'from ..agent' in line or 'from ..api' in line:
                issues.append(f"Line {i}: {line} - Relative import may not work from tests directory")
        
        return len(issues) == 0, issues
        
    except Exception as e:
        return False, [f"Error checking imports: {str(e)}"]

def validate_all_test_files():
    """Validate all test files for syntax and import issues."""
    print("\n🔍 Validating all test files...")
    print("=" * 60)
    
    structure_ok, present_files = check_test_directory_structure()
    
    if not structure_ok:
        print("\n❌ Test directory structure is incomplete")
        return False
    
    print(f"\n🧪 Checking syntax and imports for {len(present_files)} files...")
    
    all_good = True
    
    for file_name in present_files:
        file_path = Path("tests") / file_name
        print(f"\n📋 Checking {file_name}:")
        
        # Check syntax
        syntax_ok, syntax_error = check_file_syntax(file_path)
        if syntax_ok:
            print(f"   ✅ Syntax: Valid")
        else:
            print(f"   ❌ Syntax: {syntax_error}")
            all_good = False
        
        # Check imports
        imports_ok, import_issues = check_import_paths(file_path)
        if imports_ok:
            print(f"   ✅ Imports: OK")
        else:
            print(f"   ⚠️  Import issues:")
            for issue in import_issues[:3]:  # Show first 3 issues
                print(f"      • {issue}")
            if len(import_issues) > 3:
                print(f"      • ... and {len(import_issues) - 3} more")
    
    print("\n" + "=" * 60)
    if all_good:
        print("🎉 All test files are valid!")
    else:
        print("🔧 Some files have issues that need fixing")
    
    return all_good

def suggest_fixes():
    """Suggest fixes for common issues."""
    print("\n🔧 COMMON FIXES FOR TEST FILES")
    print("=" * 60)
    
    print("1️⃣ For import path issues, add this at the top of test files:")
    print("```python")
    print("import sys")
    print("import os")
    print("sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))")
    print("```")
    
    print("\n2️⃣ Change relative imports from:")
    print("   from ..agent.something import Something")
    print("   TO:")
    print("   from src.agent.something import Something")
    
    print("\n3️⃣ For running tests from tests directory:")
    print("   cd tests")
    print("   python test_name.py")
    
    print("\n4️⃣ For running tests from project root:")
    print("   python tests/test_name.py")

def create_test_runner():
    """Create a simple test runner script."""
    runner_content = '''#!/usr/bin/env python3
"""
Test Runner - Run all tests from the project root
"""

import os
import sys
import subprocess
from pathlib import Path

def run_test(test_file):
    """Run a single test file."""
    test_path = Path("tests") / test_file
    if not test_path.exists():
        return False, f"Test file not found: {test_file}"
    
    try:
        result = subprocess.run(
            [sys.executable, str(test_path)],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            return True, "PASSED"
        else:
            return False, f"FAILED: {result.stderr[:200]}"
            
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, f"ERROR: {str(e)}"

def main():
    """Run all available tests."""
    print("🧪 Test Runner - Secure Agentic Browser")
    print("=" * 50)
    
    # Core tests to run
    tests = [
        ("syntax_check.py", "Syntax validation"),
        ("verify_fix.py", "Environment verification"),
        ("quick_test.py", "End-to-end system test"),
    ]
    
    results = {}
    
    for test_file, description in tests:
        print(f"\\n🔄 Running {description}...")
        success, message = run_test(test_file)
        results[test_file] = success
        
        if success:
            print(f"✅ {test_file}: {message}")
        else:
            print(f"❌ {test_file}: {message}")
    
    # Summary
    passed = sum(results.values())
    total = len(results)
    
    print(f"\\n📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
    else:
        print("🔧 Some tests failed - check output above")

if __name__ == "__main__":
    main()
'''
    
    with open("run_tests.py", "w") as f:
        f.write(runner_content)
    
    print("📝 Created run_tests.py - use this to run tests from project root")

if __name__ == "__main__":
    print("🔍 Test Directory Validation Tool")
    print("=" * 60)
    
    # Change to project root if we're in tests directory
    if os.path.basename(os.getcwd()) == "tests":
        os.chdir("..")
        print("📁 Changed to project root directory")
    
    success = validate_all_test_files()
    
    if not success:
        suggest_fixes()
    
    # Create test runner
    create_test_runner()
    
    print(f"\n🎯 Next steps:")
    print(f"   • Fix any syntax/import issues shown above")
    print(f"   • Run tests with: python run_tests.py")
    print(f"   • Or run individual tests: python tests/test_name.py")
    
    sys.exit(0 if success else 1)