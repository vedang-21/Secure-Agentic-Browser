#!/usr/bin/env python3
"""
Verify that all imports work correctly
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def test_imports():
    """Test all major imports"""
    print("🔍 Testing imports...\n")
    
    tests_passed = 0
    tests_failed = 0
    
    # Test core imports
    try:
        from src.core.agent import AgenticBrowser
        from src.core.security_mediator import SecurityMediator
        print("✅ Core imports: OK")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ Core imports: FAILED - {e}")
        tests_failed += 1
    
    # Test analyzer imports
    try:
        from src.analyzers.dom_analyzer import DOMAnalyzer
        from src.analyzers.nlp_classifier import NLPThreatClassifier
        from src.analyzers.llm_reasoner import LLMThreatReasoner
        print("✅ Analyzer imports: OK")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ Analyzer imports: FAILED - {e}")
        tests_failed += 1
    
    # Test policy imports
    try:
        from src.policies.risk_calculator import MultiFactorRiskCalculator
        print("✅ Policy imports: OK")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ Policy imports: FAILED - {e}")
        tests_failed += 1
    
    # Test utils imports
    try:
        from src.utils.performance_monitor import PerformanceMonitor
        from src.utils.metrics_collector import MetricsCollector
        from src.utils.explanation_generator import ExplanationGenerator
        print("✅ Utils imports: OK")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ Utils imports: FAILED - {e}")
        tests_failed += 1
    
    # Summary
    print("\n" + "="*50)
    print(f"Tests Passed: {tests_passed}")
    print(f"Tests Failed: {tests_failed}")
    
    if tests_failed == 0:
        print("\n✅ All imports working correctly!")
        return 0
    else:
        print("\n❌ Some imports failed. Check the error messages above.")
        return 1

if __name__ == '__main__':
    sys.exit(test_imports())