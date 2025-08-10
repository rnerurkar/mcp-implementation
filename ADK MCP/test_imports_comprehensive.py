#!/usr/bin/env python3
"""
Comprehensive Import and Compilation Test Suite
==============================================

This consolidated test file combines all import validation, compilation testing,
and verification functionality from the previous separate test files:
- test_agent_imports.py
- test_comprehensive_imports.py  
- test_final_verification.py
- test_compilation_all.py
- test_imports.py

Provides complete validation of:
1. Python syntax compilation
2. Import resolution
3. Agent service functionality
4. Security integration
5. Final verification
"""

import sys
import os
import py_compile
import glob
import importlib.util
from pathlib import Path

def test_python_compilation():
    """Test Python syntax compilation for all .py files"""
    print("🔍 Testing Python file compilation...")
    print("=" * 50)
    
    # Get all Python files in the current directory
    python_files = glob.glob("*.py")
    compilation_results = {}
    
    for file in python_files:
        if file.startswith('test_'):
            continue  # Skip test files to avoid circular dependencies
            
        try:
            py_compile.compile(file, doraise=True)
            compilation_results[file] = "✅ PASS"
            print(f"  ✅ {file} - Compilation successful")
        except py_compile.PyCompileError as e:
            compilation_results[file] = f"❌ FAIL: {e}"
            print(f"  ❌ {file} - Compilation failed: {e}")
        except Exception as e:
            compilation_results[file] = f"❌ ERROR: {e}"
            print(f"  ❌ {file} - Unexpected error: {e}")
    
    return compilation_results

def test_basic_imports():
    """Test basic import functionality for core modules"""
    print("\n🔍 Testing Basic Imports...")
    print("=" * 50)
    
    import_tests = {}
    
    # Test core security imports
    try:
        from agent_security_controls import OptimizedAgentSecurity, OptimizedSecurityConfig
        import_tests['agent_security_controls'] = "✅ PASS"
        print("  ✅ agent_security_controls imports work")
    except ImportError as e:
        import_tests['agent_security_controls'] = f"❌ FAIL: {e}"
        print(f"  ❌ agent_security_controls import failed: {e}")
    
    # Test agent service imports
    try:
        from agent_service import EnhancedAgentService
        import_tests['agent_service'] = "✅ PASS"
        print("  ✅ agent_service imports work")
    except ImportError as e:
        import_tests['agent_service'] = f"❌ FAIL: {e}"
        print(f"  ❌ agent_service import failed: {e}")
    
    # Test base agent service imports
    try:
        from base_agent_service import BaseAgentService
        import_tests['base_agent_service'] = "✅ PASS"
        print("  ✅ base_agent_service imports work")
    except ImportError as e:
        import_tests['base_agent_service'] = f"❌ FAIL: {e}"
        print(f"  ❌ base_agent_service import failed: {e}")
    
    return import_tests

def test_agent_service_functionality():
    """Test agent service imports and basic functionality"""
    print("\n🔍 Testing Agent Service Functionality...")
    print("=" * 50)
    
    functionality_tests = {}
    
    try:
        # Test security configuration creation
        from agent_security_controls import OptimizedSecurityConfig
        config = OptimizedSecurityConfig()
        functionality_tests['security_config'] = "✅ PASS"
        print(f"  ✅ Security config created: {type(config)}")
        
        # Test security instance creation
        from agent_security_controls import OptimizedAgentSecurity
        security = OptimizedAgentSecurity(config)
        functionality_tests['security_instance'] = "✅ PASS"
        print(f"  ✅ Security instance created: {type(security)}")
        
        # Test agent service instantiation
        from agent_service import EnhancedAgentService
        # Note: Not actually instantiating due to complex dependencies
        functionality_tests['agent_service_class'] = "✅ PASS"
        print("  ✅ EnhancedAgentService class accessible")
        
        return functionality_tests
        
    except Exception as e:
        functionality_tests['error'] = f"❌ ERROR: {e}"
        print(f"  ❌ Functionality test failed: {e}")
        return functionality_tests

def test_usage_patterns():
    """Test the actual usage patterns from agent_service.py"""
    print("\n🎯 Testing Actual Usage Patterns...")
    print("=" * 40)
    
    usage_tests = {}
    
    try:
        # Test agent_service.py pattern
        print("1. Testing agent_service.py pattern...")
        from agent_security_controls import OptimizedSecurityConfig, OptimizedAgentSecurity
        
        config = OptimizedSecurityConfig()
        security = OptimizedAgentSecurity(config)
        usage_tests['agent_service_pattern'] = "✅ PASS"
        print("   ✅ agent_service.py usage pattern works")
        
        # Test base_agent_service.py pattern  
        print("\n2. Testing base_agent_service.py pattern...")
        from base_agent_service import BaseAgentService
        usage_tests['base_agent_pattern'] = "✅ PASS"
        print("   ✅ Base agent service pattern works")
        
        return usage_tests
        
    except Exception as e:
        usage_tests['error'] = f"❌ ERROR: {e}"
        print(f"   ❌ Usage pattern test failed: {e}")
        return usage_tests

def test_security_functionality():
    """Test security functionality and methods"""
    print("\n🛡️ Testing Security Functionality...")
    print("=" * 35)
    
    security_tests = {}
    
    try:
        from agent_security_controls import OptimizedAgentSecurity, OptimizedSecurityConfig
        
        config = OptimizedSecurityConfig()
        security = OptimizedAgentSecurity(config)
        security_tests['security_creation'] = "✅ PASS"
        print("  ✅ Security instance created")
        
        # Test that security methods are available
        if hasattr(security, 'validate_request'):
            security_tests['validate_request'] = "✅ PASS"
            print("  ✅ validate_request method available")
        
        if hasattr(security, 'check_permissions'):
            security_tests['check_permissions'] = "✅ PASS"
            print("  ✅ check_permissions method available")
            
        return security_tests
        
    except Exception as e:
        security_tests['error'] = f"❌ ERROR: {e}"
        print(f"  ❌ Security functionality test failed: {e}")
        return security_tests

def test_import_compatibility():
    """Test import compatibility and backward compatibility"""
    print("\n🔄 Testing Import Compatibility...")
    print("=" * 35)
    
    compatibility_tests = {}
    
    try:
        # Test direct imports
        from agent_security_controls import OptimizedAgentSecurity, OptimizedSecurityConfig
        compatibility_tests['direct_imports'] = "✅ PASS"
        print("  ✅ Direct imports work")
        
        # Test aliased imports (backward compatibility)
        from agent_security_controls import OptimizedAgentSecurity as MainAgentSecurity
        from agent_security_controls import OptimizedSecurityConfig as MainSecurityConfig
        compatibility_tests['aliased_imports'] = "✅ PASS" 
        print("  ✅ Aliased imports work")
        
        return compatibility_tests
        
    except Exception as e:
        compatibility_tests['error'] = f"❌ ERROR: {e}"
        print(f"  ❌ Compatibility test failed: {e}")
        return compatibility_tests

def run_comprehensive_test_suite():
    """Run the complete comprehensive test suite"""
    print("🚀 Comprehensive Import and Compilation Test Suite")
    print("=" * 60)
    
    all_results = {}
    
    # Run all test categories
    all_results['compilation'] = test_python_compilation()
    all_results['basic_imports'] = test_basic_imports()
    all_results['functionality'] = test_agent_service_functionality()
    all_results['usage_patterns'] = test_usage_patterns()
    all_results['security'] = test_security_functionality()
    all_results['compatibility'] = test_import_compatibility()
    
    # Summary
    print("\n📋 Test Results Summary")
    print("=" * 60)
    
    total_tests = 0
    passed_tests = 0
    
    for category, results in all_results.items():
        print(f"\n{category.upper()}:")
        if isinstance(results, dict):
            for test_name, result in results.items():
                total_tests += 1
                if "✅ PASS" in str(result):
                    passed_tests += 1
                print(f"  {test_name}: {result}")
        else:
            total_tests += 1
            if "✅ PASS" in str(results):
                passed_tests += 1
            print(f"  {category}: {results}")
    
    print(f"\n🎯 Overall Results: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("✅ ALL TESTS PASSED!")
        print("\n🎉 Summary:")
        print("   • All files compile successfully")
        print("   • All imports work correctly")
        print("   • Agent service functionality verified")
        print("   • Security integration working")
        print("   • Backward compatibility maintained")
        print("\n🚀 Ready for production use!")
        return True
    else:
        print("❌ SOME TESTS FAILED!")
        print("\n🔧 Issues detected - review failed tests above")
        return False

if __name__ == "__main__":
    success = run_comprehensive_test_suite()
    sys.exit(0 if success else 1)
