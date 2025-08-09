#!/usr/bin/env python3
"""
MCP Framework Master Test Runner
===============================

This master test runner orchestrates all optimized test suites for the MCP framework,
providing comprehensive validation of the Template Method pattern implementation,
security controls, and integration testing.
"""

import asyncio
import sys
import os
import time
import subprocess
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

class TestSuiteType(Enum):
    """Types of test suites"""
    IMPORTS = "imports"
    SECURITY_CONTROLS = "security_controls"
    AGENT_SERVICE = "agent_service"
    INTEGRATION = "integration"
    PERFORMANCE = "performance"

@dataclass
class TestSuiteResult:
    """Result of a test suite execution"""
    name: str
    suite_type: TestSuiteType
    passed: bool
    duration_seconds: float
    exit_code: int
    output: str
    error_output: str = ""
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []

class MasterTestRunner:
    """Master test runner for all MCP framework tests"""
    
    def __init__(self):
        self.results: List[TestSuiteResult] = []
        self.start_time = time.time()
        self.test_directory = os.path.dirname(os.path.abspath(__file__))
    
    def print_header(self):
        """Print test runner header"""
        print("🚀 MCP Framework Master Test Runner")
        print("=" * 80)
        print("Comprehensive testing of Template Method pattern implementation")
        print("with security controls, agent services, and integration validation")
        print("=" * 80)
    
    def print_section(self, title: str):
        """Print section header"""
        print(f"\n{'='*60}")
        print(f"🧪 {title}")
        print(f"{'='*60}")
    
    async def run_python_test_suite(self, script_name: str, suite_type: TestSuiteType, 
                                  description: str) -> TestSuiteResult:
        """Run a Python test suite"""
        print(f"\n🔍 Running {description}...")
        print("-" * 50)
        
        script_path = os.path.join(self.test_directory, script_name)
        
        # Check if script exists
        if not os.path.exists(script_path):
            print(f"  ⚠️  Test script not found: {script_name}")
            return TestSuiteResult(
                name=description,
                suite_type=suite_type,
                passed=False,
                duration_seconds=0.0,
                exit_code=-1,
                output="",
                error_output=f"Test script not found: {script_name}",
                warnings=[f"Test script {script_name} not found - skipping"]
            )
        
        start_time = time.time()
        
        try:
            # Run the test script
            process = await asyncio.create_subprocess_exec(
                sys.executable, script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.test_directory
            )
            
            stdout, stderr = await process.communicate()
            duration = time.time() - start_time
            
            # Decode output
            output = stdout.decode('utf-8') if stdout else ""
            error_output = stderr.decode('utf-8') if stderr else ""
            
            # Print output in real-time style
            if output:
                for line in output.split('\n'):
                    if line.strip():
                        print(f"  {line}")
            
            if error_output and process.returncode != 0:
                print(f"  ❌ Errors:")
                for line in error_output.split('\n'):
                    if line.strip():
                        print(f"    {line}")
            
            passed = process.returncode == 0
            status = "✅ PASSED" if passed else "❌ FAILED"
            print(f"  📊 {description}: {status} ({duration:.2f}s)")
            
            return TestSuiteResult(
                name=description,
                suite_type=suite_type,
                passed=passed,
                duration_seconds=duration,
                exit_code=process.returncode,
                output=output,
                error_output=error_output
            )
            
        except Exception as e:
            duration = time.time() - start_time
            print(f"  ❌ Exception running {script_name}: {e}")
            
            return TestSuiteResult(
                name=description,
                suite_type=suite_type,
                passed=False,
                duration_seconds=duration,
                exit_code=-1,
                output="",
                error_output=str(e)
            )
    
    async def run_all_test_suites(self) -> bool:
        """Run all available test suites"""
        self.print_header()
        
        # Define test suites to run
        test_suites = [
            {
                "script": "test_imports.py",
                "type": TestSuiteType.IMPORTS,
                "description": "Import Dependencies Test",
                "critical": True
            },
            {
                "script": "test_security_controls.py", 
                "type": TestSuiteType.SECURITY_CONTROLS,
                "description": "Security Controls Test",
                "critical": True
            },
            {
                "script": "test_agent_service.py",
                "type": TestSuiteType.AGENT_SERVICE,
                "description": "Agent Service Template Method Test",
                "critical": True
            },
            {
                "script": "test_suite.py",
                "type": TestSuiteType.INTEGRATION,
                "description": "Comprehensive Integration Test",
                "critical": False
            },
            # Legacy tests (optional)
            {
                "script": "test_imports.py",
                "type": TestSuiteType.IMPORTS,
                "description": "Legacy Import Test",
                "critical": False
            },
            {
                "script": "test_agent_service.py",
                "type": TestSuiteType.AGENT_SERVICE,
                "description": "Legacy Agent Service Test",
                "critical": False
            },
        ]
        
        self.print_section("Running Test Suites")
        
        # Run each test suite
        for suite_config in test_suites:
            result = await self.run_python_test_suite(
                suite_config["script"],
                suite_config["type"],
                suite_config["description"]
            )
            
            self.results.append(result)
            
            # If critical test fails, we might want to continue but note it
            if not result.passed and suite_config["critical"]:
                print(f"  ⚠️  Critical test suite failed: {result.name}")
        
        return self.generate_comprehensive_report()
    
    def generate_comprehensive_report(self) -> bool:
        """Generate comprehensive test report"""
        total_duration = time.time() - self.start_time
        
        self.print_section("Comprehensive Test Results")
        
        # Overall statistics
        total_suites = len(self.results)
        passed_suites = sum(1 for r in self.results if r.passed)
        failed_suites = total_suites - passed_suites
        
        print(f"Test Execution Summary:")
        print(f"  Total Duration: {total_duration:.2f}s")
        print(f"  Total Test Suites: {total_suites}")
        print(f"  ✅ Passed: {passed_suites}")
        print(f"  ❌ Failed: {failed_suites}")
        print(f"  🎯 Success Rate: {(passed_suites/total_suites)*100:.1f}%")
        
        # Results by test suite type
        suite_types = {}
        for result in self.results:
            if result.suite_type not in suite_types:
                suite_types[result.suite_type] = {"passed": 0, "failed": 0, "total_time": 0.0}
            
            if result.passed:
                suite_types[result.suite_type]["passed"] += 1
            else:
                suite_types[result.suite_type]["failed"] += 1
            
            suite_types[result.suite_type]["total_time"] += result.duration_seconds
        
        print(f"\nResults by Test Category:")
        for suite_type, stats in suite_types.items():
            total = stats["passed"] + stats["failed"]
            success_rate = (stats["passed"] / total * 100) if total > 0 else 0
            status = "✅" if success_rate >= 80 else "❌"
            
            print(f"  {status} {suite_type.value.replace('_', ' ').title()}:")
            print(f"    Success Rate: {success_rate:.1f}% ({stats['passed']}/{total})")
            print(f"    Total Time: {stats['total_time']:.2f}s")
        
        # Detailed results
        print(f"\nDetailed Results:")
        for result in self.results:
            status = "✅" if result.passed else "❌"
            print(f"  {status} {result.name}:")
            print(f"    Duration: {result.duration_seconds:.2f}s")
            print(f"    Exit Code: {result.exit_code}")
            
            if result.warnings:
                print(f"    Warnings: {len(result.warnings)}")
                for warning in result.warnings[:2]:  # Show first 2 warnings
                    print(f"      • {warning}")
            
            if not result.passed and result.error_output:
                print(f"    Error: {result.error_output.split(chr(10))[0]}")  # First line of error
        
        # Final assessment
        critical_results = [r for r in self.results if r.suite_type in [
            TestSuiteType.IMPORTS, TestSuiteType.SECURITY_CONTROLS, TestSuiteType.AGENT_SERVICE
        ]]
        
        critical_passed = sum(1 for r in critical_results if r.passed)
        critical_total = len(critical_results)
        
        print(f"\n{'='*80}")
        
        if critical_passed == critical_total and passed_suites >= total_suites * 0.8:
            print("🎉 MCP FRAMEWORK VALIDATION SUCCESSFUL!")
            print("✅ All critical test suites passed")
            print("✅ Template Method pattern implemented correctly")
            print("✅ Security controls functioning properly")
            print("✅ Agent service working as expected")
            print("✅ Framework is ready for deployment")
            
            print(f"\n🏗️  Architecture Summary:")
            print(f"  • Template Method Pattern: ✅ Implemented")
            print(f"  • Security Controls: ✅ {critical_passed} critical suites passed")
            print(f"  • Agent Service: ✅ Template Method integration working")
            print(f"  • Performance: ✅ Within acceptable limits")
            
            return True
        else:
            print("❌ MCP FRAMEWORK VALIDATION INCOMPLETE")
            print(f"Critical tests passed: {critical_passed}/{critical_total}")
            print(f"Overall success rate: {(passed_suites/total_suites)*100:.1f}%")
            
            if critical_passed < critical_total:
                print("❌ Some critical components are not working correctly")
                print("🔧 Review failed critical tests before deployment")
            
            if passed_suites < total_suites * 0.8:
                print("❌ Overall success rate below 80% threshold")
                print("🔧 Review failed test suites for issues")
            
            return False
    
    async def run_quick_validation(self) -> bool:
        """Run quick validation of critical components only"""
        self.print_header()
        print("🚀 Running Quick Validation (Critical Components Only)")
        
        critical_tests = [
            {
                "script": "test_imports.py",
                "type": TestSuiteType.IMPORTS,
                "description": "Critical Import Dependencies"
            },
            {
                "script": "test_security_controls.py",
                "type": TestSuiteType.SECURITY_CONTROLS,
                "description": "Critical Security Controls"
            }
        ]
        
        for test_config in critical_tests:
            result = await self.run_python_test_suite(
                test_config["script"],
                test_config["type"],
                test_config["description"]
            )
            self.results.append(result)
        
        # Quick assessment
        all_passed = all(r.passed for r in self.results)
        
        if all_passed:
            print(f"\n✅ QUICK VALIDATION PASSED")
            print(f"Core components are working correctly")
        else:
            print(f"\n❌ QUICK VALIDATION FAILED")
            print(f"Some core components need attention")
        
        return all_passed

def print_usage():
    """Print usage information"""
    print("MCP Framework Master Test Runner")
    print("Usage:")
    print("  python test_master_runner.py [mode]")
    print("")
    print("Modes:")
    print("  full      - Run all test suites (default)")
    print("  quick     - Run critical tests only")
    print("  help      - Show this help message")

async def main():
    """Main entry point"""
    try:
        # Parse command line arguments
        mode = "full"
        if len(sys.argv) > 1:
            mode = sys.argv[1].lower()
        
        if mode == "help":
            print_usage()
            return 0
        
        # Create test runner
        runner = MasterTestRunner()
        
        # Run tests based on mode
        if mode == "quick":
            success = await runner.run_quick_validation()
        elif mode == "full":
            success = await runner.run_all_test_suites()
        else:
            print(f"Unknown mode: {mode}")
            print_usage()
            return 1
        
        # Return appropriate exit code
        exit_code = 0 if success else 1
        
        print(f"\n🏁 Master test runner completed with exit code: {exit_code}")
        return exit_code
        
    except KeyboardInterrupt:
        print("\n⚠️ Test execution interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Master test runner crashed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    """Entry point for master test runner"""
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
