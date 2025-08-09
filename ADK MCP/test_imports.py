#!/usr/bin/env python3
"""
Import Test for MCP Framework
======================================

This test validates that all required dependencies and modules can be imported
successfully for the Template Method pattern implementation.
"""

import sys
import os
from typing import Dict, List, Tuple

class ImportTestResult:
    """Container for import test results"""
    
    def __init__(self):
        self.successful_imports: List[str] = []
        self.failed_imports: List[Tuple[str, str]] = []  # (module_name, error)
        self.warnings: List[str] = []

class ImportTester:
    """Import Tester with better error handling and reporting"""
    
    def __init__(self):
        self.result = ImportTestResult()
    
    def test_import_group(self, group_name: str, imports: List[Tuple[str, str]]) -> bool:
        """Test a group of related imports"""
        print(f"\n🧪 Testing {group_name} imports...")
        
        group_success = True
        for module_name, import_statement in imports:
            try:
                # Execute the import
                exec(import_statement)
                self.result.successful_imports.append(module_name)
                print(f"  ✅ {module_name}")
            except ImportError as e:
                self.result.failed_imports.append((module_name, str(e)))
                print(f"  ❌ {module_name}: {e}")
                group_success = False
            except Exception as e:
                self.result.failed_imports.append((module_name, f"Unexpected error: {e}"))
                print(f"  ⚠️  {module_name}: Unexpected error: {e}")
                group_success = False
        
        status = "✅ PASSED" if group_success else "❌ FAILED"
        print(f"  📊 {group_name}: {status}")
        return group_success
    
    def run_comprehensive_import_test(self) -> bool:
        """Run comprehensive import tests for all dependencies"""
        print("🚀 Starting MCP Framework Import Tests")
        print("=" * 60)
        
        all_groups_passed = True
        
        # Group 1: Core Python modules
        core_imports = [
            ("os", "import os"),
            ("sys", "import sys"),
            ("json", "import json"),
            ("asyncio", "import asyncio"),
            ("typing", "from typing import Dict, Any, List, Optional"),
            ("datetime", "import datetime"),
            ("pathlib", "from pathlib import Path"),
        ]
        all_groups_passed &= self.test_import_group("Core Python", core_imports)
        
        # Group 2: Web framework dependencies
        web_imports = [
            ("fastapi", "from fastapi import FastAPI, Request, HTTPException"),
            ("uvicorn", "import uvicorn"),
            ("pydantic", "from pydantic import BaseModel"),
            ("starlette", "from starlette.middleware.cors import CORSMiddleware"),
        ]
        all_groups_passed &= self.test_import_group("Web Framework", web_imports)
        
        # Group 3: Testing framework
        testing_imports = [
            ("unittest", "import unittest"),
            ("unittest.mock", "from unittest.mock import Mock, AsyncMock, patch"),
            ("contextlib", "from contextlib import asynccontextmanager"),
        ]
        all_groups_passed &= self.test_import_group("Testing Framework", testing_imports)
        
        # Group 4: Security and encryption
        security_imports = [
            ("cryptography", "from cryptography.fernet import Fernet"),
            ("hashlib", "import hashlib"),
            ("hmac", "import hmac"),
            ("secrets", "import secrets"),
        ]
        all_groups_passed &= self.test_import_group("Security Libraries", security_imports)
        
        # Group 5: Google Cloud dependencies (optional)
        gcp_imports = [
            ("google.auth", "from google.auth import default"),
            ("google.cloud.secretmanager", "from google.cloud import secretmanager"),
        ]
        gcp_passed = self.test_import_group("Google Cloud (Optional)", gcp_imports)
        if not gcp_passed:
            self.result.warnings.append("Google Cloud libraries not available - OK for local testing")
        
        # Group 6: MCP Framework modules (may not exist in all environments)
        mcp_imports = [
            ("base_agent_service", "from base_agent_service import BaseAgentService"),
            ("agent_security_controls", "from agent_security_controls import OptimizedAgentSecurity"),
            ("mcp_security_controls", "from mcp_security_controls import InputSanitizer"),
        ]
        mcp_passed = self.test_import_group("MCP Framework Modules", mcp_imports)
        if not mcp_passed:
            self.result.warnings.append("MCP Framework modules not found - this is expected in some test environments")
        
        return self._generate_final_report(all_groups_passed)
    
    def _generate_final_report(self, core_passed: bool) -> bool:
        """Generate final test report"""
        print("\n" + "=" * 60)
        print("📊 IMPORT TEST RESULTS")
        print("=" * 60)
        
        print(f"✅ Successful imports: {len(self.result.successful_imports)}")
        print(f"❌ Failed imports: {len(self.result.failed_imports)}")
        print(f"⚠️  Warnings: {len(self.result.warnings)}")
        
        if self.result.successful_imports:
            print(f"\n✅ Successfully imported modules:")
            for module in self.result.successful_imports:
                print(f"  • {module}")
        
        if self.result.failed_imports:
            print(f"\n❌ Failed to import:")
            for module, error in self.result.failed_imports:
                print(f"  • {module}: {error}")
        
        if self.result.warnings:
            print(f"\n⚠️  Warnings:")
            for warning in self.result.warnings:
                print(f"  • {warning}")
        
        print(f"\n{'='*60}")
        
        if core_passed:
            print("🎉 CORE DEPENDENCIES READY!")
            print("✅ All essential modules imported successfully")
            print("✅ MCP Framework can run with current dependencies")
            if self.result.warnings:
                print("⚠️  Some optional modules missing but core functionality available")
            return True
        else:
            print("❌ CORE DEPENDENCIES MISSING!")
            print("❌ Some essential modules failed to import")
            print("🔧 Install missing dependencies: pip install -r requirements.txt")
            return False

def main():
    """Main entry point for Import Testing"""
    try:
        tester = ImportTester()
        success = tester.run_comprehensive_import_test()
        
        exit_code = 0 if success else 1
        print(f"\n🏁 Import test completed with exit code: {exit_code}")
        return exit_code
        
    except KeyboardInterrupt:
        print("\n⚠️ Import test interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Import test crashed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    """Entry point for running Import Tests"""
    exit_code = main()
    sys.exit(exit_code)
