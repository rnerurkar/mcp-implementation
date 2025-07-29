#!/usr/bin/env python3
"""
Test script for MCP Server deployment.
Tests health endpoints and basic functionality.
"""

import os
import sys
import asyncio
import httpx
import json
from typing import Dict, Any

# Configuration
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000")

async def test_health_endpoint():
    """Test the health check endpoint."""
    print("🏥 Testing health endpoint...")
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{MCP_SERVER_URL}/health", timeout=10.0)
            response.raise_for_status()
            
            health_data = response.json()
            print(f"✅ Health check passed: {health_data['status']}")
            print(f"   - Service: {health_data.get('service', 'unknown')}")
            print(f"   - Version: {health_data.get('version', 'unknown')}")
            print(f"   - Tools: {health_data.get('tools_registered', 0)}")
            print(f"   - Security: {health_data.get('security_enabled', False)}")
            return True
            
        except httpx.RequestError as e:
            print(f"❌ Health check failed - Request error: {e}")
            return False
        except httpx.HTTPStatusError as e:
            print(f"❌ Health check failed - HTTP {e.response.status_code}: {e.response.text}")
            return False
        except Exception as e:
            print(f"❌ Health check failed - Unexpected error: {e}")
            return False

async def test_mcp_health_endpoint():
    """Test the MCP-specific health check endpoint."""
    print("🔧 Testing MCP health endpoint...")
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{MCP_SERVER_URL}/mcp-server/health", timeout=10.0)
            response.raise_for_status()
            
            health_data = response.json()
            print(f"✅ MCP health check passed: {health_data['status']}")
            return True
            
        except Exception as e:
            print(f"❌ MCP health check failed: {e}")
            return False

async def test_root_endpoint():
    """Test the root endpoint for service information."""
    print("📋 Testing root endpoint...")
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{MCP_SERVER_URL}/", timeout=10.0)
            response.raise_for_status()
            
            root_data = response.json()
            print(f"✅ Root endpoint accessible")
            print(f"   - Service: {root_data.get('service', 'unknown')}")
            print(f"   - Endpoints: {list(root_data.get('endpoints', {}).keys())}")
            return True
            
        except Exception as e:
            print(f"❌ Root endpoint test failed: {e}")
            return False

async def test_tool_invocation():
    """Test tool invocation endpoint with a simple request."""
    print("🛠️ Testing tool invocation...")
    
    # Sample payload for testing
    test_payload = {
        "tool": "hello",
        "parameters": {"name": "TestUser"},
        "user_id": "test_user",
        "session_id": "test_session"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{MCP_SERVER_URL}/invoke",
                json=test_payload,
                timeout=30.0,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Tool invocation successful")
                print(f"   - Response: {result}")
                return True
            else:
                print(f"⚠️ Tool invocation returned HTTP {response.status_code}")
                print(f"   - Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Tool invocation test failed: {e}")
            return False

async def test_api_documentation():
    """Test if API documentation is accessible."""
    print("📚 Testing API documentation...")
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{MCP_SERVER_URL}/docs", timeout=10.0)
            
            if response.status_code == 200:
                print("✅ API documentation accessible at /docs")
                return True
            else:
                print(f"⚠️ API documentation returned HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ API documentation test failed: {e}")
            return False

async def main():
    """Run all tests."""
    print("🧪 MCP Server Test Suite")
    print("=" * 50)
    print(f"Testing MCP Server at: {MCP_SERVER_URL}")
    print()
    
    tests = [
        ("Health Check", test_health_endpoint),
        ("MCP Health Check", test_mcp_health_endpoint),
        ("Root Endpoint", test_root_endpoint),
        ("Tool Invocation", test_tool_invocation),
        ("API Documentation", test_api_documentation),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"Running: {test_name}")
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
        print()
    
    # Summary
    print("📊 Test Results Summary")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
        if result:
            passed += 1
    
    print()
    print(f"Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! MCP Server is ready.")
        sys.exit(0)
    else:
        print("⚠️ Some tests failed. Please check the MCP Server configuration.")
        sys.exit(1)

if __name__ == "__main__":
    print("Starting MCP Server tests...")
    asyncio.run(main())
