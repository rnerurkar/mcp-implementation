#!/usr/bin/env python3
"""Test script to verify MCP server imports and functionality"""

try:
    print("Testing MCP Server imports...")
    
    # Test base imports
    import os
    import json
    from typing import Dict, Any, List
    print("✅ Basic imports successful")
    
    # Test FastAPI imports
    from fastapi import FastAPI, Request, HTTPException
    print("✅ FastAPI imports successful")
    
    # Test FastMCP import
    from fastmcp import FastMCP
    print("✅ FastMCP import successful")
    
    # Test base server import
    from base_mcp_server import BaseMCPServer
    print("✅ Base MCP Server import successful")
    
    # Test security controls import
    from mcp_security_controls import InputSanitizer
    print("✅ Security controls import successful")
    
    # Test main server import
    from mcp_server_service import MCPServer
    print("✅ MCP Server import successful")
    
    # Test server instantiation
    config = {
        "security_level": "standard",
        "opa_url": "http://localhost:8181"
    }
    server = MCPServer(config)
    print("✅ MCP Server instantiation successful")
    
    # Test app creation
    app = server.get_fastapi_app()
    print("✅ FastAPI app creation successful")
    
    print("\n🎉 All tests passed! MCP Server is ready for deployment.")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
