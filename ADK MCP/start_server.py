#!/usr/bin/env python3
"""Development server startup script"""

import uvicorn
from mcp_server_service import app

if __name__ == "__main__":
    print("🚀 Starting MCP Server...")
    print("📡 Server will be available at: http://localhost:8000")
    print("📋 MCP endpoint: http://localhost:8000/mcp-server")
    print("🔧 Invoke endpoint: http://localhost:8000/invoke")
    print("📖 Docs: http://localhost:8000/docs")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        reload=True,
        log_level="info"
    )
