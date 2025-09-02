#!/bin/bash

# Set default port from Cloud Run environment
PORT=${PORT:-8080}

# Start the uvicorn server with streaming MCP server
exec uvicorn mcp_server_service:create_app --factory --host 0.0.0.0 --port $PORT
