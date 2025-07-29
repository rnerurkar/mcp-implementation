import os
from typing import Dict, Any, List
from fastapi import FastAPI, Request, HTTPException
from base_mcp_server import BaseMCPServer

from fastmcp import FastMCP

class MCPServer(BaseMCPServer):
    """
    Concrete MCP Server that exposes tools using FastMCP and FastAPI.
    """
    def __init__(self, config):
        super().__init__(config)
        self.mcp = FastMCP("GreetingServer")
        self.register_tools()

    def register_tools(self):
        @self.mcp.tool()
        def hello(name: str) -> str:
            """
            A simple tool that returns a greeting message.
            """
            return f"Hello, {name}!"

    def _load_tool_schema(self, tool_name: str) -> Dict[str, Any]:
        # Example: Return a simple schema for the "hello" tool
        if tool_name == "hello":
            return {
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "required": ["name"]
            }
        return {}

    def _load_security_rules(self) -> List[Dict[str, Any]]:
        # Example: Add a max length rule for all string inputs
        return [
            {"type": "string", "max_length": 100}
        ]

    def get_expected_audience(self) -> str:
        # Return the expected audience for Azure AD token validation
        return self.config["azure_audience"]

    def validate_authorization(self, request_payload: dict):
        # Example: Check for required scope in token claims
        scopes = request_payload.get("scp", "").split()
        required_scopes = set(self.config.get("azure_scopes", []))
        if not required_scopes.issubset(set(scopes)):
            raise PermissionError("Missing required scopes for tool invocation.")

    def fetch_data(self, validated_params: dict, credentials: dict):
        # For the hello tool, just return the parameters as "raw data"
        # If parameters are not present, return an empty dict
        return validated_params

    def build_context(self, raw_data) -> dict:
        # For the hello tool, context is just the input parameters
        return {"tool": "hello", "input": raw_data}

    def get_fastapi_app(self):
        mcp_app = self.mcp.http_app(path='/mcp', transport="sse")
        app = FastAPI(
            title="MCP Server",
            description="Model Context Protocol Server with secure tool execution",
            version="1.0.0",
            lifespan=mcp_app.lifespan
        )
        app.mount("/mcp-server", mcp_app)

        @app.get("/health")
        async def health_check():
            """Health check endpoint for Cloud Run and monitoring."""
            try:
                # Basic health check - verify server is responsive
                tools_count = len(self.mcp._tools) if hasattr(self.mcp, '_tools') else 0
                return {
                    "status": "healthy",
                    "service": "mcp-server",
                    "version": "1.0.0",
                    "tools_registered": tools_count,
                    "security_enabled": bool(self.config.get("azure_audience")),
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat()
                }
            except Exception as e:
                raise HTTPException(status_code=503, detail=f"Health check failed: {str(e)}")

        @app.get("/mcp-server/health")
        async def mcp_health_check():
            """Health check endpoint specifically for MCP server mount point."""
            return await health_check()

        @app.post("/invoke")
        async def invoke_tool(request: Request):
            try:
                payload = await request.json()
                response = self.handle_request(payload)
                if response["status"] == "error":
                    raise HTTPException(status_code=400, detail=response["message"])
                return response
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/")
        async def root():
            """Root endpoint with service information."""
            return {
                "service": "MCP Server",
                "version": "1.0.0",
                "endpoints": {
                    "health": "/health",
                    "mcp_server": "/mcp-server",
                    "mcp_health": "/mcp-server/health",
                    "invoke_tool": "/invoke",
                    "docs": "/docs"
                },
                "description": "Model Context Protocol Server with secure tool execution"
            }

        return app

def create_app():
    config = {
        "azure_audience": os.getenv("AZURE_AUDIENCE"),
        "azure_scopes": os.getenv("AZURE_SCOPES", "").split() if os.getenv("AZURE_SCOPES") else [],
        "azure_issuer": os.getenv("AZURE_ISSUER"),
        "gcp_project": os.getenv("GCP_PROJECT"),
        "opa_url": os.getenv("OPA_URL", "http://localhost:8181"),
        "kms_key_path": os.getenv("KMS_KEY_PATH"),
        "security_level": os.getenv("SECURITY_LEVEL", "standard"),
    }
    server = MCPServer(config)
    return server.get_fastapi_app()

app = create_app()