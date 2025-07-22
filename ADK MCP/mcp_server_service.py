from fastmcp import FastMCP
from fastapi import FastAPI

class MCPServer:
    def __init__(self, name: str):
        self.mcp = FastMCP(name)
        self.register_tools()

    def register_tools(self):
        @self.mcp.tool()
        def hello(name: str) -> str:
            """
            A simple tool that returns a greeting message.
            Args:
                name: The name to greet.
            Returns:
                A string with the greeting.
            """
            return f"Hello, {name}!"

    def get_app(self):
        # Create the ASGI app for FastMCP with SSE transport
        mcp_app = self.mcp.http_app(path='/mcp', transport="sse")
        # Create a FastAPI app and mount the MCP server
        app = FastAPI(lifespan=mcp_app.lifespan)
        app.mount("/mcp-server", mcp_app)
        return app

# Instantiate the server and expose the FastAPI app
mcp_server = MCPServer("GreetingServer")
app = mcp_server.get_app()