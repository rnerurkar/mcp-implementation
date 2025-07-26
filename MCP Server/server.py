
from fastmcp import FastMCP
from fastapi import FastAPI
from starlette.routing import Mount
# Create your FastMCP server as well as any tools, resources, etc.
mcp = FastMCP("GreetingServer")
@mcp.tool()
def hello(name: str) -> str:
    """
    A simple tool that returns a greeting message.
    Args:
        name: The name to greet.
    Returns:
        A string with the greeting.
    """
    return f"Hello, {name}!"
# Create the ASGI app for FastMCP with SSE transport
mcp_app = mcp.http_app(path='/mcp', transport="sse")
# Create a FastAPI app and mount the MCP server
app = FastAPI(lifespan=mcp_app.lifespan)
app.mount("/mcp-server", mcp_app)