import os
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import httpx
from jose import jwt
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseServerParams
from dotenv import load_dotenv
app = FastAPI()

load_dotenv()
class MCPClient:
    def __init__(self):
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.openid_config = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0/.well-known/openid-configuration"
        self.mcp_url = os.getenv("MCP_SERVER_URL")

    async def get_azure_jwks(self):
        async with httpx.AsyncClient() as client:
            resp = await client.get(self.openid_config)
            jwks_uri = resp.json()["jwks_uri"]
            jwks_resp = await client.get(jwks_uri)
            return jwks_resp.json()

    async def validate_token(self, token: str):
        jwks = await self.get_azure_jwks()
        try:
            claims = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
            )
            return claims
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

    async def get_tools(self, token: str):
        claims = await self.validate_token(token)
         # Here you would authenticate and fetch the toolset from MCP Server
        try:
            toolset = MCPToolset(
                connection_params=SseServerParams(
                    url=self.mcp_url,
                    # Add headers or token as needed
                )
            )
            tools = await toolset.get_tools()
            # You can't directly return the toolset object, so return tool info (names, etc.)
            # If you need to use the toolset object, you may need to serialize/deserialize or use a session/token
            return {"tools": [tool.name for tool in tools]}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
            # Your logic here, e.g., fetch tools based on claims
            return {"tools": ["hello"]}

@app.post("/get_tools")
async def get_tools(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header.split(" ", 1)[1]
    mcp_client = MCPClient()
    return await mcp_client.get_tools(token)