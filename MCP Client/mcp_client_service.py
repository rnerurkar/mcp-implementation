import os
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import httpx
from jose import jwt
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseServerParams
from dotenv import load_dotenv
# For ID token generation in Cloud Run service-to-service calls
import google.auth
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
import requests
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

    async def generate_id_token_for_service(self, target_service_url: str) -> str:
        """
        Generate Google Cloud ID token for service-to-service authentication
        
        This method generates an ID token that can be used for authenticating
        with another Cloud Run service. The ID token contains the service account
        identity and is specifically targeted for the destination service.
        
        WHEN TO USE THIS APPROACH:
        - Cloud Run service-to-service calls
        - When you need cryptographic proof of caller identity
        - For zero-trust security models
        - When the receiving service needs to verify caller identity
        
        SECURITY BENEFITS:
        - Cryptographically signed by Google
        - Contains verified service account identity
        - Audience-specific (can't be reused for other services)
        - Short-lived tokens (typically 1 hour)
        - No service account keys required in Cloud Run
        
        Args:
            target_service_url (str): The URL of the target Cloud Run service
                                    This becomes the 'audience' claim in the token
        
        Returns:
            str: ID token that can be used in Authorization header
            
        Raises:
            Exception: If token generation fails
            
        Example usage:
            # Generate ID token for calling MCP server
            id_token = await client.generate_id_token_for_service(
                "https://mcp-server-xyz-uc.a.run.app"
            )
            
            # Use token in API call
            headers = {"Authorization": f"Bearer {id_token}"}
            response = await httpx.post(mcp_server_url, headers=headers, json=data)
        """
        try:
            # Get default credentials (works automatically in Cloud Run)
            # No service account keys needed - uses Workload Identity
            credentials, project_id = google.auth.default()
            
            # Create a request object for the Google Auth library
            auth_request = GoogleRequest()
            
            # Generate ID token with the target service as audience
            # This creates a JWT token signed by Google with:
            # - iss: https://accounts.google.com
            # - aud: target_service_url
            # - sub: service account ID
            # - email: service account email
            # - exp: expiration time (typically 1 hour)
            token = id_token.fetch_id_token(auth_request, target_service_url)
            
            print(f"✅ Generated ID token for target: {target_service_url}")
            return token
            
        except Exception as e:
            print(f"❌ Failed to generate ID token: {str(e)}")
            raise HTTPException(
                status_code=500, 
                detail=f"Failed to generate service authentication token: {str(e)}"
            )

    async def call_mcp_server_with_id_token(self, endpoint: str, data: dict = None) -> dict:
        """
        Make authenticated calls to MCP server using ID tokens
        
        This method demonstrates the complete flow for service-to-service
        authentication using ID tokens:
        1. Generate ID token targeting the MCP server
        2. Include token in Authorization header
        3. Make the API call
        4. Handle authentication errors
        
        Args:
            endpoint (str): MCP server endpoint to call
            data (dict): Request payload
            
        Returns:
            dict: Response from MCP server
            
        Example:
            response = await client.call_mcp_server_with_id_token(
                "/tools/execute",
                {"tool": "hello", "params": {"name": "world"}}
            )
        """
        try:
            # Generate ID token for the MCP server
            id_token_str = await self.generate_id_token_for_service(self.mcp_url)
            
            # Prepare headers with ID token
            headers = {
                "Authorization": f"Bearer {id_token_str}",
                "Content-Type": "application/json"
            }
            
            # Make authenticated request to MCP server
            async with httpx.AsyncClient() as client:
                if data:
                    response = await client.post(
                        f"{self.mcp_url}{endpoint}",
                        headers=headers,
                        json=data,
                        timeout=30.0
                    )
                else:
                    response = await client.get(
                        f"{self.mcp_url}{endpoint}",
                        headers=headers,
                        timeout=30.0
                    )
                
                # Handle authentication errors
                if response.status_code == 401:
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication failed - ID token invalid or expired"
                    )
                elif response.status_code == 403:
                    raise HTTPException(
                        status_code=403,
                        detail="Authorization failed - insufficient permissions"
                    )
                
                response.raise_for_status()
                return response.json()
                
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail="MCP server request timeout"
            )
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=502,
                detail=f"MCP server communication error: {str(e)}"
            )

@app.post("/get_tools")
async def get_tools(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header.split(" ", 1)[1]
    mcp_client = MCPClient()
    return await mcp_client.get_tools(token)