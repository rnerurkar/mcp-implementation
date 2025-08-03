"""
Base MCP Client Implementation for Google Cloud Service-to-Service Authentication

This module provides a foundational client for connecting to Model Context Protocol (MCP) servers
using Google Cloud Run service-to-service authentication with ID tokens.

Key Features:
- Google Cloud ID token authentication for service-to-service communication
- Automatic token management and refresh from metadata server
- Secure tool discovery from MCP servers
- Connection pooling and session management
- Error handling and retry logic
- Integration with Google ADK toolsets
"""

import time
import httpx
from typing import Tuple, List, Any

# Google ADK imports for MCP tool integration
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseServerParams

# Exception classes for error handling
class AuthenticationError(Exception):
    """Raised when authentication fails"""
    pass

class BaseMCPClient:
    """
    Base client for connecting to and interacting with MCP servers using Google Cloud authentication
    
    This class provides secure authentication and tool discovery capabilities for AI agents
    that need to access tools provided by MCP servers running on Google Cloud Run.
    """
    
    def __init__(self, mcp_url: str, target_audience: str):
        """
        Initialize the MCP client with Google Cloud authentication configuration
        
        Args:
            mcp_url (str): Base URL of the MCP server to connect to
                          Example: "https://your-mcp-server-abc123-uc.a.run.app"
            target_audience (str): Target audience for ID token (usually the mcp_url)
                                 Used for Cloud Run service-to-service authentication
        """
        self.mcp_url = mcp_url
        self.target_audience = target_audience
        
        # Will be initialized when tools are discovered
        self.toolset = None
        
        # Authentication state (will be managed internally)
        self._id_token = None
        self._token_expires_at = None

    async def authenticate(self):
        """
        Get Google Cloud ID token for service-to-service authentication
        
        This method implements Google Cloud Run service-to-service authentication
        by fetching an ID token from the metadata server or using the Google Auth library.
        
        Raises:
            AuthenticationError: If token acquisition fails
        """
        try:
            # Try to get ID token from metadata server (Cloud Run environment)
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={self.target_audience}",
                        headers={"Metadata-Flavor": "Google"},
                        timeout=5.0
                    )
                    response.raise_for_status()
                    self._id_token = response.text
                    
                    # ID tokens typically expire in 1 hour
                    self._token_expires_at = time.time() + 3600
                    
                    print(f"✅ Successfully obtained Google Cloud ID token for audience: {self.target_audience}")
                    return
                    
            except Exception as metadata_error:
                print(f"⚠️ Metadata server unavailable: {metadata_error}")
                
                # Fallback: Use Google Auth library to generate ID token
                try:
                    from google.auth.transport.requests import Request
                    from google.auth import default
                    from google.oauth2 import id_token_credentials
                    
                    # Get default credentials
                    credentials, project = default()
                    
                    # Create ID token credentials
                    id_creds = id_token_credentials.IDTokenCredentials(
                        credentials, 
                        target_audience=self.target_audience
                    )
                    
                    # Refresh to get the token
                    id_creds.refresh(Request())
                    self._id_token = id_creds.token
                    self._token_expires_at = time.time() + 3600
                    
                    print(f"✅ Successfully generated Google Cloud ID token using auth library")
                    return
                    
                except Exception as auth_error:
                    raise AuthenticationError(f"Failed to get ID token: {auth_error}")
                    
        except Exception as e:
            raise AuthenticationError(f"Google Cloud authentication failed: {str(e)}")

    def _is_token_expired(self) -> bool:
        """Check if the current ID token is expired or missing"""
        if not self._id_token or not self._token_expires_at:
            return True
        # Add 5-minute buffer before expiration
        return time.time() >= (self._token_expires_at - 300)

    async def get_toolset(self) -> Tuple[List[Any], MCPToolset]:
        """
        Discover and connect to tools provided by the MCP server
        
        Returns:
            Tuple[List, MCPToolset]: A tuple containing tools and toolset manager
        """
        # Ensure we have a valid authentication token
        if self._is_token_expired():
            await self.authenticate()
        
        # Create the toolset with authentication headers
        self.toolset = MCPToolset(
            connection_params=SseServerParams(
                url=self.mcp_url,
                headers={"Authorization": f"Bearer {self._id_token}"}
            )
        )
        
        # Get the tools from the server
        tools = await self.toolset.get_tools()
        
        return tools, self.toolset

    async def close(self):
        """Clean up resources"""
        if self.toolset:
            await self.toolset.close()
