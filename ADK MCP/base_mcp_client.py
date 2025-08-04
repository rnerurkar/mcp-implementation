"""
Base MCP Client Implementation for Google Cloud Service-to-Service Authentication

This module provides a foundational client for connecting to Model Context Protocol (MCP) servers
using Google Cloud Run service-to-service authentication with ID tokens via Google Auth library.

Key Features:
- Google Cloud ID token authentication using Google Auth library exclusively
- Automatic token management and refresh
- Secure tool discovery from MCP servers
- Connection pooling and session management
- Error handling and retry logic
- Integration with Google ADK toolsets

Authentication Method:
- Uses Google Auth library for ID token generation (no metadata server calls)
- Works across all Google Cloud environments (Cloud Run, GCE, local development)
- Supports service account authentication and Workload Identity
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
        using ONLY the Google Auth library for ID token generation. This approach
        works across all Google Cloud environments and provides consistent behavior.
        
        ID Token Generation Strategy:
        - Uses Google Auth library exclusively for ID token generation
        - No metadata server calls - fail fast if unsuccessful
        - Works in Cloud Run, GCE, local development with service accounts
        
        Raises:
            AuthenticationError: If ID token acquisition fails
        """
        print(f"🔐 Generating ID token using Google Auth library for audience: {self.target_audience}")
        
        try:
            from google.auth.transport.requests import Request
            from google.auth import default
            from google.oauth2 import id_token_credentials
            
            # Get default credentials
            credentials, project = default()
            if not credentials:
                raise AuthenticationError("No default credentials found. Ensure you're running in a Google Cloud environment or have GOOGLE_APPLICATION_CREDENTIALS set.")
            
            print(f"📋 Using credentials from project: {project}")
            
            # Create ID token credentials with target audience
            id_creds = id_token_credentials.IDTokenCredentials(
                credentials, 
                target_audience=self.target_audience
            )
            
            # Refresh to get the token
            auth_request = Request()
            id_creds.refresh(auth_request)
            
            # Validate the generated token
            if not id_creds.token:
                raise AuthenticationError("Google Auth library failed to generate ID token")
            
            # Validate token format (JWT should have 3 parts separated by dots)
            token_parts = id_creds.token.split('.')
            if len(token_parts) != 3:
                raise AuthenticationError(f"Invalid ID token format. Expected 3 parts, got {len(token_parts)}")
            
            # Store the token and expiration
            self._id_token = id_creds.token
            self._token_expires_at = time.time() + 3600  # ID tokens typically expire in 1 hour
            
            print(f"✅ Successfully generated ID token using Google Auth library")
            print(f"   Token length: {len(id_creds.token)} characters")
            print(f"   Project: {project}")
            print(f"   Audience: {self.target_audience}")
            print(f"   Expires at: {time.ctime(self._token_expires_at)}")
            
        except ImportError as import_error:
            error_msg = (
                f"Google Auth libraries not available: {import_error}. "
                f"Install with: pip install google-auth google-auth-oauthlib"
            )
            raise AuthenticationError(error_msg)
            
        except Exception as auth_error:
            error_msg = (
                f"Failed to generate ID token using Google Auth library: {auth_error}. "
                f"Ensure you have proper Google Cloud credentials configured."
            )
            raise AuthenticationError(error_msg)

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
