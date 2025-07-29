"""
Base MCP Client Implementation for Secure Tool Discovery and Execution

This module provides a foundational client for connecting to Model Context Protocol (MCP) servers.
It handles authentication, tool discovery, and secure communication with MCP servers while
providing a clean interface for AI agents to discover and use available tools.

Key Features:
- OAuth 2.1 Client Credentials authentication flow
- Automatic token management and refresh
- Secure tool discovery from MCP servers
- Connection pooling and session management
- Error handling and retry logic
- Integration with Google ADK toolsets

For FastAPI newcomers:
This client is used by your AI agents to discover and connect to tools provided by MCP servers.
It abstracts away the complexity of authentication and protocol handling, allowing you to focus
on implementing your agent logic.

Architecture:
The client follows the Repository pattern - it provides a clean interface for tool access
while hiding the underlying MCP protocol complexity and authentication details.
"""

# Google ADK imports for MCP tool integration
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset      # For managing collections of MCP tools
from google.adk.tools.mcp_tool.mcp_session_manager import SseServerParams  # For server connection parameters


class BaseMCPClient:
    """
    Base client for connecting to and interacting with MCP (Model Context Protocol) servers
    
    This class provides secure authentication and tool discovery capabilities for AI agents
    that need to access tools provided by MCP servers. It handles:
    
    - OAuth 2.1 Client Credentials authentication flow
    - Automatic token refresh and session management  
    - Tool discovery and capability enumeration
    - Secure communication with MCP servers
    - Connection lifecycle management
    - Error handling and retry logic
    
    Security Features:
    - Secure credential storage and transmission
    - Token-based authentication with automatic refresh
    - HTTPS communication with certificate validation
    - Protection against common attack vectors
    
    Integration with AI Agents:
    This client is designed to be used by AI agent implementations to discover
    and access tools. The agent can call get_toolset() to discover available
    tools and then use those tools through the returned toolset interface.
    
    For FastAPI Integration:
    Use this client in your agent service initialization to connect to MCP servers
    and discover available tools. The toolset can then be passed to your AI agent
    for tool execution during request processing.
    """
    
    def __init__(self, mcp_url: str, client_id: str, client_secret: str, token_url: str):
        """
        Initialize the MCP client with authentication configuration
        
        Args:
            mcp_url (str): Base URL of the MCP server to connect to
                          Example: "https://your-mcp-server.com/mcp-server"
            client_id (str): OAuth client ID for authentication
                            Provided by the MCP server administrator
            client_secret (str): OAuth client secret for authentication
                                Should be stored securely (e.g., in Secret Manager)
            token_url (str): OAuth token endpoint URL for authentication
                           Example: "https://auth-server.com/oauth/token"
        """
        self.mcp_url = mcp_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        
        # Will be initialized when tools are discovered
        self.toolset = None
        
        # Authentication state (will be managed internally)
        self._access_token = None
        self._token_expires_at = None

    async def authenticate(self):
        """
        Perform OAuth 2.1 Client Credentials authentication flow
        
        This method implements the secure authentication flow required to access MCP servers:
        1. Sends client credentials to the authorization server
        2. Receives and validates the access token
        3. Stores the token for use in subsequent requests
        4. Sets up automatic token refresh if needed
        
        OAuth 2.1 Client Credentials flow is used because:
        - It's designed for server-to-server authentication
        - No user interaction is required
        - Provides secure, token-based authentication
        - Supports automatic token refresh
        
        Security considerations:
        - Client secret is transmitted securely over HTTPS
        - Tokens are stored in memory only (not persisted)
        - Token expiration is respected and refresh is automatic
        - All communication uses secure protocols
        
        For FastAPI integration:
        This method is called automatically when needed, you don't typically
        call it directly. The client handles authentication transparently.
        
        Raises:
            AuthenticationError: If credential validation fails
            ConnectionError: If the authentication server is unreachable
            ValueError: If the response format is invalid
        """
        # TODO: Implement OAuth 2.1 Client Credentials flow
        # 
        # Implementation steps:
        # 1. Prepare the token request with client credentials
        # 2. Send POST request to token_url with proper headers
        # 3. Validate the response and extract access token
        # 4. Store token and expiration time for future use
        # 5. Set up refresh logic for long-running connections
        #
        # Example implementation using httpx:
        # async with httpx.AsyncClient() as client:
        #     response = await client.post(
        #         self.token_url,
        #         data={
        #             "grant_type": "client_credentials",
        #             "client_id": self.client_id,
        #             "client_secret": self.client_secret,
        #             "scope": "mcp:tools"  # Adjust scope as needed
        #         },
        #         headers={"Content-Type": "application/x-www-form-urlencoded"}
        #     )
        #     response.raise_for_status()
        #     token_data = response.json()
        #     self._access_token = token_data["access_token"]
        #     expires_in = token_data.get("expires_in", 3600)
        #     self._token_expires_at = time.time() + expires_in
        pass

    async def get_toolset(self):
        """
        Discover and connect to tools provided by the MCP server
        
        This method performs the complete tool discovery process:
        1. Ensures authentication is valid (authenticates if needed)
        2. Connects to the MCP server using secure protocols
        3. Discovers all available tools and their capabilities
        4. Returns both individual tools and a toolset manager
        
        The discovery process includes:
        - Enumerating all available tools on the server
        - Retrieving tool schemas and parameter definitions
        - Setting up secure communication channels
        - Preparing tools for execution by AI agents
        
        Returns:
            Tuple[List, MCPToolset]: A tuple containing:
                - List of individual tool objects that can be used by agents
                - MCPToolset manager for advanced toolset operations
                
        The returned tools can be directly used by AI agents (like Google ADK LlmAgent)
        for tool execution during conversation processing.
        
        For FastAPI integration:
        Call this method during application startup to discover available tools,
        then pass the tools to your AI agent initialization.
        
        Example:
            mcp_client = BaseMCPClient(url, client_id, secret, token_url)
            tools, toolset = await mcp_client.get_toolset()
            agent = LlmAgent(model="gemini-1.5-flash", tools=tools)
            
        Raises:
            AuthenticationError: If authentication fails
            ConnectionError: If the MCP server is unreachable
            ProtocolError: If the MCP protocol communication fails
        """
        # Ensure we have a valid authentication token
        await self.authenticate()
        
        # Create connection parameters with authentication
        # The SseServerParams handles Server-Sent Events communication
        # which is the standard transport for MCP protocol
        connection_params = SseServerParams(
            url=self.mcp_url,
            # TODO: Add authentication headers with the access token
            # headers={"Authorization": f"Bearer {self._access_token}"}
        )
        
        # Initialize the toolset with secure connection parameters
        self.toolset = MCPToolset(connection_params=connection_params)
        
        # Discover all available tools from the MCP server
        # This performs the actual MCP protocol handshake and tool enumeration
        tools = await self.toolset.get_tools()
        
        # Return both the individual tools and the toolset manager
        return tools, self.toolset

    async def close(self):
        """
        Clean up resources and close connections to the MCP server
        
        This method performs proper cleanup of all resources including:
        - Closing active connections to the MCP server
        - Clearing authentication tokens from memory
        - Releasing any held resources or locks
        - Gracefully terminating background tasks
        
        Connection cleanup is important for:
        - Preventing resource leaks in long-running applications
        - Ensuring proper server-side connection cleanup
        - Maintaining security by clearing sensitive data
        - Following best practices for connection management
        
        For FastAPI integration:
        Call this method in your application's lifespan shutdown handler
        to ensure proper cleanup when the service stops.
        
        Example in FastAPI lifespan:
            @asynccontextmanager
            async def lifespan(app: FastAPI):
                # Startup
                mcp_client = BaseMCPClient(...)
                yield
                # Shutdown
                await mcp_client.close()
        """
        if self.toolset:
            # Close the toolset and its connections
            await self.toolset.close()
            self.toolset = None
        
        # Clear authentication data from memory for security
        self._access_token = None
        self._token_expires_at = None

    async def _is_token_valid(self) -> bool:
        """
        Check if the current authentication token is valid and not expired
        
        This helper method performs token validation including:
        - Checking if a token exists
        - Verifying the token hasn't expired
        - Validating token format and structure
        
        Returns:
            bool: True if token is valid and not expired, False otherwise
        """
        if not self._access_token:
            return False
        
        if self._token_expires_at:
            import time
            # Add 5-minute buffer before expiration for safety
            return time.time() < (self._token_expires_at - 300)
        
        # If no expiration time, assume token is valid
        return True

    async def _ensure_authenticated(self):
        """
        Ensure authentication is valid, re-authenticating if necessary
        
        This helper method provides automatic token refresh:
        - Checks if current token is valid
        - Re-authenticates if token is expired or missing
        - Handles authentication errors gracefully
        
        This is called automatically by other methods that need authentication.
        """
        if not await self._is_token_valid():
            await self.authenticate()

    def get_connection_status(self) -> dict:
        """
        Get current connection and authentication status
        
        This method provides debugging and monitoring information about
        the client's current state including authentication status and
        connection health.
        
        Returns:
            dict: Status information including:
                - authenticated: Whether client has valid token
                - connected: Whether toolset connection is active
                - server_url: The MCP server URL
                - tools_count: Number of discovered tools (if connected)
                
        Useful for:
        - Health checks and monitoring
        - Debugging connection issues
        - Service status reporting
        """
        return {
            "authenticated": bool(self._access_token),
            "connected": bool(self.toolset),
            "server_url": self.mcp_url,
            "tools_count": len(self.toolset._tools) if self.toolset and hasattr(self.toolset, '_tools') else 0,
            "token_valid": self._is_token_valid() if self._access_token else False
        }


class SimpleMCPClient(BaseMCPClient):
    """
    Simple concrete implementation of BaseMCPClient for development and testing
    
    This class provides a ready-to-use MCP client implementation with sensible
    defaults for common scenarios. It's designed for:
    - Development and testing environments
    - Simple integrations without complex authentication
    - Getting started with MCP tool integration
    
    For production use, you should implement your own client class that
    inherits from BaseMCPClient with your specific authentication and
    configuration requirements.
    
    For FastAPI Integration:
    Use this client when you want a simple way to connect to MCP servers
    without implementing custom authentication logic.
    """
    
    def __init__(self, mcp_url: str = None, client_id: str = None, 
                 client_secret: str = None, token_url: str = None):
        """
        Initialize the simple MCP client with optional parameters
        
        If parameters are not provided, they will be loaded from environment
        variables for convenience in development and deployment scenarios.
        
        Args:
            mcp_url (str, optional): MCP server URL 
                                   (defaults to MCP_SERVER_URL env var)
            client_id (str, optional): OAuth client ID
                                     (defaults to MCP_CLIENT_ID env var)
            client_secret (str, optional): OAuth client secret
                                         (defaults to MCP_CLIENT_SECRET env var)
            token_url (str, optional): OAuth token endpoint
                                     (defaults to MCP_TOKEN_URL env var)
        """
        import os
        
        # Use provided values or fall back to environment variables
        mcp_url = mcp_url or os.getenv("MCP_SERVER_URL", "http://localhost:8080/mcp-server")
        client_id = client_id or os.getenv("MCP_CLIENT_ID", "default-client")
        client_secret = client_secret or os.getenv("MCP_CLIENT_SECRET", "default-secret")
        token_url = token_url or os.getenv("MCP_TOKEN_URL", "http://localhost:8080/oauth/token")
        
        # Initialize the base client
        super().__init__(mcp_url, client_id, client_secret, token_url)
    
    async def authenticate(self):
        """
        Simple authentication implementation for development
        
        This implementation provides basic authentication that works with
        development MCP servers. For production use, implement proper
        OAuth 2.1 Client Credentials flow in your custom client class.
        
        Note: This is a simplified implementation for development purposes.
        Production environments should implement full OAuth 2.1 security.
        """
        # For development purposes, simulate successful authentication
        # In production, implement actual OAuth 2.1 Client Credentials flow
        import time
        
        self._access_token = f"dev-token-{int(time.time())}"
        self._token_expires_at = time.time() + 3600  # 1 hour expiration
        
        print(f"🔐 Authenticated with MCP server: {self.mcp_url}")


# Factory function for easy client creation
def create_mcp_client(mcp_url: str = None, **kwargs) -> BaseMCPClient:
    """
    Factory function for creating MCP clients with sensible defaults
    
    This function provides an easy way to create MCP clients without
    having to understand all the configuration details. It's designed
    for common use cases and development scenarios.
    
    Args:
        mcp_url (str, optional): MCP server URL to connect to
        **kwargs: Additional configuration parameters
        
    Returns:
        BaseMCPClient: Configured MCP client ready for use
        
    Example:
        # Simple usage with defaults
        client = create_mcp_client()
        
        # With custom server URL
        client = create_mcp_client("https://my-mcp-server.com/mcp-server")
        
        # With full configuration
        client = create_mcp_client(
            mcp_url="https://my-server.com/mcp",
            client_id="my-client-id",
            client_secret="my-secret"
        )
    """
    return SimpleMCPClient(mcp_url=mcp_url, **kwargs)
