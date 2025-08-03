# Import necessary libraries for the MCP Server Service
import os  # For environment variable access
from typing import Dict, Any, List  # For type hints and better code documentation
from fastapi import FastAPI, Request, HTTPException  # FastAPI web framework components
from base_mcp_server import BaseMCPServer  # Our secure MCP server foundation

from fastmcp import FastMCP  # FastMCP library for Model Context Protocol implementation

class MCPServer(BaseMCPServer):
    """
    Concrete implementation of an MCP (Model Context Protocol) Server
    
    This class provides tools and capabilities that AI agents can discover and use.
    It combines:
    - FastMCP for the Model Context Protocol implementation
    - BaseMCPServer for comprehensive security controls
    - FastAPI for HTTP endpoints and API documentation
    
    The server exposes tools that agents can call, such as:
    - Simple greeting functions
    - Data processing capabilities
    - External API integrations
    - File operations
    - And any other custom tools you define
    """
    
    def __init__(self, config):
        """
        Initialize the MCP Server with security configuration
        
        Args:
            config: Dictionary containing security and operational configuration
                   Including Google Cloud Run settings, GCP project info, security levels, etc.
        """
        # Initialize the secure base server with all security controls
        super().__init__(config)
        
        # Create FastMCP instance for implementing the Model Context Protocol
        # This handles the communication protocol between agents and tools
        self.mcp = FastMCP("GreetingServer")  # Server identifier for MCP clients
        
        # Register all available tools that agents can discover and use
        self.register_tools()

    def register_tools(self):
        """
        Register all tools that will be available to MCP clients (AI agents)
        
        This method defines the tools that AI agents can discover and execute.
        Each tool is registered with:
        - A descriptive name
        - Parameter definitions (using Pydantic models for validation)
        - The actual function implementation
        
        Tools are the core capability that makes MCP useful - they allow agents
        to perform actions in the real world through your server.
        """
        
        # Register a simple greeting tool that demonstrates basic MCP functionality
        @self.mcp.tool()
        def hello(name: str) -> str:
            """
            A simple greeting tool for demonstration purposes
            
            This tool shows how to:
            - Accept string parameters with automatic validation
            - Return formatted responses to the calling agent
            - Provide a basic example of agent-tool interaction
            
            Args:
                name (str): The name to include in the greeting
                
            Returns:
                str: A personalized greeting message
            """
            return f"Hello, {name}!"

    def _load_tool_schema(self, tool_name: str) -> Dict[str, Any]:
        """
        Define the input schema for MCP tools
        
        This method specifies what parameters each tool expects.
        The schema follows JSON Schema format and is used for:
        - Parameter validation before tool execution
        - Automatic documentation generation
        - Client-side input validation
        
        Args:
            tool_name (str): Name of the tool to get schema for
            
        Returns:
            Dict[str, Any]: JSON Schema defining the tool's expected parameters
        """
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
        """
        Define security validation rules for tool inputs
        
        This method returns a list of security rules that will be applied
        to all tool inputs before execution. Rules can include:
        - Maximum string lengths to prevent buffer overflow attacks
        - Input pattern validation (regex matching)
        - Forbidden character lists
        - Data type restrictions
        - Range validations for numeric inputs
        
        Returns:
            List[Dict[str, Any]]: List of security rules to apply to inputs
        """
        # Example: Add a max length rule for all string inputs
        return [
            {"type": "string", "max_length": 100}
        ]

    def get_expected_audience(self) -> str:
        """
        Get the expected audience for Azure AD token validation
        
        This method returns the audience claim that should be present in
        Azure AD JWT tokens. The audience identifies the intended recipient
        of the token and helps prevent token misuse.
        
        In Azure AD:
        - Audience is typically the Application ID URI of your application
        - It's used to verify that tokens were meant for your service
        - Prevents tokens from other applications being used maliciously
        
        Returns:
            str: The expected audience value from configuration
        """
        # Return the expected audience for Azure AD token validation
        return self.config["azure_audience"]

    def validate_authorization(self, request_payload: dict):
        """
        Validate authorization for incoming requests
        
        This method performs security validation to ensure that:
        - The request comes from an authorized source
        - Authentication tokens are valid and not expired
        - The user has permission to execute the requested tool
        - The request meets all security policy requirements
        
        This is a critical security checkpoint that should be called
        before executing any tool functionality.
        
        Args:
            request_payload (dict): The incoming request data to validate
                Should contain token claims including 'scp' (scopes)
            
        Raises:
            PermissionError: If required scopes are missing from the token
        """
        # Example: Check for required scope in token claims
        # Scopes define what actions the token holder is authorized to perform
        scopes = request_payload.get("scp", "").split()
        required_scopes = set(self.config.get("azure_scopes", []))
        
        # Verify that all required scopes are present in the token
        if not required_scopes.issubset(set(scopes)):
            raise PermissionError("Missing required scopes for tool invocation.")

    def fetch_data(self, validated_params: dict, credentials: dict):
        """
        Fetch any required data for tool execution
        
        This method is called after parameter validation but before tool execution.
        It can be used to:
        - Retrieve data from external APIs or databases
        - Prepare context information needed by tools
        - Fetch user-specific data based on credentials
        - Load configuration or reference data
        
        Args:
            validated_params (dict): Tool parameters that have passed validation
            credentials (dict): User credentials for authenticated data access
            
        Returns:
            dict: Raw data that will be passed to the tool execution
        """
        # For the hello tool, just return the parameters as "raw data"
        # If parameters are not present, return an empty dict
        return validated_params

    def build_context(self, raw_data) -> dict:
        """
        Build execution context for tool invocation
        
        This method prepares the final context that will be available
        during tool execution. It can include:
        - Processed data from fetch_data()
        - Tool metadata and configuration
        - User context and preferences
        - Execution environment information
        
        Args:
            raw_data: The data returned from fetch_data()
            
        Returns:
            dict: Complete context for tool execution
        """
        # For the hello tool, context is just the input parameters
        return {"tool": "hello", "input": raw_data}

    def get_fastapi_app(self):
        """
        Create and configure the FastAPI application
        
        This method sets up the complete FastAPI application including:
        - MCP (Model Context Protocol) endpoints for agent communication
        - Health check endpoints for monitoring and Cloud Run
        - Tool invocation endpoints for direct API access
        - API documentation and service information
        
        The application combines:
        - FastMCP's HTTP app for MCP protocol compliance
        - Custom REST endpoints for direct tool access
        - Security middleware and error handling
        - Comprehensive health monitoring
        
        Returns:
            FastAPI: Configured FastAPI application ready to serve requests
        """
        # Create the MCP HTTP app with Server-Sent Events transport
        # This handles the Model Context Protocol for agent communication
        mcp_app = self.mcp.http_app(path='/mcp', transport="sse")
        
        # Create the main FastAPI application with metadata
        app = FastAPI(
            title="MCP Server",
            description="Model Context Protocol Server with secure tool execution",
            version="1.0.0",
            lifespan=mcp_app.lifespan  # Share lifespan management with MCP app
        )
        
        # Mount the MCP app at /mcp-server path
        # This makes MCP protocol endpoints available to AI agents
        app.mount("/mcp-server", mcp_app)

        @app.get("/health")
        async def health_check():
            """
            Health check endpoint for Cloud Run and monitoring
            
            This endpoint provides comprehensive health status information including:
            - Service availability and responsiveness
            - Number of registered tools
            - Security configuration status
            - Timestamp for monitoring purposes
            
            Used by:
            - Google Cloud Run for health monitoring
            - Load balancers for service discovery
            - Monitoring systems for alerting
            - DevOps teams for troubleshooting
            
            Returns:
                dict: Health status information
                
            Raises:
                HTTPException: 503 status if health check fails
            """
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
            """
            Health check endpoint specifically for MCP server mount point
            
            This provides the same health information as /health but is available
            at the MCP server mount path for consistency and load balancer configuration.
            
            Returns:
                dict: Same health status as main health endpoint
            """
            return await health_check()

        @app.post("/invoke")
        async def invoke_tool(request: Request):
            """
            Direct tool invocation endpoint
            
            This endpoint allows direct HTTP POST access to MCP tools without
            using the full MCP protocol. Useful for:
            - Testing tools during development
            - Integration with non-MCP systems
            - Direct API access from web applications
            - Debugging and troubleshooting
            
            The request should contain JSON with tool parameters.
            
            Args:
                request (Request): FastAPI request object containing tool parameters
                
            Returns:
                dict: Tool execution results
                
            Raises:
                HTTPException: 400 for tool errors, 500 for server errors
            """
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
            """
            Root endpoint with service information
            
            This endpoint provides an overview of the MCP server including:
            - Service identification and version
            - Available API endpoints and their purposes
            - Service description and capabilities
            
            Useful for:
            - Service discovery
            - API documentation
            - Integration guidance
            - Development and testing
            
            Returns:
                dict: Service information and endpoint directory
            """
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
    """
    Application factory function for creating the MCP server FastAPI app
    
    This function:
    1. Loads configuration from environment variables
    2. Creates an MCPServer instance with security controls
    3. Returns a configured FastAPI application
    
    Configuration loaded from environment:
    - CLOUD_RUN_AUDIENCE: Expected audience for Google Cloud ID tokens
    - GCP_PROJECT: Google Cloud Project ID for services
    - OPA_URL: Open Policy Agent URL for policy decisions
    - KMS_KEY_PATH: Key Management Service path for encryption
    - SECURITY_LEVEL: Security level (standard, high, etc.)
    
    Returns:
        FastAPI: Configured application ready for deployment
    """
    # Build configuration from environment variables
    # This allows different configs for dev, staging, and production
    config = {
        "cloud_run_audience": os.getenv("CLOUD_RUN_AUDIENCE"),
        "gcp_project": os.getenv("GCP_PROJECT"),
        "opa_url": os.getenv("OPA_URL", "http://localhost:8181"),
        "kms_key_path": os.getenv("KMS_KEY_PATH"),
        "security_level": os.getenv("SECURITY_LEVEL", "standard"),
    }
    
    # Create the MCP server with security configuration
    server = MCPServer(config)
    
    # Return the configured FastAPI application
    return server.get_fastapi_app()

# Create the application instance for deployment
# This is the ASGI application that will be run by uvicorn/gunicorn
# Cloud Run, Docker, and other deployment systems will import this 'app' variable
app = create_app()