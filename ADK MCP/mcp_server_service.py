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
        Get the expected audience for Google Cloud ID token validation
        
        This method returns the audience claim that should be present in
        Google Cloud ID tokens. The audience identifies the intended recipient
        of the token and helps prevent token misuse.
        
        In Google Cloud Run service-to-service authentication:
        - Audience is typically the URL of the target Cloud Run service
        - It's used to verify that tokens were meant for your service
        - Prevents tokens from other services being used maliciously
        
        Returns:
            str: The expected audience value from configuration
        """
        # Return the expected audience for Google Cloud ID token validation
        return self.config.get("cloud_run_audience", "")

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
        required_scopes = set(self.config.get("required_scopes", []))
        
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

    async def _execute_tool_securely(self, tool_name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute tool with security controls and return results in MCP format
        
        This method integrates with the base class streaming functionality
        to securely execute tools and return properly formatted results.
        
        Args:
            tool_name (str): Name of the tool to execute
            arguments (Dict[str, Any]): Tool arguments
            
        Returns:
            List[Dict[str, Any]]: Results in MCP content format
        """
        try:
            # Get tools dictionary from FastMCP
            tools_dict = await self.mcp.get_tools()
            
            if tool_name not in tools_dict:
                return [{"type": "text", "text": f"Tool '{tool_name}' not found"}]
            
            tool = tools_dict[tool_name]
            
            # Execute the tool function directly
            if hasattr(tool, 'fn') and callable(tool.fn):
                result = tool.fn(**arguments)
                
                # Convert result to MCP content format
                if isinstance(result, str):
                    return [{"type": "text", "text": result}]
                elif isinstance(result, dict):
                    return [{"type": "text", "text": str(result)}]
                else:
                    return [{"type": "text", "text": str(result)}]
            else:
                return [{"type": "text", "text": f"Tool '{tool_name}' is not callable"}]
                
        except Exception as e:
            # Return error in MCP format
            return [{"type": "text", "text": f"Error executing tool {tool_name}: {str(e)}"}]

    # === FASTAPI APPLICATION CUSTOMIZATION ===
    
    def get_app_title(self) -> str:
        """Override the FastAPI application title"""
        return "Greeting MCP Server"
    
    def get_app_description(self) -> str:
        """Override the FastAPI application description"""
        return "Model Context Protocol Server with greeting tools and secure execution"

    def _add_custom_endpoints(self, app: FastAPI):
        """Add custom endpoints specific to this MCP server"""
        
        @app.get("/tools")
        async def list_tools():
            """Custom endpoint to list available tools"""
            return {
                "tools": [
                    {
                        "name": "hello",
                        "description": "Simple greeting tool",
                        "parameters": {"name": "string"}
                    }
                ]
            }
        
        @app.get("/greeting-stats")
        async def greeting_stats():
            """Custom endpoint for greeting-specific statistics"""
            return {
                "total_greetings": 0,  # You could implement actual tracking
                "last_greeting": None,
                "service": "greeting-mcp-server"
            }

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
    - REQUIRED_SCOPES: Required scopes for tool invocation (comma-separated)
    
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
        "required_scopes": os.getenv("REQUIRED_SCOPES", "").split(",") if os.getenv("REQUIRED_SCOPES") else [],
    }
    
    # Create the MCP server with security configuration
    server = MCPServer(config)
    
    # Return the configured FastAPI application
    return server.get_fastapi_app()

# Create the application instance for deployment
# This is the ASGI application that will be run by uvicorn/gunicorn
# Cloud Run, Docker, and other deployment systems will import this 'app' variable
app = create_app()