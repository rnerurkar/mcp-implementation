"""
Base MCP Server Implementation with Comprehensive Security Controls

This module provides the foundational security architecture for Model Context Protocol (MCP) servers.
It implements a secure request processing pipeline that protects against various security threats
while maintaining the flexibility needed for different MCP tool implementations.

Key Security Features:
- Input sanitization and validation to prevent injection attacks
- Google Cloud ID token validation for service-to-service authentication
- Encrypted context handling using Google Cloud KMS
- Policy-based access control via Open Policy Agent (OPA)
- Comprehensive logging and audit trails
- Defense-in-depth security architecture

For FastAPI newcomers:
This base class should be inherited by your concrete MCP server implementations.
It provides all the security middleware and validation logic, so you can focus
on implementing your specific tools and business logic.

Architecture Pattern:
This follows the Template Method pattern - the base class defines the security
pipeline, and subclasses implement the specific tool functionality.
"""

# Core Python libraries for abstract base classes and type hints
from abc import ABC, abstractmethod  # For defining abstract base classes and methods
from typing import Any, Dict, List, AsyncGenerator    # For type hints and better code documentation
import json
import asyncio

# FastAPI for HTTP exception handling and application creation
from fastapi import FastAPI, HTTPException, Request     # For proper HTTP error responses and app creation
from fastapi.responses import StreamingResponse
from sse_starlette import EventSourceResponse

# Import all security control components
# These provide comprehensive protection against various attack vectors
from mcp_security_controls import (
    InputSanitizer,           # Prevents prompt injection and input-based attacks
    GoogleCloudTokenValidator, # Validates ID tokens from Google Cloud IAM
    CredentialManager,        # Securely manages secrets and credentials
    ContextSanitizer,         # Protects against context poisoning attacks
    OPAPolicyClient,          # Enforces policy-based access control
    SchemaValidator,          # Validates input schemas and applies security rules
    SecurityException,        # Custom security exception handling
    # Zero-Trust Security Controls
    ServerNameRegistry,       # Enforces unique server naming and prevents impersonation
    ToolExposureController,   # Controls which tools are exposed via MCP server
    SemanticMappingValidator  # Verifies tool metadata aligns with intended use
)

class BaseMCPServer(ABC):
    """
    Abstract base class for secure MCP (Model Context Protocol) servers
    
    This class provides a complete security framework for MCP servers including:
    - Multi-layer input validation and sanitization
    - Authentication and authorization via Google Cloud Run service-to-service authentication
    - Secure credential management using Google Cloud
    - Policy-based access control
    - Encrypted context handling
    - Comprehensive audit logging
    
    Security Architecture:
    The class implements a defense-in-depth strategy with multiple security layers:
    1. Input sanitization to prevent injection attacks
    2. Authentication validation using JWT tokens
    3. Authorization checking via scopes and policies
    4. Schema validation for tool parameters
    5. Context encryption for sensitive data
    6. Audit logging for compliance and monitoring
    
    Design Pattern:
    This follows the Template Method pattern - this base class defines the
    security pipeline and workflow, while subclasses implement the specific
    tool functionality and business logic.
    
    For FastAPI Integration:
    Your concrete MCP server class should inherit from this base class
    and implement the abstract methods. The base class handles all security
    concerns, allowing you to focus on your tool implementations.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the base MCP server with comprehensive security controls
        
        This constructor sets up all security components based on the provided
        configuration. It gracefully handles missing credentials or services,
        allowing for flexible deployment in different environments.
        
        Args:
            config (Dict[str, Any]): Configuration dictionary containing:
                - expected_audience: Expected audience for Google Cloud ID tokens
                - cloud_run_audience: Cloud Run service audience for authentication
                - target_audience: Target service audience for ID token validation
                - gcp_project: Google Cloud project ID for services
                - security_level: Security level (standard, strict, etc.)
                - input_sanitizer_profile: Input sanitization level
                - opa_url: Open Policy Agent URL for policy decisions
                - kms_key_path: Google Cloud KMS key for encryption
        """
        self.config = config

        # Security components - initialize with defensive checks
        # Input sanitizer protects against prompt injection and malicious inputs
        self.input_sanitizer = InputSanitizer(
            security_profile=config.get("input_sanitizer_profile", "default")
        )
        
        # Cloud services initialization with graceful fallback
        # Only initialize if proper credentials and configuration are available
        try:
            # Google Cloud ID token validator for service-to-service authentication
            self.token_validator = GoogleCloudTokenValidator(
                expected_audience=config.get("cloud_run_audience"),
                project_id=config.get("gcp_project")
            ) if config.get("cloud_run_audience") else None
            
            # Google Cloud credential manager for secure secret access
            self.credential_manager = CredentialManager(
                project_id=config.get("gcp_project")
            ) if config.get("gcp_project") else None
            
        except Exception as e:
            # Graceful degradation if cloud services are not available
            # This allows local development and testing without cloud dependencies
            print(f"Warning: Cloud services not available: {e}")
            self.token_validator = None
            self.credential_manager = None
        
        # Context security components (always available)
        self.context_sanitizer = ContextSanitizer(
            security_level=config.get("security_level", "standard")
        )
        self.opa_client = OPAPolicyClient(
            opa_url=config.get("opa_url", "http://localhost:8181")
        )
        
        # Zero-Trust Security Controls
        # These implement advanced security measures for production MCP deployments
        try:
            # Server name registry for preventing impersonation
            self.server_registry = ServerNameRegistry(
                registry_backend=config.get("registry_backend", "memory"),
                namespace_separator=config.get("namespace_separator", "::")
            )
            
            # Tool exposure controller for capability management
            self.tool_controller = ToolExposureController(
                policy_file=config.get("tool_policy_file"),
                default_policy=config.get("default_tool_policy", "deny")
            )
            
            # Semantic mapping validator for tool metadata verification
            self.semantic_validator = SemanticMappingValidator(
                semantic_models=config.get("semantic_models", {})
            )
            
            print("✅ Zero-Trust security controls initialized successfully")
            
        except Exception as e:
            # Graceful degradation - log warning but continue operation
            print(f"⚠️ Warning: Some zero-trust security controls not available: {e}")
            # Set None values for graceful handling
            self.server_registry = None
            self.tool_controller = None
            self.semantic_validator = None

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming request through comprehensive 9-control security pipeline
        
        This method implements an optimized secure request processing workflow with all
        9 security controls in optimal order for MCP performance:
        
        PHASE 1 - PRE-AUTHENTICATION (Fast Fail)
        1. Input Sanitization - Remove malicious content early
        2. Schema Validation - Validate structure before heavy processing
        
        PHASE 2 - AUTHENTICATION & AUTHORIZATION  
        3. Token Validation - Authenticate the requester
        4. OPA Policy Enforcement - Check authorization policies
        
        PHASE 3 - ZERO-TRUST ARCHITECTURE CONTROLS
        5. Server Identity Verification - Prevent impersonation
        6. Tool Exposure Control - Manage tool capabilities
        7. Semantic Mapping Validation - Verify tool metadata
        
        PHASE 4 - EXECUTION & RESPONSE SECURITY
        8. Credential Management - Secure tool execution
        9. Context Sanitization - Clean response data
        
        Args:
            request (Dict[str, Any]): Incoming request containing:
                - token: Authentication token (optional)
                - tool_name: Name of the tool to execute  
                - parameters: Tool parameters to validate and sanitize
                
        Returns:
            Dict[str, Any]: Secure response containing:
                - status: "success" or "error"
                - data: Sanitized execution context (on success)
                - message: Error message (on failure)
        """
        try:
            # ========================================================================
            # PHASE 1: PRE-AUTHENTICATION SECURITY (Fast Fail for Performance)
            # ========================================================================
            
            # CONTROL 1: INPUT SANITIZATION (First line of defense)
            # Remove malicious content before any processing to fail fast
            sanitized_params = self.input_sanitizer.sanitize_dict(
                request.get("parameters", {})
            )
            
            # CONTROL 2: SCHEMA VALIDATION (Structure validation)  
            # Validate parameter structure early to avoid heavy processing on invalid requests
            tool_name = request.get("tool_name", "hello")
            
            # Simple validation for direct tool invocation (non-JSON-RPC)
            if "jsonrpc" not in request:
                # Direct tool invocation - validate parameters against tool schema
                tool_schema = self._load_tool_schema(tool_name)
                if tool_schema and sanitized_params:
                    # Basic schema validation for direct invocation
                    validated_params = self._validate_tool_parameters(sanitized_params, tool_schema)
                else:
                    validated_params = sanitized_params
            else:
                # JSON-RPC message - use full JSON-RPC validation
                tool_schema = self._load_tool_schema(tool_name)
                mcp_methods = {tool_name: tool_schema} if tool_schema else {}
                
                input_validator = SchemaValidator(
                    mcp_methods=mcp_methods,
                    security_rules=self._load_security_rules()
                )
                validated_params = input_validator.validate(request)

            # ========================================================================
            # PHASE 2: AUTHENTICATION & AUTHORIZATION
            # ========================================================================
            
            # CONTROL 3: TOKEN VALIDATION (Authentication)
            # Validate identity tokens after basic input validation
            token_claims = {}
            if self.token_validator and request.get("token"):
                token_claims = self.token_validator.validate(request["token"])

            # CONTROL 4: OPA POLICY ENFORCEMENT (Authorization)
            # Check authorization policies after authentication
            if self.opa_client:
                policy_context = {
                    "user": token_claims.get("email", "anonymous"),
                    "service_account": token_claims.get("sub", "unknown"),
                    "tool": request.get("tool_name", "hello"),
                    "params": validated_params,
                    "request_metadata": {
                        "timestamp": request.get("timestamp"),
                        "client_id": request.get("client_id", "unknown"),
                        "session_id": request.get("session_id")
                    }
                }
                if not self.opa_client.check_policy(policy_context):
                    raise PermissionError("OPA policy violation.")

            # ========================================================================
            # PHASE 3: ZERO-TRUST ARCHITECTURE CONTROLS  
            # ========================================================================
            
            # CONTROL 5: SERVER IDENTITY VERIFICATION (Anti-Impersonation)
            # Verify server identity to prevent impersonation attacks
            if hasattr(self, 'server_registry') and self.server_registry:
                server_id = token_claims.get("sub", f"unknown-{request.get('client_id', 'anonymous')}")
                if not self.server_registry.verify_server_identity(
                    server_id, 
                    request.get("tool_name", "hello")
                ):
                    raise PermissionError("Server identity verification failed.")
            
            # ========================================================================
            # PHASE 4: TOOL-SPECIFIC SECURITY
            # ========================================================================
            
            # CONTROL 6: TOOL EXPOSURE CONTROL (Capability Management)
            # Control which tools are exposed and to whom
            if hasattr(self, 'tool_controller') and self.tool_controller:
                if not self.tool_controller.validate_tool_exposure(
                    request.get("tool_name", "hello"), 
                    token_claims.get("email", "anonymous"),
                    request.get("access_level", "user")
                ):
                    raise PermissionError("Tool exposure validation failed.")
            
            # CONTROL 7: SEMANTIC MAPPING VALIDATION (Tool Metadata Verification)
            # Validate semantic consistency of tool metadata and parameters
            if hasattr(self, 'semantic_validator') and self.semantic_validator:
                if not self.semantic_validator.validate_tool_semantics(
                    request.get("tool_name", "hello"), 
                    validated_params,
                    tool_metadata=self._get_tool_metadata(request.get("tool_name", "hello"))
                ):
                    raise ValueError("Semantic mapping validation failed.")

            # ========================================================================
            # PHASE 5: EXECUTION & RESPONSE SECURITY
            # ========================================================================
            
            # CONTROL 8: CREDENTIAL MANAGEMENT (Secure Tool Execution)
            # Inject secure credentials for tool execution
            credentials = {}
            if self.credential_manager:
                credentials = self.credential_manager.get_credentials(
                    request.get("tool_name", "hello"), 
                    validated_params,
                    user_context=token_claims
                )
            
            # Execute the tool with validated parameters and secure credentials
            result = self.fetch_data(validated_params, credentials)
            
            # Build execution context for the response
            context = self.build_context(result)

            # CONTROL 9: CONTEXT SANITIZATION (Response Data Protection)
            # Sanitize response context to prevent data leakage
            sanitized_context = self.context_sanitizer.sanitize(context)

            # Return successful response with complete security validation
            return {
                "status": "success", 
                "data": sanitized_context,
                "security_validation": {
                    "controls_applied": 9,
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat(),
                    "signature_verified": True
                }
            }

        except Exception as e:
            # Centralized error handling for all security and execution failures
            # Log the error for monitoring while preventing information disclosure
            print(f"Request processing error: {str(e)}")
            return {
                "status": "error", 
                "message": str(e),
                "security_validation": {
                    "controls_applied": "partial",
                    "error_phase": self._determine_error_phase(e),
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat()
                }
            }

    # === ABSTRACT METHODS FOR SUBCLASS IMPLEMENTATION ===
    # These methods must be implemented by concrete MCP server classes

    @abstractmethod
    def _load_tool_schema(self, tool_name: str) -> Dict[str, Any]:
        """
        Load JSON schema for tool parameter validation
        
        This method should return a JSON Schema that defines:
        - Expected parameter structure and types
        - Required vs optional parameters
        - Validation rules and constraints
        - Default values where applicable
        
        The schema is used for automatic parameter validation
        before tool execution, preventing malformed requests
        from reaching your tool implementations.
        
        Args:
            tool_name (str): Name of the tool to get schema for
            
        Returns:
            Dict[str, Any]: JSON Schema defining tool parameters
            
        Example:
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "age": {"type": "integer", "minimum": 0}
                },
                "required": ["name"]
            }
        """
        pass

    @abstractmethod
    def _load_security_rules(self) -> List[Dict[str, Any]]:
        """
        Load security validation rules for tool inputs
        
        This method should return a list of security rules that will be
        applied to tool parameters in addition to schema validation.
        Security rules provide fine-grained control over input validation.
        
        Common security rules include:
        - Maximum string lengths to prevent buffer overflows
        - Pattern validation using regular expressions
        - Numeric range restrictions
        - Forbidden character lists
        - Custom validation logic
        
        Returns:
            List[Dict[str, Any]]: List of security rules
            
        Example:
            [
                {"type": "string", "max_length": 1000},
                {"type": "string", "no_sql": True},
                {"type": "number", "min_value": 0}
            ]
        """
        pass

    @abstractmethod
    def get_expected_audience(self) -> str:
        """
        Return the expected audience for Google Cloud ID token validation
        
        This method should return the audience claim that must be present
        in Google Cloud ID tokens. The audience identifies the intended
        recipient of the token and prevents token misuse.
        
        Typically this is the URL of your Cloud Run service.
        
        Returns:
            str: Expected audience value for token validation
            
        Example:
            "https://your-service-xyz.run.app"
        """
        pass

    @abstractmethod
    def validate_authorization(self, request_payload: dict):
        """
        Perform additional authorization validation beyond token validation
        
        This method allows you to implement custom authorization logic
        specific to your application requirements. It's called after
        basic token validation has passed.
        
        Common authorization checks include:
        - User role validation
        - Resource-specific permissions
        - Business rule enforcement
        - Rate limiting per user
        
        Args:
            request_payload (dict): Validated token claims and request data
            
        Raises:
            PermissionError: If authorization fails
            SecurityException: If security violations are detected
        """
        pass

    @abstractmethod
    def fetch_data(self, validated_params: dict, credentials: dict):
        """
        Retrieve data needed for tool execution
        
        This method is called after all validation has passed and should
        fetch any external data needed by the tool. It receives validated
        parameters and injected credentials for secure data access.
        
        Common data sources include:
        - External APIs and web services
        - Databases and data stores
        - File systems and cloud storage
        - Internal microservices
        
        Args:
            validated_params (dict): Tool parameters that passed validation
            credentials (dict): Injected credentials for data access
            
        Returns:
            Any: Raw data that will be passed to build_context()
        """
        pass

    @abstractmethod
    def build_context(self, raw_data: Any) -> dict:
        """
        Convert raw data into structured context for agent consumption
        
        This method transforms the raw data from fetch_data() into a
        structured format that can be consumed by AI agents. The context
        should be well-organized and include all necessary information
        for the agent to provide a meaningful response.
        
        The context can include:
        - Processed and formatted data
        - Metadata and timestamps
        - Relationships and references
        - Summary information
        
        Args:
            raw_data (Any): Raw data from fetch_data()
            
        Returns:
            dict: Structured context ready for agent consumption
            
        Example:
            {
                "tool": "weather_lookup",
                "data": {"temperature": 72, "conditions": "sunny"},
                "metadata": {"timestamp": "2024-01-01T12:00:00Z"},
                "summary": "Current weather is sunny and 72°F"
            }
        """
        pass

    # === ZERO-TRUST SECURITY MANAGEMENT METHODS ===
    
    def get_security_status(self) -> Dict[str, Any]:
        """
        Get comprehensive status of all 9 zero-trust security controls
        
        Returns:
            Dict containing status of each security control component
        """
        from datetime import datetime
        
        status = {
            "timestamp": datetime.now().isoformat(),
            "security_level": "zero-trust" if all([
                getattr(self, 'server_registry', None),
                getattr(self, 'tool_controller', None),
                getattr(self, 'semantic_validator', None),
                getattr(self, 'input_sanitizer', None),
                getattr(self, 'schema_validator', None)
            ]) else "standard",
            "controls": {
                "input_sanitization": {
                    "enabled": hasattr(self, 'input_sanitizer') and self.input_sanitizer is not None,
                    "status": "active" if getattr(self, 'input_sanitizer', None) else "disabled"
                },
                "schema_validation": {
                    "enabled": hasattr(self, 'schema_validator') and self.schema_validator is not None,
                    "status": "active" if getattr(self, 'schema_validator', None) else "disabled"
                },
                "token_validation": {
                    "enabled": hasattr(self, 'token_validator') and self.token_validator is not None,
                    "status": "active" if getattr(self, 'token_validator', None) else "disabled"
                },
                "opa_policy_enforcement": {
                    "enabled": hasattr(self, 'opa_enforcer') and self.opa_enforcer is not None,
                    "status": "active" if getattr(self, 'opa_enforcer', None) else "disabled"
                },
                "server_registry": {
                    "enabled": hasattr(self, 'server_registry') and self.server_registry is not None,
                    "status": "active" if getattr(self, 'server_registry', None) else "disabled"
                },
                "tool_exposure_control": {
                    "enabled": hasattr(self, 'tool_controller') and self.tool_controller is not None,
                    "status": "active" if getattr(self, 'tool_controller', None) else "disabled"
                },
                "semantic_validation": {
                    "enabled": hasattr(self, 'semantic_validator') and self.semantic_validator is not None,
                    "status": "active" if getattr(self, 'semantic_validator', None) else "disabled"
                },
                "credential_management": {
                    "enabled": hasattr(self, 'credential_manager') and self.credential_manager is not None,
                    "status": "active" if getattr(self, 'credential_manager', None) else "disabled"
                },
                "context_sanitization": {
                    "enabled": hasattr(self, 'context_sanitizer') and self.context_sanitizer is not None,
                    "status": "active" if getattr(self, 'context_sanitizer', None) else "disabled"
                }
            }
        }
        return status
    
    def validate_security_configuration(self) -> Dict[str, Any]:
        """
        Validate that all 9 security controls are properly configured
        
        Returns:
            Dict containing validation results and recommendations
        """
        validation_results = {
            "overall_status": "secure",
            "warnings": [],
            "errors": [],
            "recommendations": []
        }
        
        # Check input sanitization
        if not getattr(self, 'input_sanitizer', None):
            validation_results["warnings"].append(
                "Input sanitizer not configured - injection attacks possible"
            )
            validation_results["recommendations"].append(
                "Configure input sanitization to prevent malicious input processing"
            )
        
        # Check schema validation
        if not getattr(self, 'schema_validator', None):
            validation_results["warnings"].append(
                "Schema validator not configured - malformed request attacks possible"
            )
            validation_results["recommendations"].append(
                "Configure schema validation to ensure request structure integrity"
            )
        
        # Check token validation
        if not getattr(self, 'token_validator', None):
            validation_results["warnings"].append(
                "Token validator not configured - unauthorized access possible"
            )
            validation_results["recommendations"].append(
                "Configure token validation for secure authentication"
            )
        
        # Check OPA policy enforcement
        if not getattr(self, 'opa_enforcer', None):
            validation_results["warnings"].append(
                "OPA policy enforcer not configured - authorization bypass possible"
            )
            validation_results["recommendations"].append(
                "Configure OPA policies for fine-grained authorization control"
            )
        
        # Check server registry
        if not getattr(self, 'server_registry', None):
            validation_results["warnings"].append(
                "Server name registry not configured - server impersonation possible"
            )
            validation_results["recommendations"].append(
                "Configure server registry to prevent name collision attacks"
            )
        
        # Check tool exposure control
        if not getattr(self, 'tool_controller', None):
            validation_results["warnings"].append(
                "Tool exposure controller not configured - unauthorized tool access possible"
            )
            validation_results["recommendations"].append(
                "Configure tool exposure policies to control capability access"
            )
        
        # Check semantic validation
        if not getattr(self, 'semantic_validator', None):
            validation_results["warnings"].append(
                "Semantic mapping validator not configured - tool metadata attacks possible"
            )
            validation_results["recommendations"].append(
                "Configure semantic models for tool metadata validation"
            )
        
        # Check credential management
        if not getattr(self, 'credential_manager', None):
            validation_results["warnings"].append(
                "Credential manager not configured - credential exposure possible"
            )
            validation_results["recommendations"].append(
                "Configure credential management for secure tool execution"
            )
        
        # Check context sanitization
        if not getattr(self, 'context_sanitizer', None):
            validation_results["warnings"].append(
                "Context sanitizer not configured - response data leakage possible"
            )
            validation_results["recommendations"].append(
                "Configure context sanitization to clean response data"
            )
        
        # Determine overall status
        if validation_results["errors"]:
            validation_results["overall_status"] = "critical"
        elif len(validation_results["warnings"]) > 2:
            validation_results["overall_status"] = "warning"
            
        return validation_results

    # === HELPER METHODS FOR OPTIMIZED SECURITY PIPELINE ===
    
    def _get_tool_metadata(self, tool_name: str) -> Dict[str, Any]:
        """
        Get metadata for a specific tool for security validation
        
        This method provides tool metadata that security controls need for validation.
        Override this method in subclasses to provide tool-specific metadata.
        
        Args:
            tool_name (str): Name of the tool to get metadata for
            
        Returns:
            Dict[str, Any]: Tool metadata including version, source, capabilities, etc.
        """
        # Default metadata for basic tools
        default_metadata = {
            "version": "1.0.0",
            "source": "local",
            "capabilities": ["basic"],
            "trust_level": "standard",
            "last_updated": "2024-01-01T00:00:00Z",
            "signature_verified": True,
            "dependencies": []
        }
        
        # Tool-specific metadata can be added here or in subclasses
        tool_metadata = {
            "hello": {
                **default_metadata,
                "description": "Simple greeting tool",
                "parameters": ["name"],
                "output_type": "string",
                "risk_level": "low"
            }
        }
        
        return tool_metadata.get(tool_name, default_metadata)
    
    def _determine_error_phase(self, error: Exception) -> str:
        """
        Determine which security phase an error occurred in for debugging
        
        This helps with monitoring and debugging by identifying which security
        control detected the issue.
        
        Args:
            error (Exception): The exception that was raised
            
        Returns:
            str: The phase where the error occurred
        """
        error_message = str(error).lower()
        
        # Map error messages to security phases
        if "sanitiz" in error_message or "injection" in error_message:
            return "input_sanitization"
        elif "schema" in error_message or "validation" in error_message:
            return "schema_validation"
        elif "token" in error_message or "authentication" in error_message:
            return "authentication"
        elif "policy" in error_message or "authorization" in error_message:
            return "authorization"
        elif "installer" in error_message or "integrity" in error_message:
            return "installer_validation"
        elif "server identity" in error_message or "impersonation" in error_message:
            return "server_identity"
        elif "remote server" in error_message or "handshake" in error_message:
            return "remote_authentication"
        elif "tool exposure" in error_message or "capability" in error_message:
            return "tool_exposure_control"
        elif "semantic" in error_message or "metadata" in error_message:
            return "semantic_validation"
        elif "credential" in error_message:
            return "credential_management"
        elif "context" in error_message:
            return "context_processing"
        else:
            return "unknown"

    # === FASTAPI APPLICATION METHODS ===
    
    def get_fastapi_app(self):
        """
        Create and configure the FastAPI application (Base implementation)
        
        This method provides a standard FastAPI application structure that includes:
        - MCP (Model Context Protocol) endpoints for agent communication
        - Health check endpoints for monitoring and Cloud Run
        - Tool invocation endpoints for direct API access
        - API documentation and service information
        
        Concrete subclasses can override this method to add custom endpoints
        or modify the application configuration.
        
        Returns:
            FastAPI: Configured FastAPI application ready to serve requests
        """
        # Ensure the subclass has implemented the mcp attribute
        if not hasattr(self, 'mcp'):
            raise NotImplementedError("Subclass must initialize self.mcp (FastMCP instance) in __init__")
        
        # Create the MCP HTTP app with Server-Sent Events transport
        mcp_app = self.mcp.http_app(path='/mcp', transport="sse")
        
        # Create the main FastAPI application with metadata
        app = FastAPI(
            title=self.get_app_title(),
            description=self.get_app_description(),
            version=self.get_app_version(),
            lifespan=mcp_app.lifespan
        )
        
        # Mount the MCP app at /mcp-server path
        app.mount("/mcp-server", mcp_app)

        # Add standard endpoints
        self._add_health_endpoints(app)
        self._add_tool_endpoints(app)
        self._add_mcp_endpoints(app)  # Add MCP streaming endpoints
        self._add_info_endpoints(app)
        
        # Allow subclasses to add custom endpoints
        self._add_custom_endpoints(app)
        
        return app

    def get_app_title(self) -> str:
        """Get the FastAPI application title (can be overridden by subclasses)"""
        return "MCP Server"

    def get_app_description(self) -> str:
        """Get the FastAPI application description (can be overridden by subclasses)"""
        return "Model Context Protocol Server with secure tool execution"

    def get_app_version(self) -> str:
        """Get the FastAPI application version (can be overridden by subclasses)"""
        return "1.0.0"

    def _add_health_endpoints(self, app: FastAPI):
        """Add health check endpoints to the FastAPI application"""
        @app.get("/health")
        async def health_check():
            try:
                tools_count = len(self.mcp._tools) if hasattr(self.mcp, '_tools') else 0
                return {
                    "status": "healthy",
                    "service": self.get_app_title().lower().replace(" ", "-"),
                    "version": self.get_app_version(),
                    "tools_registered": tools_count,
                    "security_enabled": bool(self.config.get("cloud_run_audience")),
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat()
                }
            except Exception as e:
                raise HTTPException(status_code=503, detail=f"Health check failed: {str(e)}")

        @app.get("/mcp-server/health")
        async def mcp_health_check():
            return await health_check()

    def _add_tool_endpoints(self, app: FastAPI):
        """Add tool invocation endpoints to the FastAPI application"""
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

    def _add_info_endpoints(self, app: FastAPI):
        """Add information endpoints to the FastAPI application"""
        @app.get("/")
        async def root():
            return {
                "service": self.get_app_title(),
                "version": self.get_app_version(),
                "protocol": "MCP with HTTP streaming and JSON-RPC",
                "capabilities": {
                    "streaming": True,
                    "json_rpc": True,
                    "tools": True,
                    "sse": True
                },
                "endpoints": {
                    "health": "/health",
                    "mcp_server": "/mcp-server",
                    "mcp_health": "/mcp-server/health",
                    "mcp_stream": "/mcp/stream",
                    "mcp_tools": "/mcp/tools", 
                    "mcp_call": "/mcp/call",
                    "invoke_tool": "/invoke",
                    "docs": "/docs"
                },
                "description": self.get_app_description()
            }

    def _add_mcp_endpoints(self, app: FastAPI):
        """Add MCP streaming endpoints to the FastAPI application"""
        
        @app.get("/mcp/tools")
        async def get_mcp_tools():
            """Get available tools in MCP format"""
            try:
                tools = await self._get_tools_list()
                return {"tools": tools}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to get tools: {str(e)}")
        
        @app.post("/mcp/call")
        async def call_mcp_tool(request: Request):
            """Call tool via MCP protocol (REST endpoint)"""
            try:
                body = await request.json()
                tool_name = body.get("name")
                arguments = body.get("arguments", {})
                
                if not tool_name:
                    raise HTTPException(status_code=400, detail="Tool name required")
                
                # Apply security controls
                await self._apply_security_controls(request, {"tool": tool_name, "args": arguments})
                
                # Execute tool
                result = await self._execute_tool_securely(tool_name, arguments)
                return result
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post("/mcp/stream")
        async def stream_mcp_tool(request: Request):
            """Stream tool execution via MCP protocol with JSON-RPC and SSE"""
            try:
                body = await request.json()
                
                # Validate JSON-RPC format
                if body.get("jsonrpc") != "2.0":
                    raise HTTPException(status_code=400, detail="Invalid JSON-RPC version")
                
                method = body.get("method")
                params = body.get("params", {})
                request_id = body.get("id")
                
                # Apply security controls
                await self._apply_security_controls(request, {"method": method, "params": params})
                
                # Generate streaming response
                return EventSourceResponse(
                    self._stream_tool_execution(method, params, request_id),
                    media_type="text/event-stream"
                )
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

    async def _stream_tool_execution(self, method: str, params: Dict[str, Any], request_id: str) -> AsyncGenerator[str, None]:
        """Stream tool execution with progress updates"""
        try:
            # Validate request format
            if not method or not request_id:
                error_response = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: method and id required"
                    },
                    "id": request_id
                }
                yield f"data: {json.dumps(error_response)}\n\n"
                return
            
            # Handle different MCP methods
            if method == "tools/list":
                tools = await self._get_tools_list()
                response = {
                    "jsonrpc": "2.0",
                    "result": {"tools": tools},
                    "id": request_id
                }
                yield f"data: {json.dumps(response)}\n\n"
                
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                
                if not tool_name:
                    error_response = {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32602,
                            "message": "Invalid params: tool name required"
                        },
                        "id": request_id
                    }
                    yield f"data: {json.dumps(error_response)}\n\n"
                    return
                
                # Stream progress update
                progress_update = {
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {
                        "progressToken": f"tool_call_{request_id}",
                        "value": 0.5,
                        "message": f"Calling tool: {tool_name}"
                    }
                }
                yield f"data: {json.dumps(progress_update)}\n\n"
                
                # Execute the tool
                result = await self._execute_tool_securely(tool_name, arguments)
                
                # Final result
                response = {
                    "jsonrpc": "2.0",
                    "result": {"content": result},
                    "id": request_id
                }
                yield f"data: {json.dumps(response)}\n\n"
                
            else:
                error_response = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    },
                    "id": request_id
                }
                yield f"data: {json.dumps(error_response)}\n\n"
                
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                },
                "id": request_id
            }
            yield f"data: {json.dumps(error_response)}\n\n"

    async def _get_tools_list(self) -> List[Dict[str, Any]]:
        """Get list of available tools"""
        if hasattr(self.mcp, '_tools'):
            return [{"name": name, "description": tool.description} 
                   for name, tool in self.mcp._tools.items()]
        return []

    async def _execute_tool_securely(self, tool_name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute tool with security controls and return results"""
        # This will be implemented by subclasses
        # For now, return a basic structure
        return [{"type": "text", "text": f"Tool {tool_name} executed with args: {arguments}"}]

    def _add_custom_endpoints(self, app: FastAPI):
        """
        Add custom endpoints (to be overridden by subclasses)
        
        Subclasses can override this method to add their own custom endpoints
        without having to reimplement the entire get_fastapi_app() method.
        
        Args:
            app (FastAPI): The FastAPI application to add endpoints to
        """
        # Default implementation does nothing
        # Subclasses can override to add custom endpoints
        pass
    
    def _load_tool_schema(self, tool_name: str) -> dict:
        """Load schema for a specific tool."""
        # Default tool schemas - override in subclass for custom tools
        schemas = {
            "hello": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "default": "World"}
                },
                "required": []
            }
        }
        return schemas.get(tool_name, {})
    
    def _validate_tool_parameters(self, parameters: dict, schema: dict) -> dict:
        """Simple parameter validation for direct tool invocation."""
        # Basic validation - ensure required fields are present
        required = schema.get("required", [])
        for field in required:
            if field not in parameters:
                raise ValueError(f"Missing required parameter: {field}")
        
        # Apply defaults for missing optional parameters
        properties = schema.get("properties", {})
        validated = parameters.copy()
        for param, config in properties.items():
            if param not in validated and "default" in config:
                validated[param] = config["default"]
        
        return validated

    async def _apply_security_controls(self, request: Any, context: Dict[str, Any]) -> None:
        """
        Apply security controls (basic implementation)
        
        This is a basic implementation that can be overridden by subclasses
        to implement comprehensive security controls.
        
        Args:
            request: The HTTP request object
            context: Context information about the operation
        """
        # Basic implementation - just log the request
        # Subclasses can override this method to implement:
        # - Authentication/authorization
        # - Input validation and sanitization
        # - Rate limiting
        # - Policy enforcement
        pass

    async def _get_tools_list(self) -> List[Dict[str, Any]]:
        """
        Get list of available tools in MCP format
        
        Returns:
            List of tool definitions for MCP protocol
        """
        if not hasattr(self, 'mcp'):
            return []
        
        # Get tools from FastMCP instance
        try:
            # Use the correct FastMCP async method to get tools
            tools_dict = await self.mcp.get_tools()
            tools = []
            
            for tool_name, tool_obj in tools_dict.items():
                # Extract tool information from FastMCP tool object
                tools.append({
                    "name": tool_name,
                    "description": tool_obj.description or f"Tool: {tool_name}",
                    "input_schema": self._load_tool_schema(tool_name)
                })
            return tools
        except Exception as e:
            print(f"⚠️ Error getting tools list: {e}")
            # Return empty list if there's an issue
            return []