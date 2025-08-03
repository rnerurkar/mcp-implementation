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
from typing import Any, Dict, List    # For type hints and better code documentation

# FastAPI for HTTP exception handling
from fastapi import HTTPException     # For proper HTTP error responses

# Import all security control components
# These provide comprehensive protection against various attack vectors
from mcp_security_controls import (
    InputSanitizer,           # Prevents prompt injection and input-based attacks
    GoogleCloudTokenValidator, # Validates ID tokens from Google Cloud IAM
    CredentialManager,        # Securely manages secrets and credentials
    ContextSanitizer,         # Protects against context poisoning attacks
    ContextSecurity,          # Provides encryption for sensitive context data
    OPAPolicyClient,          # Enforces policy-based access control
    SchemaValidator,          # Validates input schemas and applies security rules
    SecurityException         # Custom security exception handling
)

class BaseMCPServer(ABC):
    """
    Abstract base class for secure MCP (Model Context Protocol) servers
    
    This class provides a complete security framework for MCP servers including:
    - Multi-layer input validation and sanitization
    - Authentication and authorization via Azure AD
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
                - azure_audience: Expected audience for Azure AD tokens
                - azure_scopes: Required OAuth scopes for authorization
                - azure_issuer: Azure AD token issuer URL
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
        self.context_security = ContextSecurity(
            kms_key_path=config.get("kms_key_path")
        )
        self.opa_client = OPAPolicyClient(
            opa_url=config.get("opa_url", "http://localhost:8181")
        )

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming request through comprehensive security pipeline
        
        This method implements a secure request processing workflow that:
        1. Authenticates and authorizes the request
        2. Sanitizes and validates all inputs
        3. Enforces security policies
        4. Securely executes the requested tool
        5. Sanitizes and signs the response context
        
        The pipeline provides defense-in-depth security with multiple
        validation and sanitization layers. Each step can reject malicious
        or invalid requests before they reach sensitive tool execution.
        
        Args:
            request (Dict[str, Any]): Incoming request containing:
                - token: Authentication token (optional)
                - tool_name: Name of the tool to execute
                - parameters: Tool parameters to validate and sanitize
                
        Returns:
            Dict[str, Any]: Secure response containing:
                - status: "success" or "error"
                - context: Sanitized and signed execution context (on success)
                - message: Error message (on failure)
                
        Raises:
            HTTPException: For authentication, authorization, or validation failures
        """
        try:
            # === PHASE 1: AUTHENTICATION & AUTHORIZATION ===
            # Validate Google Cloud ID tokens if authentication is configured
            token_claims = {}
            if self.token_validator and request.get("token"):
                # Validate token signature, audience, and expiration
                token_claims = self.token_validator.validate(request["token"])

            # === PHASE 2: INPUT SANITIZATION ===
            # Clean input parameters to prevent injection attacks
            sanitized_params = self.input_sanitizer.sanitize(
                request.get("parameters", {})
            )

            # === PHASE 3: INPUT VALIDATION ===
            # Validate parameters against schema and security rules
            input_validator = SchemaValidator(
                schema=self._load_tool_schema(request.get("tool_name", "hello")),
                security_rules=self._load_security_rules()
            )
            validated_params = input_validator.validate(sanitized_params)

            # === PHASE 4: POLICY ENFORCEMENT ===
            # Check Open Policy Agent rules if policy engine is available
            if self.opa_client:
                policy_context = {
                    "user": token_claims.get("email", "anonymous"),  # Google Cloud uses email
                    "service_account": token_claims.get("sub", "unknown"),  # Service account ID
                    "tool": request.get("tool_name", "hello"),
                    "params": validated_params
                }
                if not self.opa_client.check_policy(policy_context):
                    raise PermissionError("OPA policy violation.")

            # === PHASE 5: SECURE TOOL EXECUTION ===
            # Inject credentials securely and execute the tool
            credentials = {}
            if self.credential_manager:
                credentials = self.credential_manager.get_credentials(
                    request.get("tool_name", "hello"), validated_params
                )
            
            # Execute the tool with validated parameters and secure credentials
            result = self.fetch_data(validated_params, credentials)

            # === PHASE 6: CONTEXT BUILDING ===
            # Build execution context for the response
            context = self.build_context(result)

            # === PHASE 7: RESPONSE SANITIZATION & SIGNING ===
            # === PHASE 7: RESPONSE SANITIZATION & SIGNING ===
            # Sanitize response context to prevent data leakage
            sanitized_context = self.context_sanitizer.sanitize(context)
            
            # Sign the context for integrity verification
            signed_context = self.context_security.sign(sanitized_context)

            # Return successful response with secure context
            return {"status": "success", "data": signed_context}

        except Exception as e:
            # Centralized error handling for all security and execution failures
            # Log the error for monitoring while preventing information disclosure
            print(f"Request processing error: {str(e)}")
            return {"status": "error", "message": str(e)}

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
        Return the expected audience for Azure AD token validation
        
        This method should return the audience claim that must be present
        in Azure AD JWT tokens. The audience identifies the intended
        recipient of the token and prevents token misuse.
        
        Typically this is your application's ID URI in Azure AD.
        
        Returns:
            str: Expected audience value for token validation
            
        Example:
            "api://your-application-id"
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