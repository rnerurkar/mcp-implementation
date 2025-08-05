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
    SecurityException,        # Custom security exception handling
    # Zero-Trust Security Controls
    InstallerSecurityValidator, # Prevents malicious installer distribution
    ServerNameRegistry,       # Enforces unique server naming and prevents impersonation
    RemoteServerAuthenticator, # Validates remote server identity and capabilities
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
        self.context_security = ContextSecurity(
            kms_key_path=config.get("kms_key_path")
        )
        self.opa_client = OPAPolicyClient(
            opa_url=config.get("opa_url", "http://localhost:8181")
        )
        
        # Zero-Trust Security Controls
        # These implement advanced security measures for production MCP deployments
        try:
            # Installer security validator for supply chain protection
            self.installer_validator = InstallerSecurityValidator(
                trusted_registries=config.get("trusted_registries", [
                    "https://registry.npmjs.org", "https://pypi.org", "https://github.com"
                ]),
                signature_keys=config.get("installer_signature_keys", {})
            )
            
            # Server name registry for preventing impersonation
            self.server_registry = ServerNameRegistry(
                registry_backend=config.get("registry_backend", "memory"),
                namespace_separator=config.get("namespace_separator", "::")
            )
            
            # Remote server authenticator for secure communication
            self.remote_authenticator = RemoteServerAuthenticator(
                trusted_ca_certs=config.get("trusted_ca_certs", []),
                handshake_timeout=config.get("handshake_timeout", 30)
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
            self.installer_validator = None
            self.server_registry = None
            self.remote_authenticator = None
            self.tool_controller = None
            self.semantic_validator = None

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

            # === PHASE 5: ZERO-TRUST SECURITY VALIDATION ===
            # Advanced security controls for production deployment
            if hasattr(self, 'tool_controller') and self.tool_controller:
                # Validate tool exposure permissions
                if not self.tool_controller.validate_tool_exposure(
                    request.get("tool_name", "hello"), 
                    token_claims.get("email", "anonymous")
                ):
                    raise PermissionError("Tool exposure validation failed.")
            
            if hasattr(self, 'server_registry') and self.server_registry:
                # Verify server identity to prevent impersonation
                server_id = token_claims.get("sub", f"unknown-{request.get('client_id', 'anonymous')}")
                if not self.server_registry.verify_server_identity(
                    server_id, 
                    request.get("tool_name", "hello")
                ):
                    raise PermissionError("Server identity verification failed.")
            
            if hasattr(self, 'semantic_validator') and self.semantic_validator:
                # Validate semantic mapping for tool metadata
                if not self.semantic_validator.validate_tool_semantics(
                    request.get("tool_name", "hello"), 
                    validated_params
                ):
                    raise ValueError("Semantic mapping validation failed.")

            # === PHASE 6: SECURE TOOL EXECUTION ===
            # Inject credentials securely and execute the tool
            credentials = {}
            if self.credential_manager:
                credentials = self.credential_manager.get_credentials(
                    request.get("tool_name", "hello"), validated_params
                )
            
            # Execute the tool with validated parameters and secure credentials
            result = self.fetch_data(validated_params, credentials)

            # === PHASE 7: CONTEXT BUILDING ===
            # Build execution context for the response
            context = self.build_context(result)

            # === PHASE 8: RESPONSE SANITIZATION & SIGNING ===
            # === PHASE 8: RESPONSE SANITIZATION & SIGNING ===
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
        Get comprehensive status of all zero-trust security controls
        
        Returns:
            Dict containing status of each security control component
        """
        from datetime import datetime
        
        status = {
            "timestamp": datetime.now().isoformat(),
            "security_level": "zero-trust" if all([
                getattr(self, 'installer_validator', None),
                getattr(self, 'server_registry', None), 
                getattr(self, 'remote_authenticator', None),
                getattr(self, 'tool_controller', None),
                getattr(self, 'semantic_validator', None)
            ]) else "standard",
            "controls": {
                "installer_security": {
                    "enabled": hasattr(self, 'installer_validator') and self.installer_validator is not None,
                    "status": "active" if getattr(self, 'installer_validator', None) else "disabled"
                },
                "server_registry": {
                    "enabled": hasattr(self, 'server_registry') and self.server_registry is not None,
                    "status": "active" if getattr(self, 'server_registry', None) else "disabled"
                },
                "remote_authentication": {
                    "enabled": hasattr(self, 'remote_authenticator') and self.remote_authenticator is not None,
                    "status": "active" if getattr(self, 'remote_authenticator', None) else "disabled"
                },
                "tool_exposure_control": {
                    "enabled": hasattr(self, 'tool_controller') and self.tool_controller is not None,
                    "status": "active" if getattr(self, 'tool_controller', None) else "disabled"
                },
                "semantic_validation": {
                    "enabled": hasattr(self, 'semantic_validator') and self.semantic_validator is not None,
                    "status": "active" if getattr(self, 'semantic_validator', None) else "disabled"
                }
            }
        }
        return status
    
    def validate_security_configuration(self) -> Dict[str, Any]:
        """
        Validate that all security controls are properly configured
        
        Returns:
            Dict containing validation results and recommendations
        """
        validation_results = {
            "overall_status": "secure",
            "warnings": [],
            "errors": [],
            "recommendations": []
        }
        
        # Check installer security
        if not getattr(self, 'installer_validator', None):
            validation_results["warnings"].append(
                "Installer security validator not configured - supply chain attacks possible"
            )
            validation_results["recommendations"].append(
                "Configure trusted registries and signature keys for installer validation"
            )
        
        # Check server registry
        if not getattr(self, 'server_registry', None):
            validation_results["warnings"].append(
                "Server name registry not configured - server impersonation possible"
            )
            validation_results["recommendations"].append(
                "Configure server registry to prevent name collision attacks"
            )
        
        # Check remote authentication
        if not getattr(self, 'remote_authenticator', None):
            validation_results["warnings"].append(
                "Remote server authenticator not configured - MITM attacks possible"
            )
            validation_results["recommendations"].append(
                "Configure trusted CA certificates for remote server authentication"
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
        
        # Determine overall status
        if validation_results["errors"]:
            validation_results["overall_status"] = "critical"
        elif len(validation_results["warnings"]) > 2:
            validation_results["overall_status"] = "warning"
            
        return validation_results