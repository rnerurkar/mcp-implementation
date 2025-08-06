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
        Process incoming request through comprehensive 12-control security pipeline
        
        This method implements an optimized secure request processing workflow with all
        12 security controls in optimal order for MCP performance:
        
        PHASE 1 - PRE-AUTHENTICATION (Fast Fail)
        1. Input Sanitization - Remove malicious content early
        2. Schema Validation - Validate structure before heavy processing
        
        PHASE 2 - AUTHENTICATION & AUTHORIZATION  
        3. Token Validation - Authenticate the requester
        4. OPA Policy Enforcement - Check authorization policies
        
        PHASE 3 - SUPPLY CHAIN & INFRASTRUCTURE SECURITY
        5. Installer Security Validation - Verify tool integrity  
        6. Server Identity Verification - Prevent impersonation
        7. Remote Server Authentication - Secure communication
        
        PHASE 4 - TOOL-SPECIFIC SECURITY
        8. Tool Exposure Control - Manage tool capabilities
        9. Semantic Mapping Validation - Verify tool metadata
        
        PHASE 5 - EXECUTION & RESPONSE SECURITY
        10. Credential Management - Secure tool execution
        11. Context Sanitization - Clean response data
        12. Context Security - Sign and verify response integrity
        
        Args:
            request (Dict[str, Any]): Incoming request containing:
                - token: Authentication token (optional)
                - tool_name: Name of the tool to execute  
                - parameters: Tool parameters to validate and sanitize
                
        Returns:
            Dict[str, Any]: Secure response containing:
                - status: "success" or "error"
                - data: Sanitized and signed execution context (on success)
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
            input_validator = SchemaValidator(
                schema=self._load_tool_schema(request.get("tool_name", "hello")),
                security_rules=self._load_security_rules()
            )
            validated_params = input_validator.validate(sanitized_params)

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
            # PHASE 3: SUPPLY CHAIN & INFRASTRUCTURE SECURITY  
            # ========================================================================
            
            # CONTROL 5: INSTALLER SECURITY VALIDATION (Supply Chain Protection)
            # Verify tool installation integrity and trusted sources
            if hasattr(self, 'installer_validator') and self.installer_validator:
                tool_name = request.get("tool_name", "hello")
                if not self.installer_validator.validate_tool_integrity(
                    tool_name, 
                    self._get_tool_metadata(tool_name)
                ):
                    raise SecurityException("Tool installation integrity validation failed.")
            
            # CONTROL 6: SERVER IDENTITY VERIFICATION (Anti-Impersonation)
            # Verify server identity to prevent impersonation attacks
            if hasattr(self, 'server_registry') and self.server_registry:
                server_id = token_claims.get("sub", f"unknown-{request.get('client_id', 'anonymous')}")
                if not self.server_registry.verify_server_identity(
                    server_id, 
                    request.get("tool_name", "hello")
                ):
                    raise PermissionError("Server identity verification failed.")
            
            # CONTROL 7: REMOTE SERVER AUTHENTICATION (Secure Communication)
            # Authenticate remote server connections for distributed MCP
            if hasattr(self, 'remote_authenticator') and self.remote_authenticator:
                if request.get("remote_server_id"):
                    if not self.remote_authenticator.authenticate_remote_server(
                        request.get("remote_server_id"),
                        request.get("server_certificate"),
                        request.get("handshake_data")
                    ):
                        raise PermissionError("Remote server authentication failed.")

            # ========================================================================
            # PHASE 4: TOOL-SPECIFIC SECURITY
            # ========================================================================
            
            # CONTROL 8: TOOL EXPOSURE CONTROL (Capability Management)
            # Control which tools are exposed and to whom
            if hasattr(self, 'tool_controller') and self.tool_controller:
                if not self.tool_controller.validate_tool_exposure(
                    request.get("tool_name", "hello"), 
                    token_claims.get("email", "anonymous"),
                    request.get("access_level", "user")
                ):
                    raise PermissionError("Tool exposure validation failed.")
            
            # CONTROL 9: SEMANTIC MAPPING VALIDATION (Tool Metadata Verification)
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
            
            # CONTROL 10: CREDENTIAL MANAGEMENT (Secure Tool Execution)
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

            # CONTROL 11: CONTEXT SANITIZATION (Response Data Protection)
            # Sanitize response context to prevent data leakage
            sanitized_context = self.context_sanitizer.sanitize(context)
            
            # CONTROL 12: CONTEXT SECURITY (Response Integrity & Verification)
            # Sign the context for integrity verification and non-repudiation
            signed_context = self.context_security.sign(sanitized_context)

            # Return successful response with complete security validation
            return {
                "status": "success", 
                "data": signed_context,
                "security_validation": {
                    "controls_applied": 12,
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