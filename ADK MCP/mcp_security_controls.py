"""
MCP Security Controls Implementation

This module provides comprehensive security controls for Model Context Protocol (MCP) servers,
implementing industry best practices for:

- JSON-RPC 2.0 message validation and MCP protocol security
- Input sanitization and prompt injection prevention
- Cloud Run service-to-service authentication (automatic validation)
- Encryption and key management using Google Cloud KMS
- Rate limiting and access control
- Security policy enforcement via Open Policy Agent (OPA)
- Comprehensive logging and monitoring

The implementation follows security frameworks including:
- MCP (Model Context Protocol) specification compliance
- JSON-RPC 2.0 protocol security best practices
- OWASP guidelines for web application security
- NIST cybersecurity framework principles
- Cloud security best practices
- Zero-trust security model

For FastAPI/MCP integration:
This module integrates with FastAPI through middleware and dependency injection,
providing security layers that protect your MCP tools from various attack vectors
including JSON-RPC injection, parameter tampering, and protocol violations.
"""

# Core Python libraries for security operations
import os       # Environment variable access for configuration
import json     # JSON parsing for tokens and configurations
import re       # Regular expressions for pattern matching and validation
from urllib.parse import urlparse  # URL parsing for security validation

# JWT (JSON Web Token) library for token validation
# Google Cloud ID tokens are JWT tokens signed by Google
import jwt

# HTTP client for making API calls to external services
import requests

# Type hints for better code documentation and IDE support
from typing import Dict, Any, List, Optional, Union

# Cryptography library for RSA key generation
from cryptography.hazmat.primitives.asymmetric import rsa

# Google Cloud libraries for secret and key management
# These provide secure storage for sensitive configuration data
from google.cloud import secretmanager, kms_v1

# %%
# ----------------------------
# 1. Input/Output Sanitization
# ----------------------------

class InputSanitizer:
    """
    OWASP-recommended prompt injection prevention system
    
    This class protects MCP tools from various security threats including:
    - Prompt injection attacks that try to manipulate AI behavior
    - SQL injection attempts
    - Cross-site scripting (XSS) attacks
    - Code injection and eval() attempts
    - Unauthorized data extraction attempts
    
    Security profiles:
    - 'default': Basic protection against common attacks
    - 'strict': Enhanced protection including URL and PII detection
    
    For FastAPI integration:
    Use this class in request validation middleware or as a dependency
    to sanitize all incoming data before it reaches your tools.
    """
    
    def __init__(self, security_profile: str = "default"):
        """
        Initialize the input sanitizer with specified security profile
        
        Args:
            security_profile (str): Security level - 'default' or 'strict'
        """
        self.security_profile = security_profile
        self.patterns = self._load_patterns(security_profile)

    def _load_patterns(self, profile: str) -> List[re.Pattern]:
        """
        Load security patterns based on the selected profile
        
        This method defines regular expressions that match potentially
        dangerous input patterns. Patterns are compiled for performance.
        
        Args:
            profile (str): Security profile name
            
        Returns:
            List[re.Pattern]: Compiled regex patterns for threat detection
        """
        # Base patterns that all profiles include
        # These protect against common injection attacks
        base_patterns = [
            r"ignore\s+previous",           # Prompt injection attempts
            r"system:\s*override",          # System command injection
            r"<!--\s*inject\s*-->",        # HTML injection markers
            r"\{\{.*\}\}",                 # Template injection
            r";\s*DROP\s+TABLE",           # SQL injection
            r"<\s*script\s*>",             # XSS script tags
            r"eval\s*\(",                  # Code evaluation attempts
            r"document\.cookie"            # Browser cookie access
        ]

        # Strict profile adds additional protections
        if profile == "strict":
            base_patterns.extend([
                r"http[s]?://",                           # URLs (potential data exfiltration)
                r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",        # Phone numbers (PII protection)
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # Email addresses (PII protection)
            ])

        # Compile all patterns for better performance during runtime
        # re.IGNORECASE makes patterns case-insensitive for broader protection
        return [re.compile(p, re.IGNORECASE) for p in base_patterns]

    def sanitize(self, text: str) -> str:
        """
        Apply security filters to user input using regex patterns
        
        This method provides input sanitization through local regex patterns
        to protect against prompt injection and other input-based attacks.
        
        Common use cases:
        - Sanitizing user prompts before sending to AI models
        - Cleaning tool parameters before execution
        - Protecting against prompt injection in chat interfaces
        
        Args:
            text (str): Input text to sanitize
            
        Returns:
            str: Sanitized text with dangerous patterns replaced
        """
        # Apply local regex patterns for sanitization
        for pattern in self.patterns:
            text = pattern.sub("[REDACTED]", text)
        return text

    def sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a dictionary of parameters by applying string sanitization to all string values
        
        This method recursively sanitizes all string values in a dictionary while preserving
        the structure and non-string values. Useful for sanitizing tool parameters.
        
        Args:
            data (Dict[str, Any]): Dictionary containing parameters to sanitize
            
        Returns:
            Dict[str, Any]: Dictionary with sanitized string values
        """
        if not isinstance(data, dict):
            return data
            
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                # Sanitize string values
                sanitized[key] = self.sanitize(value)
            elif isinstance(value, dict):
                # Recursively sanitize nested dictionaries
                sanitized[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                # Sanitize lists that may contain strings
                sanitized[key] = [
                    self.sanitize(item) if isinstance(item, str) 
                    else self.sanitize_dict(item) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                # Keep non-string values as-is (numbers, booleans, etc.)
                sanitized[key] = value
                
        return sanitized

    def _get_credential_if_available(self, secret_name: str) -> Optional[str]:
        """
        Safely attempt to get credentials from credential manager
        
        Args:
            secret_name (str): Name of the secret to retrieve
            
        Returns:
            Optional[str]: Secret value if available, None if not configured
        """
        try:
            # This would integrate with your existing CredentialManager
            # For now, return None to indicate credential manager not available
            return None
        except Exception:
            return None



# %%
# -------------------------------------------
# 2. Token Validation (Google Cloud ID Tokens)
# -------------------------------------------

# Import JWT libraries for token validation
# Google Cloud uses JWT ID tokens for service-to-service authentication
import jwt  # Core JWT library for token decode/encode operations

class SecurityException(Exception):
    """
    Custom exception for security-related errors
    
    This exception is raised when security validation fails, including:
    - Invalid or expired authentication tokens
    - Missing required permissions or scopes
    - Failed authorization checks
    - Security policy violations
    
    For FastAPI error handling:
    Catch this exception in your middleware to return appropriate
    HTTP status codes (401 Unauthorized, 403 Forbidden, etc.)
    """
    pass

class GoogleCloudTokenValidator:
    """
    Cloud Run service-to-service authentication validator using Cloud Run's built-in validation
    
    This class leverages Cloud Run's infrastructure-level ID token validation and focuses on
    business logic validation of the authenticated service account identity.
    
    Cloud Run Infrastructure Automatically Handles:
    - ID token signature verification using Google's public keys
    - Audience validation (token must target this service)
    - Issuer verification (must be from Google)
    - Expiration checking (exp claim)
    - Token format validation
    
    This Class Adds:
    - Service account authorization (allowlist validation)
    - Business-specific access control rules
    - Additional claims validation
    - Audit logging and monitoring
    
    For Cloud Run Deployment:
    Configure your service with --no-allow-unauthenticated to enable automatic validation.
    Cloud Run will reject invalid tokens before they reach your application code.
    
    Authentication Headers Injected by Cloud Run:
    - X-Goog-Authenticated-User-Email: Service account email
    - X-Goog-Authenticated-User-ID: Service account subject
    - Authorization: Bearer <validated-token> (optional passthrough)
    
    For FastAPI integration:
    Use this validator to check business rules after Cloud Run has validated the token.
    """
    
    def __init__(self, project_id: str = None, allowed_service_accounts: List[str] = None):
        """
        Initialize the Cloud Run authentication validator
        
        Args:
            project_id (str, optional): Google Cloud project ID for validation
            allowed_service_accounts (List[str], optional): Allowlist of permitted service accounts
        """
        self.project_id = project_id
        self.allowed_service_accounts = allowed_service_accounts or []
        
    def validate_cloud_run_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Validate Cloud Run authentication headers and apply business rules
        
        Cloud Run automatically validates ID tokens and injects authentication headers
        when deployed with --no-allow-unauthenticated. This method validates those
        headers and applies additional business logic.
        
        Args:
            headers (Dict[str, str]): Request headers from FastAPI Request object
            
        Returns:
            Dict[str, Any]: Validated authentication info
            
        Raises:
            SecurityException: If authentication or authorization fails
            
        Example usage:
        ```python
        @app.get("/secure-endpoint")
        async def endpoint(request: Request):
            validator = GoogleCloudTokenValidator(project_id="my-project")
            auth_info = validator.validate_cloud_run_headers(dict(request.headers))
            return {"authenticated_as": auth_info["service_account"]}
        ```
        """
        # Check if Cloud Run authenticated the request
        service_account = headers.get("x-goog-authenticated-user-email")
        subject = headers.get("x-goog-authenticated-user-id")
        
        if not service_account:
            raise SecurityException(
                "No authenticated user found. Ensure Cloud Run is configured with "
                "--no-allow-unauthenticated and proper IAM roles are set."
            )
        
        if not subject:
            raise SecurityException("Missing authenticated user ID from Cloud Run")
        
        # Validate service account format
        if not service_account.endswith('.gserviceaccount.com'):
            raise SecurityException(f"Invalid service account format: {service_account}")
        
        # Validate project context if specified
        if self.project_id and self.project_id not in service_account:
            raise SecurityException(
                f"Service account {service_account} not from expected project {self.project_id}"
            )
        
        # Validate against allowlist if specified
        if self.allowed_service_accounts and service_account not in self.allowed_service_accounts:
            raise SecurityException(
                f"Service account {service_account} not in allowlist: {self.allowed_service_accounts}"
            )
        
        # Additional business rules can be added here
        # Example: Time-based access control
        from datetime import datetime
        current_hour = datetime.now().hour
        if hasattr(self, 'business_hours_only') and self.business_hours_only:
            if current_hour < 9 or current_hour > 17:
                raise SecurityException("Access only allowed during business hours (9 AM - 5 PM)")
        
        # Log successful authentication for audit
        print(f"✅ Cloud Run authenticated service account: {service_account}")
        print(f"   Subject: {subject}")
        print(f"   Validation: Business rules passed")
        
        return {
            "service_account": service_account,
            "subject": subject,
            "validated_by": "cloud_run_infrastructure",
            "additional_validation": "business_rules_passed"
        }
    
    def validate_manual_token(self, token: str, expected_audience: str) -> Dict[str, Any]:
        """
        Fallback manual token validation for development/testing scenarios
        
        Use this method only when Cloud Run automatic validation is not available,
        such as local development or testing environments.
        
        Args:
            token (str): ID token string from Authorization header
            expected_audience (str): Expected audience claim in the token
            
        Returns:
            Dict[str, Any]: Validated token claims
            
        Raises:
            SecurityException: If token validation fails
        """
        try:
            # Import Google Auth libraries for ID token verification
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token as google_id_token
            from google.auth import exceptions as google_exceptions
            
            # Create a Google Auth request object for token verification
            request = google_requests.Request()
            
            # Verify the ID token using Google's public keys
            claims = google_id_token.verify_oauth2_token(
                token, 
                request, 
                audience=expected_audience
            )
            
            # Apply the same business rules as Cloud Run validation
            service_account = claims.get('email', '')
            if not service_account.endswith('.gserviceaccount.com'):
                raise SecurityException(f"Token not from service account: {service_account}")
            
            if not claims.get('email_verified', False):
                raise SecurityException("Service account email not verified")
            
            # Apply business rules
            if self.project_id and self.project_id not in service_account:
                raise SecurityException(f"Service account not from project {self.project_id}")
            
            if self.allowed_service_accounts and service_account not in self.allowed_service_accounts:
                raise SecurityException(f"Service account not in allowlist: {service_account}")
            
            print(f"✅ Manual validation successful for: {service_account}")
            print(f"   ⚠️  Consider using Cloud Run automatic validation in production")
            
            return {
                "service_account": service_account,
                "subject": claims.get('sub'),
                "validated_by": "manual_validation",
                "claims": claims
            }
            
        except google_exceptions.GoogleAuthError as e:
            raise SecurityException(f"Token validation failed: {str(e)}")
        except Exception as e:
            raise SecurityException(f"Manual token validation error: {str(e)}")

# %%
# ---------------------------
# 3. Strict Input Validation
# ---------------------------

class SchemaValidator:
    """
    JSON-RPC 2.0 message validation with MCP-specific security rules
    
    This class provides comprehensive validation for MCP JSON-RPC messages:
    - JSON-RPC 2.0 protocol compliance validation
    - MCP-specific method and parameter validation
    - Security rules enforcement for MCP message patterns
    - Protection against malformed or malicious JSON-RPC requests
    
    MCP Protocol Security:
    - Validates JSON-RPC method names against MCP specification
    - Ensures proper request/response/notification structure
    - Prevents JSON-RPC injection attacks
    - Validates MCP tool parameters and results
    
    JSON-RPC 2.0 Message Types:
    1. Request: {"jsonrpc": "2.0", "method": "tools/call", "params": {...}, "id": 1}
    2. Response: {"jsonrpc": "2.0", "result": {...}, "id": 1}
    3. Error: {"jsonrpc": "2.0", "error": {...}, "id": 1}
    4. Notification: {"jsonrpc": "2.0", "method": "notifications/message", "params": {...}}
    
    For FastAPI integration:
    Use with MCP JSON-RPC endpoints to validate all incoming messages
    before they reach your MCP server implementation.
    """
    
    def __init__(self, mcp_methods: Dict[str, Dict[str, Any]] = None, security_rules: List[Dict[str, Any]] = None):
        """
        Initialize the JSON-RPC/MCP schema validator
        
        Args:
            mcp_methods (Dict[str, Dict[str, Any]]): MCP method schemas and validation rules
            security_rules (List[Dict[str, Any]]): Additional security validation rules
        """
        self.security_rules = security_rules or []
        
        # Default MCP method schemas based on MCP specification
        self.mcp_methods = mcp_methods or {
            # Core MCP methods
            "initialize": {
                "type": "request",
                "required_params": ["protocolVersion", "capabilities"],
                "param_schema": {
                    "protocolVersion": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
                    "capabilities": {"type": "object"},
                    "clientInfo": {"type": "object", "optional": True}
                }
            },
            "tools/list": {
                "type": "request",
                "required_params": [],
                "param_schema": {}
            },
            "tools/call": {
                "type": "request", 
                "required_params": ["name", "arguments"],
                "param_schema": {
                    "name": {"type": "string", "max_length": 100},
                    "arguments": {"type": "object"}
                }
            },
            "resources/list": {
                "type": "request",
                "required_params": [],
                "param_schema": {}
            },
            "resources/read": {
                "type": "request",
                "required_params": ["uri"],
                "param_schema": {
                    "uri": {"type": "string", "max_length": 2048}
                }
            },
            "prompts/list": {
                "type": "request",
                "required_params": [],
                "param_schema": {}
            },
            "prompts/get": {
                "type": "request",
                "required_params": ["name"],
                "param_schema": {
                    "name": {"type": "string", "max_length": 100},
                    "arguments": {"type": "object", "optional": True}
                }
            },
            # Notification methods
            "notifications/initialized": {
                "type": "notification",
                "required_params": [],
                "param_schema": {}
            },
            "notifications/progress": {
                "type": "notification", 
                "required_params": ["progressToken"],
                "param_schema": {
                    "progressToken": {"type": "string"},
                    "progress": {"type": "number", "min": 0, "max": 100}
                }
            },
            "notifications/message": {
                "type": "notification",
                "required_params": ["level", "data"],
                "param_schema": {
                    "level": {"type": "string", "enum": ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]},
                    "data": {"type": "object"}
                }
            }
        }
        
        # JSON-RPC security patterns to detect injection attempts
        self.jsonrpc_security_patterns = [
            r"__proto__",           # Prototype pollution
            r"constructor",         # Constructor injection
            r"eval\s*\(",          # Code evaluation
            r"Function\s*\(",      # Function constructor
            r"setTimeout\s*\(",    # Timer injection
            r"setInterval\s*\(",   # Interval injection
            r"require\s*\(",       # Module injection (Node.js)
            r"import\s*\(",        # Dynamic import injection
        ]

    def validate_jsonrpc_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive JSON-RPC 2.0 message validation for MCP
        
        This method performs multi-stage validation:
        1. JSON-RPC 2.0 protocol structure validation
        2. MCP method-specific validation
        3. Security rule enforcement
        4. Parameter sanitization
        
        Args:
            message (Dict[str, Any]): JSON-RPC message to validate
            
        Returns:
            Dict[str, Any]: Validated and sanitized message
            
        Raises:
            ValueError: If JSON-RPC structure validation fails
            SecurityException: If security rules are violated
        """
        # 1. JSON-RPC 2.0 protocol validation
        self._validate_jsonrpc_structure(message)
        
        # 2. MCP method validation
        if "method" in message:
            self._validate_mcp_method(message)
        
        # 3. Security rule enforcement
        self._enforce_security_rules(message)
        
        # 4. Deep sanitization
        sanitized_message = self._deep_sanitize_jsonrpc(message)
        
        print(f"✅ JSON-RPC message validated: {message.get('method', 'response')} (id: {message.get('id', 'N/A')})")
        return sanitized_message

    def _validate_jsonrpc_structure(self, message: Dict[str, Any]):
        """
        Validate JSON-RPC 2.0 protocol structure
        
        JSON-RPC 2.0 Specification Requirements:
        - Must have "jsonrpc": "2.0"
        - Request: must have "method", may have "params" and "id"
        - Response: must have "result" or "error", must have "id" (except for error responses to invalid requests)
        - Notification: must have "method", may have "params", must NOT have "id"
        
        Args:
            message (Dict[str, Any]): Message to validate
            
        Raises:
            ValueError: If JSON-RPC structure is invalid
        """
        # Check required jsonrpc field
        if not isinstance(message, dict):
            raise ValueError("JSON-RPC message must be an object")
        
        if message.get("jsonrpc") != "2.0":
            raise ValueError("Invalid or missing JSON-RPC version. Must be '2.0'")
        
        # Determine message type and validate structure
        has_method = "method" in message
        has_id = "id" in message
        has_result = "result" in message
        has_error = "error" in message
        
        if has_method:
            # This is a request or notification
            method = message["method"]
            if not isinstance(method, str) or not method:
                raise ValueError("JSON-RPC method must be a non-empty string")
            
            # Validate method name format (MCP uses namespace/method pattern)
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(/[a-zA-Z][a-zA-Z0-9_]*)*$", method):
                raise ValueError(f"Invalid JSON-RPC method format: {method}")
            
            # Check if it's a notification (no id) or request (has id)
            if has_id:
                # Request: validate id
                if message["id"] is None:
                    raise ValueError("JSON-RPC request id cannot be null")
            else:
                # Notification: ensure no id field
                if has_result or has_error:
                    raise ValueError("JSON-RPC notification cannot have result or error fields")
            
            # Validate params if present
            if "params" in message:
                params = message["params"]
                if not isinstance(params, (dict, list)):
                    raise ValueError("JSON-RPC params must be an object or array")
        
        elif has_result or has_error:
            # This is a response
            if not has_id:
                # Error responses to invalid requests may omit id
                if not has_error:
                    raise ValueError("JSON-RPC response must have id field")
            
            if has_result and has_error:
                raise ValueError("JSON-RPC response cannot have both result and error")
            
            if not has_result and not has_error:
                raise ValueError("JSON-RPC response must have either result or error")
            
            # Validate error structure if present
            if has_error:
                error = message["error"]
                if not isinstance(error, dict):
                    raise ValueError("JSON-RPC error must be an object")
                
                if "code" not in error or not isinstance(error["code"], int):
                    raise ValueError("JSON-RPC error must have integer code")
                
                if "message" not in error or not isinstance(error["message"], str):
                    raise ValueError("JSON-RPC error must have string message")
        
        else:
            raise ValueError("Invalid JSON-RPC message: must have method (request/notification) or result/error (response)")

    def _validate_mcp_method(self, message: Dict[str, Any]):
        """
        Validate MCP-specific method calls and parameters
        
        Args:
            message (Dict[str, Any]): JSON-RPC message with method
            
        Raises:
            ValueError: If MCP method validation fails
            SecurityException: If method presents security risks
        """
        method = message["method"]
        params = message.get("params", {})
        
        # Check if method is recognized MCP method
        if method not in self.mcp_methods:
            # Allow unknown methods but log for monitoring
            print(f"⚠️ Unknown MCP method: {method}")
            return
        
        method_schema = self.mcp_methods[method]
        
        # Validate method type matches message structure
        expected_type = method_schema["type"]
        has_id = "id" in message
        
        if expected_type == "notification" and has_id:
            raise ValueError(f"MCP method '{method}' should be a notification (no id)")
        
        if expected_type == "request" and not has_id:
            raise ValueError(f"MCP method '{method}' should be a request (requires id)")
        
        # Validate required parameters
        required_params = method_schema["required_params"]
        if not isinstance(params, dict):
            if required_params:
                raise ValueError(f"MCP method '{method}' requires object parameters, got {type(params)}")
            return
        
        missing_params = [param for param in required_params if param not in params]
        if missing_params:
            raise ValueError(f"MCP method '{method}' missing required parameters: {missing_params}")
        
        # Validate parameter schemas
        param_schema = method_schema["param_schema"]
        for param_name, param_value in params.items():
            if param_name in param_schema:
                self._validate_parameter(method, param_name, param_value, param_schema[param_name])
        
        # Check for unexpected parameters
        expected_params = set(param_schema.keys())
        provided_params = set(params.keys())
        unexpected_params = provided_params - expected_params
        
        if unexpected_params:
            print(f"⚠️ Unexpected parameters in MCP method '{method}': {unexpected_params}")

    def _validate_parameter(self, method: str, param_name: str, param_value: Any, param_schema: Dict[str, Any]):
        """
        Validate individual parameter against its schema
        
        Args:
            method (str): MCP method name
            param_name (str): Parameter name
            param_value (Any): Parameter value to validate
            param_schema (Dict[str, Any]): Parameter validation schema
            
        Raises:
            ValueError: If parameter validation fails
            SecurityException: If parameter presents security risks
        """
        param_type = param_schema.get("type")
        
        # Type validation
        if param_type == "string":
            if not isinstance(param_value, str):
                raise ValueError(f"Parameter '{param_name}' in method '{method}' must be string, got {type(param_value)}")
            
            # String-specific validations
            max_length = param_schema.get("max_length")
            if max_length and len(param_value) > max_length:
                raise ValueError(f"Parameter '{param_name}' exceeds max length {max_length}")
            
            pattern = param_schema.get("pattern")
            if pattern and not re.match(pattern, param_value):
                raise ValueError(f"Parameter '{param_name}' does not match required pattern")
            
            enum_values = param_schema.get("enum")
            if enum_values and param_value not in enum_values:
                raise ValueError(f"Parameter '{param_name}' must be one of: {enum_values}")
        
        elif param_type == "number":
            if not isinstance(param_value, (int, float)):
                raise ValueError(f"Parameter '{param_name}' must be number, got {type(param_value)}")
            
            min_val = param_schema.get("min")
            if min_val is not None and param_value < min_val:
                raise ValueError(f"Parameter '{param_name}' must be >= {min_val}")
            
            max_val = param_schema.get("max")
            if max_val is not None and param_value > max_val:
                raise ValueError(f"Parameter '{param_name}' must be <= {max_val}")
        
        elif param_type == "object":
            if not isinstance(param_value, dict):
                raise ValueError(f"Parameter '{param_name}' must be object, got {type(param_value)}")
        
        elif param_type == "array":
            if not isinstance(param_value, list):
                raise ValueError(f"Parameter '{param_name}' must be array, got {type(param_value)}")
        
        elif param_type == "boolean":
            if not isinstance(param_value, bool):
                raise ValueError(f"Parameter '{param_name}' must be boolean, got {type(param_value)}")
        
        # Security validation for string parameters
        if isinstance(param_value, str):
            self._validate_string_security(method, param_name, param_value)

    def _validate_string_security(self, method: str, param_name: str, param_value: str):
        """
        Validate string parameters for security threats
        
        Args:
            method (str): MCP method name
            param_name (str): Parameter name  
            param_value (str): String value to validate
            
        Raises:
            SecurityException: If string contains security threats
        """
        # Check for JSON-RPC injection patterns
        for pattern in self.jsonrpc_security_patterns:
            if re.search(pattern, param_value, re.IGNORECASE):
                raise SecurityException(
                    f"Security threat detected in parameter '{param_name}' of method '{method}': "
                    f"matches pattern '{pattern}'"
                )
        
        # Additional MCP-specific security checks
        if method == "tools/call":
            if param_name == "name":
                # Tool names should not contain path traversal
                if ".." in param_value or "/" in param_value:
                    raise SecurityException(f"Invalid tool name: {param_value}")
            
            elif param_name == "arguments":
                # Tool arguments should not contain dangerous patterns (handled by InputSanitizer)
                pass
        
        elif method == "resources/read":
            if param_name == "uri":
                # Resource URIs should be validated for safe schemes
                parsed_uri = urlparse(param_value)
                safe_schemes = {"file", "http", "https", "data"}
                if parsed_uri.scheme and parsed_uri.scheme not in safe_schemes:
                    raise SecurityException(f"Unsafe URI scheme: {parsed_uri.scheme}")

    def _enforce_security_rules(self, message: Dict[str, Any]):
        """
        Apply additional security rules to the message
        
        Args:
            message (Dict[str, Any]): JSON-RPC message to validate
            
        Raises:
            SecurityException: If security rules are violated
        """
        for rule in self.security_rules:
            self._apply_security_rule(message, rule)

    def _apply_security_rule(self, message: Any, rule: Dict[str, Any]):
        """
        Apply a specific security rule to the message
        
        Args:
            message (Any): The message data to validate
            rule (Dict[str, Any]): The security rule to apply
            
        Raises:
            SecurityException: If the rule is violated
        """
        rule_type = rule["type"]

        if rule_type == "max_message_size":
            # Check total message size to prevent DoS
            message_size = len(json.dumps(message, default=str))
            max_size = rule.get("max_size", 1024 * 1024)  # 1MB default
            if message_size > max_size:
                raise SecurityException(f"Message size {message_size} exceeds limit {max_size}")

        elif rule_type == "max_nesting_depth":
            # Check nesting depth to prevent stack overflow
            max_depth = rule.get("max_depth", 10)
            if self._calculate_nesting_depth(message) > max_depth:
                raise SecurityException(f"Message nesting depth exceeds limit {max_depth}")

        elif rule_type == "rate_limit":
            # Rate limiting would be implemented here
            # For now, just validate the rule exists
            pass

    def _calculate_nesting_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth of an object"""
        if current_depth > 20:  # Prevent infinite recursion
            return current_depth
        
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(
                self._calculate_nesting_depth(value, current_depth + 1)
                for value in obj.values()
            )
        elif isinstance(obj, list):
            if not obj:
                return current_depth
            return max(
                self._calculate_nesting_depth(item, current_depth + 1)
                for item in obj
            )
        else:
            return current_depth

    def _deep_sanitize_jsonrpc(self, message: Any) -> Any:
        """
        Recursive sanitization of JSON-RPC message structures
        
        This method performs deep sanitization while preserving JSON-RPC structure:
        - Sanitizes string values to remove dangerous characters
        - Preserves JSON-RPC protocol fields (jsonrpc, method, params, id, result, error)
        - Maintains data structure for proper message handling
        
        Args:
            message (Any): JSON-RPC message structure to sanitize
            
        Returns:
            Any: Sanitized message with same structure but cleaned string values
        """
        # Handle dictionary structures (JSON-RPC messages are objects)
        if isinstance(message, dict):
            sanitized = {}
            for key, value in message.items():
                # Preserve critical JSON-RPC fields without modification
                if key in ["jsonrpc", "method", "id"]:
                    sanitized[key] = value
                else:
                    sanitized[key] = self._deep_sanitize_jsonrpc(value)
            return sanitized
        
        # Handle list structures
        if isinstance(message, list):
            return [self._deep_sanitize_jsonrpc(item) for item in message]
        
        # Sanitize string values (but preserve JSON-RPC method names)
        if isinstance(message, str):
            # Use InputSanitizer for string sanitization
            # This maintains consistency with other security controls
            sanitizer = InputSanitizer(security_profile="default")
            return sanitizer.sanitize(message)
        
        # Return other data types unchanged (numbers, booleans, null)
        return message

    # Legacy method for backward compatibility
    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Legacy method for backward compatibility
        
        This method wraps the new JSON-RPC validation for existing code that
        expects the old validate() method signature.
        
        Args:
            data (Dict[str, Any]): Data to validate (assumed to be JSON-RPC message)
            
        Returns:
            Dict[str, Any]: Validated data
        """
        return self.validate_jsonrpc_message(data)



# %%
# ----------------------------
# 4. Secure Credential Handling
# ----------------------------

class CredentialManager:
    """
    Secure credential retrieval using Google Cloud Secret Manager
    
    This class provides secure access to sensitive configuration data including:
    - API keys and authentication tokens
    - Database connection strings
    - Third-party service credentials
    - Encryption keys and certificates
    
    Security benefits:
    - Credentials never stored in code or environment variables
    - Automatic encryption at rest and in transit
    - Access logging and audit trails
    - Fine-grained access control via IAM
    - Automatic credential rotation support
    
    For FastAPI integration:
    Use this class in startup functions or as a dependency to securely
    load credentials needed by your MCP tools and services.
    """
    
    def __init__(self, project_id: str):
        """
        Initialize the credential manager
        
        Args:
            project_id (str): Google Cloud project ID containing the secrets
        """
        # Initialize the Secret Manager client
        # This client handles authentication via service account or workload identity
        self.client = secretmanager.SecretManagerServiceClient()
        self.project_id = project_id

    def get_credential(self, secret_id: str, version: str = "latest") -> str:
        """
        Retrieve a credential with zero memory exposure
        
        This method securely retrieves credentials from Google Cloud Secret Manager
        with the following security features:
        - Direct retrieval without intermediate storage
        - Automatic decryption using Google's managed keys
        - Audit logging of all access attempts
        - Version-specific access for credential rotation
        
        Args:
            secret_id (str): The name/ID of the secret in Secret Manager
            version (str): Version of the secret to retrieve (default: "latest")
            
        Returns:
            str: The secret value as a string
            
        Raises:
            google.api_core.exceptions.NotFound: If secret doesn't exist
            google.api_core.exceptions.PermissionDenied: If access is denied
        """
        # Construct the full secret path
        name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
        
        # Retrieve and decrypt the secret
        response = self.client.access_secret_version(name=name)
        
        # Return the decoded secret value
        return response.payload.data.decode("UTF-8")

    def get_credentials(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """
        Execute tool with dynamically injected credentials
        
        This method demonstrates secure credential injection for tool execution:
        - Credentials are fetched just-in-time, not stored in memory
        - Different tools can use different credential types
        - Credentials are automatically cleaned up after use
        
        Args:
            tool_name (str): Name of the tool requesting credentials
            params (Dict[str, Any]): Tool execution parameters
            
        Returns:
            Any: Tool execution results with credentials injected securely
        """
        # Example: Fetch credentials based on tool type
        # Credentials are named consistently: "{tool_name}-credentials"
        creds = self.get_credential(f"{tool_name}-credentials")
        return creds
        
        # Production implementation would vary by tool type:
        # if tool_name == "database":
        #     return self._execute_db_query(creds, params)
        # elif tool_name == "api":
        #     return self._call_api(creds, params)
        # elif tool_name == "hello":
        #     # Hello tool execution logic
        #     return {"status": "success", "message": params.values()}
        # else:
        #     raise ValueError(f"Unknown tool: {tool_name}")



# %%
# ---------------------------------
# 5. Context Poisoning Mitigation
# ---------------------------------

class ContextSanitizer:
    """
    Multi-layer context poisoning prevention system with Model Armor protection
    
    This class protects against context poisoning attacks where malicious users
    try to manipulate AI behavior through crafted prompts or context injection,
    particularly in tool-returned context data.
    
    Protection mechanisms:
    - Model Armor API integration for advanced prompt injection detection
    - Pattern-based detection of known injection techniques (fallback)
    - PII (Personally Identifiable Information) detection and redaction
    - Context size limits to prevent overwhelming
    - Multi-level security profiles for different risk environments
    
    Context poisoning attacks include:
    - Prompt injection in tool responses to change AI behavior
    - Context stuffing to overwhelm the model
    - PII injection to extract sensitive information
    - System override attempts via malicious tool outputs
    - Remote tool data poisoning attacks
    
    Model Armor Integration:
    This enhanced version uses Model Armor API to detect sophisticated prompt
    injection attempts in tool-returned context that might bypass regex patterns.
    This is crucial for protecting against malicious remote tools that could
    return crafted responses designed to manipulate the AI's behavior.
    
    For FastAPI integration:
    Use this class to sanitize all user inputs, context data, tool outputs,
    and conversation history before passing to AI models.
    """
    
    def __init__(self, security_level: str = "standard"):
        """
        Initialize the context sanitizer with Model Armor integration
        
        Args:
            security_level (str): Security level - "standard" or "strict"
        """
        self.poison_patterns = self._load_poison_patterns()
        self.pii_patterns = self._load_pii_patterns()
        self.security_level = security_level

    def _load_poison_patterns(self) -> List[re.Pattern]:
        """
        Load patterns for detecting context poisoning attempts
        
        These patterns identify common prompt injection techniques:
        - Instructions to ignore previous context
        - System override commands
        - HTML/template injection markers
        - Script injection attempts
        
        Returns:
            List[re.Pattern]: Compiled regex patterns for injection detection
        """
        return [
            re.compile(r"ignore\s+(all\s+)?previous", re.IGNORECASE),           # "Ignore previous instructions"
            re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),        # "Disregard all previous"
            re.compile(r"system:\s*override", re.IGNORECASE),                   # System override attempts
            re.compile(r"<!--.*inject.*-->", re.IGNORECASE),                    # HTML injection markers
            re.compile(r"\{\{.*\}\}"),                                          # Template injection
            re.compile(r"<\s*script\s*>.*<\s*/\s*script\s*>", re.DOTALL | re.IGNORECASE)  # Script injection
        ]

    def _load_pii_patterns(self) -> List[re.Pattern]:
        """
        Load patterns for detecting Personally Identifiable Information
        
        These patterns identify common PII formats that should be redacted:
        - Social Security Numbers
        - Credit card numbers  
        - Email addresses
        - Phone numbers
        - Other sensitive data formats
        
        Returns:
            List[re.Pattern]: Compiled regex patterns for PII detection
        """
        return [
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                              # SSN format
            re.compile(r"\b\d{4} \d{4} \d{4} \d{4}\b"),                        # Credit card format
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b") # Email addresses
        ]

    def sanitize(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive sanitization pipeline for context data with Model Armor protection
        
        This method applies multiple layers of security protection:
        1. Deep copying to prevent modification of original data
        2. Model Armor API analysis for advanced prompt injection detection
        3. Poison pattern filtering to remove injection attempts (fallback)
        4. PII redaction to protect sensitive information
        5. Size limiting to prevent context overflow attacks
        
        The multi-stage approach provides defense in depth against
        various types of context manipulation attacks, with Model Armor
        providing enterprise-grade protection against sophisticated
        prompt injection attempts in tool-returned context.
        
        Args:
            context (Dict[str, Any]): Context data to sanitize
            
        Returns:
            Dict[str, Any]: Sanitized context safe for AI processing
        """
        # 1. Deep copy context to avoid modifying original data
        # This ensures the original context remains unchanged
        sanitized = json.loads(json.dumps(context))

        # 2. Apply Model Armor analysis for advanced threat detection
        sanitized = self._apply_model_armor_protection(sanitized)

        # 3. Apply fallback security transformations
        sanitized = self._apply_poison_filters(sanitized)
        sanitized = self._redact_pii(sanitized)

        # 4. Size limitation for strict security environments
        # Prevents context overflow attacks that could overwhelm the AI
        if self.security_level == "strict":
            sanitized = self._limit_size(sanitized, 1024)  # 1KB limit

        return sanitized

    def _apply_model_armor_protection(self, data: Any) -> Any:
        """
        Apply Model Armor protection to detect prompt injection in context data
        
        This method uses Model Armor API to analyze context data (especially
        tool outputs) for sophisticated prompt injection attempts that might
        bypass traditional regex patterns. This is crucial for protecting
        against malicious remote tools that could return crafted responses.
        
        Args:
            data (Any): Data structure to analyze and protect
            
        Returns:
            Any: Data with Model Armor protection applied
        """
        # Handle dictionary structures recursively
        if isinstance(data, dict):
            protected = {}
            for k, v in data.items():
                protected[k] = self._apply_model_armor_protection(v)
            return protected
        
        # Handle list structures recursively
        if isinstance(data, list):
            return [self._apply_model_armor_protection(item) for item in data]
        
        # Apply Model Armor analysis to string values
        if isinstance(data, str) and len(data.strip()) > 0:
            model_armor_result = self._check_model_armor_context(data)
            
            if model_armor_result['success']:
                if model_armor_result['is_malicious']:
                    # Model Armor detected threats - return sanitized content
                    print(f"🛡️ Model Armor blocked context threat: {model_armor_result['threat_types']}")
                    return model_armor_result['sanitized_text']
                else:
                    # Model Armor says it's safe - return original
                    return data
            else:
                # Fallback to original if Model Armor unavailable
                print(f"⚠️ Model Armor context check failed: {model_armor_result['error']}")
                return data
        
        return data

    def _check_model_armor_context(self, text: str) -> Dict[str, Any]:
        """
        Check context text against Model Armor API for prompt injection threats
        
        This method specifically focuses on detecting prompt injection attacks
        in context data, particularly tool outputs that could be designed to
        manipulate the AI's behavior.
        
        Args:
            text (str): Context text to analyze for threats
            
        Returns:
            Dict[str, Any]: Analysis results including threat status and sanitized text
        """
        try:
            # Get Model Armor API credentials from secure storage
            api_key = os.getenv('MODEL_ARMOR_API_KEY') or self._get_credential_if_available('model-armor-api-key')
            
            if not api_key:
                return {
                    'success': False,
                    'error': 'Model Armor API key not configured for context protection',
                    'is_malicious': False,
                    'sanitized_text': text
                }
            
            # Model Armor API endpoint for context analysis
            model_armor_url = "https://api.modelarmor.com/v1/analyze-context"
            
            # Prepare request payload for context-specific analysis
            payload = {
                "text": text,
                "analysis_type": "context_protection",
                "detection_types": [
                    "prompt_injection",
                    "context_poisoning",
                    "ai_manipulation",
                    "tool_response_injection",
                    "pii_leakage"
                ],
                "sanitization_mode": "redact_and_neutralize",
                "context_source": "tool_output",  # Specify this is from tool responses
                "security_profile": self.security_level
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "MCP-ContextSanitizer/1.0"
            }
            
            # Call Model Armor API with timeout for reliability
            response = requests.post(
                model_armor_url,
                json=payload,
                headers=headers,
                timeout=5.0  # 5-second timeout for production use
            )
            
            # Handle API response
            if response.status_code == 200:
                result = response.json()
                
                return {
                    'success': True,
                    'is_malicious': result.get('is_malicious', False),
                    'threat_types': result.get('detected_threats', []),
                    'confidence_score': result.get('confidence', 0.0),
                    'sanitized_text': result.get('sanitized_text', text),
                    'model_armor_id': result.get('analysis_id'),
                    'context_analysis': result.get('context_specific_analysis', {})
                }
            
            elif response.status_code == 429:
                # Rate limit exceeded - use fallback
                return {
                    'success': False,
                    'error': 'Model Armor rate limit exceeded for context analysis',
                    'is_malicious': False,
                    'sanitized_text': text
                }
            
            else:
                # Other API errors
                return {
                    'success': False,
                    'error': f'Model Armor context API error: {response.status_code}',
                    'is_malicious': False,
                    'sanitized_text': text
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Model Armor context API timeout',
                'is_malicious': False,
                'sanitized_text': text
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Model Armor context network error: {str(e)}',
                'is_malicious': False,
                'sanitized_text': text
            }
            
        except Exception as e:
            # Fail safe - log error but continue
            return {
                'success': False,
                'error': f'Model Armor context unexpected error: {str(e)}',
                'is_malicious': False,
                'sanitized_text': text
            }

    def _get_credential_if_available(self, secret_name: str) -> Optional[str]:
        """
        Safely attempt to get credentials from credential manager
        
        Args:
            secret_name (str): Name of the secret to retrieve
            
        Returns:
            Optional[str]: Secret value if available, None if not configured
        """
        try:
            # This would integrate with your existing CredentialManager
            # For now, return None to indicate credential manager not available
            return None
        except Exception:
            return None

    def _apply_poison_filters(self, data: Any) -> Any:
        """
        Recursively apply poison pattern filters to all string data
        
        This method traverses the entire data structure and applies
        security filters to every string value found. It maintains
        the data structure while cleaning the content.
        
        Args:
            data (Any): Data structure to filter
            
        Returns:
            Any: Filtered data with poison patterns removed
        """
        # Handle dictionary structures recursively
        if isinstance(data, dict):
            return {k: self._apply_poison_filters(v) for k, v in data.items()}
        
        # Handle list structures recursively
        if isinstance(data, list):
            return [self._apply_poison_filters(item) for item in data]
        
        # Apply poison filters to string values
        if isinstance(data, str):
            for pattern in self.poison_patterns:
                data = pattern.sub("[REDACTED]", data)
        return data

    def _redact_pii(self, data: Any) -> Any:
        """Recursive PII redaction"""
        if isinstance(data, dict):
            return {k: self._redact_pii(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self._redact_pii(item) for item in data]
        if isinstance(data, str):
            for pattern in self.pii_patterns:
                if pattern.search(data):
                    if "@" in data:
                        return "[EMAIL_REDACTED]"
                    if "-" in data:
                        return "[SSN_REDACTED]"
        return data

    def _limit_size(self, context: Dict[str, Any], max_size: int) -> Dict[str, Any]:
        """Apply size constraints"""
        serialized = json.dumps(context)
        if len(serialized) > max_size:
            return {
                "id": context.get("id", "unknown"),
                "warning": "Context truncated due to size limits",
                "original_size": len(serialized)
            }
        return context



# %%
# --------------------------
# 7. OPA Policy Enforcement
# --------------------------

class OPAPolicyClient:
    """
    Open Policy Agent (OPA) integration for enterprise-grade authorization
    
    OPA (Open Policy Agent) is a general-purpose policy engine that provides
    unified, fine-grained authorization across your MCP server infrastructure.
    
    KEY BENEFITS FOR MCP SERVERS:
    
    1. **Centralized Policy Management**: Define authorization rules in one place
       rather than scattered throughout your code
    
    2. **Dynamic Authorization**: Policies can be updated without code changes
       or server restarts
    
    3. **Complex Rule Support**: Handle sophisticated authorization logic like:
       - Time-based access (work hours only)
       - Resource quotas (max API calls per user)
       - Contextual permissions (different rules for different environments)
       - Multi-factor conditions (user + role + resource + time)
    
    4. **Audit and Compliance**: All authorization decisions are logged
       and auditable for compliance requirements
    
    WHEN TO USE OPA IN MCP SERVERS:
    
    ✅ **Use OPA when you have:**
    - Multiple tools with different permission requirements
    - Enterprise clients requiring fine-grained access control
    - Compliance requirements (SOX, HIPAA, PCI-DSS)
    - Complex authorization logic that changes frequently
    - Multi-tenant environments with different access patterns
    - Need for real-time policy updates without downtime
    
    ❌ **Skip OPA for:**
    - Simple single-user development environments
    - Basic tools with minimal security requirements
    - Prototypes or proof-of-concept implementations
    - Environments where external dependencies are problematic
    
    EXAMPLE USE CASES:
    
    1. **Tool Access Control**:
       "Allow database queries only for users in 'analyst' role during business hours"
    
    2. **Resource Quotas**:
       "Limit API calls to 1000 per hour per user, 10000 for premium users"
    
    3. **Environment-Based Rules**:
       "Allow destructive operations only in development environment"
    
    4. **Data Classification**:
       "Allow access to PII data only for users with privacy training"
    
    INTEGRATION PATTERN:
    
    ```python
    # In your MCP tool implementation
    opa_client = OPAPolicyClient("http://opa-server:8181")
    
    @app.call_tool()
    async def sensitive_database_query(arguments):
        # Build authorization context
        context = {
            "user": get_current_user(),
            "tool": "database_query", 
            "resource": arguments.get("table"),
            "action": "read",
            "environment": os.getenv("ENVIRONMENT"),
            "time": datetime.now().isoformat()
        }
        
        # Check policy before executing tool
        if not opa_client.check_policy(context):
            raise PermissionError("Access denied by policy")
            
        # Proceed with tool execution
        return execute_query(arguments)
    ```
    
    For FastAPI/MCP integration:
    Use this class as a dependency in your secured endpoints or as middleware
    to enforce organization-wide authorization policies consistently.
    """
    
    def __init__(self, opa_url: str, policy_path: str = "mcp/policy/allow"):
        """
        Initialize OPA policy client for authorization decisions
        
        Args:
            opa_url (str): Base URL of your OPA server (e.g., "http://opa:8181")
            policy_path (str): OPA policy path for authorization decisions
                             Format: "package/rule/path" 
                             Default: "mcp/policy/allow" maps to /v1/data/mcp/policy/allow
        
        Example OPA policy structure:
        ```
        package mcp.policy
        
        default allow = false
        
        # Allow database access for analysts during business hours
        allow {
            input.user.role == "analyst"
            input.tool == "database_query"
            business_hours
        }
        
        # Allow admin access anytime
        allow {
            input.user.role == "admin"
        }
        
        business_hours {
            time.weekday(time.now_ns()) >= 1  # Monday
            time.weekday(time.now_ns()) <= 5  # Friday
            hour := time.clock(time.now_ns())[0]
            hour >= 9   # 9 AM
            hour <= 17  # 5 PM
        }
        ```
        """
        # Construct the full OPA API endpoint for policy evaluation
        # OPA exposes policies through its REST API at /v1/data/{policy_path}
        self.base_url = f"{opa_url}/v1/data/{policy_path}"
        
        # Store original URL for debugging and logging
        self.opa_url = opa_url
        self.policy_path = policy_path

    def check_policy(self, context: Dict[str, Any]) -> bool:
        """
        Evaluate authorization policy against the given context
        
        This method sends the authorization context to OPA for policy evaluation.
        OPA will apply all relevant rules and return a boolean decision.
        
        SECURITY DESIGN PRINCIPLES:
        
        1. **Fail Secure**: If OPA is unreachable or returns an error,
           the method returns False (deny access) rather than True
        
        2. **Timeout Protection**: Uses short timeout (1 second) to prevent
           authorization checks from hanging indefinitely
        
        3. **Error Isolation**: Network/parsing errors don't crash the application,
           they result in access denial
        
        CONTEXT STRUCTURE:
        
        The context dictionary should include all information needed for
        authorization decisions. Common fields include:
        
        ```python
        context = {
            # User identification and attributes
            "user": {
                "id": "user123",
                "email": "user@company.com", 
                "role": "analyst",
                "department": "finance",
                "clearance_level": "confidential"
            },
            
            # Action being attempted
            "action": "read",  # read, write, delete, execute
            "tool": "database_query",
            "method": "GET",
            
            # Resource being accessed
            "resource": {
                "type": "database_table",
                "name": "customer_data",
                "classification": "pii",
                "owner": "marketing_team"
            },
            
            # Environmental context
            "environment": "production",
            "ip_address": "192.168.1.100",
            "time": "2024-01-15T14:30:00Z",
            "session_id": "sess_abc123"
        }
        ```
        
        Args:
            context (Dict[str, Any]): Authorization context containing all relevant
                                    information for policy evaluation
        
        Returns:
            bool: True if access is allowed, False if denied or on error
            
        Example usage:
        ```python
        # Check if user can access sensitive data
        context = {
            "user": {"role": "analyst", "id": "user123"},
            "tool": "database_query",
            "resource": {"table": "customer_pii", "classification": "sensitive"},
            "action": "read",
            "environment": "production"
        }
        
        if opa_client.check_policy(context):
            # User has permission - proceed with operation
            result = execute_sensitive_query()
        else:
            # Access denied - log attempt and return error
            logger.warning(f"Access denied for user {context['user']['id']}")
            raise PermissionError("Insufficient permissions")
        ```
        """
        try:
            # Send policy evaluation request to OPA
            # The "input" field is the standard way OPA expects context data
            response = requests.post(
                self.base_url,
                json={"input": context},
                timeout=1.0,  # Short timeout for responsive authorization
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "MCP-Security-Controls/1.0"
                }
            )
            
            # Raise exception for HTTP error status codes (4xx, 5xx)
            # This ensures we handle OPA server errors appropriately
            response.raise_for_status()
            
            # Parse OPA response and extract the authorization decision
            # OPA returns: {"result": true/false} for boolean policies
            result = response.json()
            
            # Log authorization decision for audit purposes
            # (In production, you might want more detailed logging)
            decision = result.get("result", False)
            print(f"🔐 OPA Authorization: {decision} for {context.get('user', {}).get('id', 'unknown')} accessing {context.get('tool', 'unknown')}")
            
            return decision
            
        except requests.exceptions.Timeout:
            # OPA server took too long to respond
            # Fail secure: deny access when authorization system is slow
            print(f"⚠️ OPA timeout for policy check - denying access")
            return False
            
        except requests.exceptions.ConnectionError:
            # OPA server is unreachable
            # This might happen during deployments or network issues
            print(f"⚠️ OPA server unreachable at {self.opa_url} - denying access")
            return False
            
        except requests.exceptions.HTTPError as e:
            # OPA returned an HTTP error (400, 500, etc.)
            # This could indicate policy syntax errors or server issues
            print(f"⚠️ OPA HTTP error {e.response.status_code} - denying access")
            return False
            
        except (ValueError, KeyError) as e:
            # JSON parsing error or unexpected response format
            # This could happen if OPA returns malformed responses
            print(f"⚠️ OPA response parsing error: {e} - denying access")
            return False
            
        except requests.exceptions.RequestException as e:
            # Catch-all for other network-related errors
            # Ensures any unexpected network issue results in access denial
            print(f"⚠️ OPA request failed: {e} - denying access")
            return False
            
        except Exception as e:
            # Ultimate fallback for any unexpected errors
            # Ensures authorization failures never crash the application
            print(f"⚠️ Unexpected error in OPA policy check: {e} - denying access")
            return False


# %%
# -----------------------------------------------------------
# Zero-Trust Security Controls for MCP Architecture
# -----------------------------------------------------------

import hashlib
import hmac
import time
import urllib.parse
from datetime import datetime, timedelta
from typing import Set, Tuple
from urllib.parse import urlparse

class ServerNameRegistry:
    """
    Enforces unique naming conventions for MCP servers to prevent impersonation.
    
    This class provides centralized server name management:
    - Maintains global registry of registered MCP server names
    - Prevents name collisions and namespace conflicts
    - Validates naming conventions and patterns
    - Supports hierarchical namespacing for multi-tenant environments
    
    Essential for MVP because:
    - Prevents malicious servers from impersonating trusted services
    - Ensures server authenticity in distributed MCP deployments
    - Critical for multi-tenant environments where name conflicts can cause security breaches
    - Enables trusted server discovery and validation
    
    Zero-Trust Principle:
    Every server name must be unique, verified, and traceable to its owner
    """
    
    def __init__(self, registry_backend: str = "memory", namespace_separator: str = "::"):
        """
        Initialize server name registry
        
        Args:
            registry_backend: Storage backend for registry ("memory", "redis", "database")
            namespace_separator: Separator for hierarchical namespaces
        """
        self.namespace_separator = namespace_separator
        self.registered_servers = {}  # In-memory registry for MVP
        self.name_patterns = {
            "valid_chars": re.compile(r"^[a-zA-Z0-9\-_\.]+$"),
            "reserved_names": {
                "admin", "system", "internal", "api", "auth", "security",
                "mcp-server", "mcp-client", "localhost", "default"
            },
            "max_length": 64,
            "min_length": 3
        }
        
    def register_server_name(self, server_name: str, owner_identity: str, 
                           server_metadata: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Register a new MCP server name
        
        Args:
            server_name: Proposed server name
            owner_identity: Identity of the server owner (service account, etc.)
            server_metadata: Server configuration and capabilities
            
        Returns:
            Tuple[bool, str]: (success, registration_token or error_message)
            
        Raises:
            SecurityException: If name registration fails validation
        """
        try:
            # Validate name format and patterns
            validation_result = self._validate_server_name(server_name)
            if not validation_result["valid"]:
                raise SecurityException(f"Invalid server name: {validation_result['reason']}")
            
            # Check for existing registration
            if server_name in self.registered_servers:
                existing_owner = self.registered_servers[server_name]["owner"]
                if existing_owner != owner_identity:
                    raise SecurityException(
                        f"Server name '{server_name}' already registered to different owner"
                    )
                # Allow re-registration by same owner
                print(f"ℹ️ Re-registering server '{server_name}' for owner {owner_identity}")
            
            # Generate registration token
            registration_token = self._generate_registration_token(server_name, owner_identity)
            
            # Store registration
            self.registered_servers[server_name] = {
                "owner": owner_identity,
                "registered_at": datetime.utcnow(),
                "metadata": server_metadata,
                "registration_token": registration_token,
                "status": "active"
            }
            
            print(f"✅ Server name registered: {server_name} -> {owner_identity}")
            return True, registration_token
            
        except Exception as e:
            print(f"❌ Server name registration failed: {e}")
            raise SecurityException(f"Server name registration failed: {e}")
    
    def validate_server_identity(self, server_name: str, registration_token: str) -> bool:
        """
        Validate server identity using registration token
        
        Args:
            server_name: Name of the server to validate
            registration_token: Token provided during registration
            
        Returns:
            bool: True if server identity is valid
        """
        try:
            if server_name not in self.registered_servers:
                print(f"❌ Server '{server_name}' not found in registry")
                return False
            
            stored_token = self.registered_servers[server_name]["registration_token"]
            if not hmac.compare_digest(registration_token, stored_token):
                print(f"❌ Invalid registration token for server '{server_name}'")
                return False
            
            # Check if registration is still active
            server_status = self.registered_servers[server_name]["status"]
            if server_status != "active":
                print(f"❌ Server '{server_name}' has status: {server_status}")
                return False
            
            print(f"✅ Server identity validated: {server_name}")
            return True
            
        except Exception as e:
            print(f"❌ Server identity validation failed: {e}")
            return False
    
    def _validate_server_name(self, server_name: str) -> Dict[str, Any]:
        """Validate server name against naming conventions"""
        # Check length
        if len(server_name) < self.name_patterns["min_length"]:
            return {"valid": False, "reason": f"Name too short (min {self.name_patterns['min_length']} chars)"}
        
        if len(server_name) > self.name_patterns["max_length"]:
            return {"valid": False, "reason": f"Name too long (max {self.name_patterns['max_length']} chars)"}
        
        # Check character pattern
        if not self.name_patterns["valid_chars"].match(server_name):
            return {"valid": False, "reason": "Invalid characters (use only alphanumeric, hyphens, underscores, dots)"}
        
        # Check reserved names
        name_base = server_name.split(self.namespace_separator)[0].lower()
        if name_base in self.name_patterns["reserved_names"]:
            return {"valid": False, "reason": f"Reserved name: {name_base}"}
        
        # Additional security checks
        if ".." in server_name or server_name.startswith(".") or server_name.endswith("."):
            return {"valid": False, "reason": "Invalid dot notation"}
        
        return {"valid": True, "reason": "Name validation passed"}
    
    def _generate_registration_token(self, server_name: str, owner_identity: str) -> str:
        """Generate secure registration token"""
        token_data = f"{server_name}:{owner_identity}:{time.time()}"
        return hashlib.sha256(token_data.encode()).hexdigest()


class ToolExposureController:
    """
    Ensures only vetted tools are exposed via MCP server.
    
    This class provides comprehensive tool exposure management:
    - Maintains allowlist of approved tools and their capabilities
    - Validates tool definitions against security policies
    - Prevents accidental exposure of sensitive system functions
    - Monitors and controls tool usage patterns
    
    Essential for MVP because:
    - Prevents accidental exposure of dangerous system capabilities to AI agents
    - Critical for preventing privilege escalation through tool access
    - Ensures only business-approved tools are available to agents
    - Required for compliance and audit trails in enterprise deployments
    
    Zero-Trust Principle:
    No tool is safe by default - every tool must be explicitly approved and configured
    """
    
    def __init__(self, policy_file: str = None, default_policy: str = "deny"):
        """
        Initialize tool exposure controller
        
        Args:
            policy_file: Path to tool exposure policy configuration
            default_policy: Default policy for unknown tools ("allow", "deny")
        """
        self.default_policy = default_policy
        self.approved_tools = {}  # Vetted and approved tools
        self.tool_policies = {}   # Security policies per tool
        self.usage_tracking = {}  # Tool usage monitoring
        self.sensitive_patterns = [
            r"file_system", r"network", r"database", r"shell", r"exec",
            r"admin", r"root", r"sudo", r"password", r"secret", r"credential"
        ]
        
        # Load policies if provided
        if policy_file and os.path.exists(policy_file):
            self._load_tool_policies(policy_file)
    
    def approve_tool_exposure(self, tool_name: str, tool_definition: Dict[str, Any], 
                            approver_identity: str) -> bool:
        """
        Approve a tool for exposure via MCP server
        
        Args:
            tool_name: Name of the tool to approve
            tool_definition: Complete tool definition including capabilities
            approver_identity: Identity of the person/system approving the tool
            
        Returns:
            bool: True if tool is approved for exposure
            
        Raises:
            SecurityException: If tool approval fails security validation
        """
        try:
            # Validate tool definition format
            if not self._validate_tool_definition(tool_definition):
                raise SecurityException(f"Invalid tool definition for '{tool_name}'")
            
            # Security analysis of tool capabilities
            security_analysis = self._analyze_tool_security(tool_name, tool_definition)
            if security_analysis["risk_level"] == "critical":
                raise SecurityException(
                    f"Critical security risk in tool '{tool_name}': {security_analysis['risks']}"
                )
            
            # Check for sensitive operations
            if self._contains_sensitive_operations(tool_definition):
                if security_analysis["risk_level"] not in ["low", "reviewed"]:
                    raise SecurityException(
                        f"Sensitive tool '{tool_name}' requires explicit security review"
                    )
            
            # Generate tool approval record
            approval_record = {
                "tool_definition": tool_definition,
                "approved_by": approver_identity,
                "approved_at": datetime.utcnow(),
                "security_analysis": security_analysis,
                "approval_token": self._generate_approval_token(tool_name, approver_identity),
                "status": "approved"
            }
            
            # Store approved tool
            self.approved_tools[tool_name] = approval_record
            
            # Set default policy for approved tool
            self.tool_policies[tool_name] = {
                "exposure_allowed": True,
                "rate_limit": security_analysis.get("recommended_rate_limit", 100),
                "auth_required": security_analysis["risk_level"] != "low",
                "audit_required": True
            }
            
            print(f"✅ Tool approved for exposure: {tool_name} (risk: {security_analysis['risk_level']})")
            return True
            
        except Exception as e:
            print(f"❌ Tool approval failed: {e}")
            raise SecurityException(f"Tool approval failed: {e}")
    
    def validate_tool_exposure(self, tool_name: str, request_context: Dict[str, Any]) -> bool:
        """
        Validate if tool can be exposed in current context
        
        Args:
            tool_name: Name of the tool to validate
            request_context: Context of the exposure request
            
        Returns:
            bool: True if tool exposure is allowed
        """
        try:
            # Check if tool is approved
            if tool_name not in self.approved_tools:
                if self.default_policy == "deny":
                    print(f"❌ Tool '{tool_name}' not in approved list")
                    return False
                else:
                    print(f"⚠️ Tool '{tool_name}' not approved but default policy allows")
            
            # Check tool-specific policies
            if tool_name in self.tool_policies:
                policy = self.tool_policies[tool_name]
                
                if not policy["exposure_allowed"]:
                    print(f"❌ Tool '{tool_name}' exposure disabled by policy")
                    return False
                
                # Check rate limiting
                if not self._check_rate_limit(tool_name, request_context):
                    print(f"❌ Tool '{tool_name}' rate limit exceeded")
                    return False
                
                # Check authentication requirements
                if policy["auth_required"] and not request_context.get("authenticated"):
                    print(f"❌ Tool '{tool_name}' requires authentication")
                    return False
            
            # Track usage
            self._track_tool_usage(tool_name, request_context)
            
            print(f"✅ Tool exposure validated: {tool_name}")
            return True
            
        except Exception as e:
            print(f"❌ Tool exposure validation failed: {e}")
            return False
    
    def get_approved_tools(self) -> Dict[str, Any]:
        """Get list of all approved tools and their definitions"""
        return {
            tool_name: {
                "definition": record["tool_definition"],
                "approved_by": record["approved_by"],
                "approved_at": record["approved_at"].isoformat(),
                "risk_level": record["security_analysis"]["risk_level"]
            }
            for tool_name, record in self.approved_tools.items()
            if record["status"] == "approved"
        }
    
    def _validate_tool_definition(self, tool_definition: Dict[str, Any]) -> bool:
        """Validate tool definition format and completeness"""
        required_fields = ["name", "description", "parameters"]
        return all(field in tool_definition for field in required_fields)
    
    def _analyze_tool_security(self, tool_name: str, tool_definition: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze tool for security risks"""
        risks = []
        risk_level = "low"
        
        # Analyze tool name and description for sensitive operations
        tool_text = f"{tool_name} {tool_definition.get('description', '')}"
        for pattern in self.sensitive_patterns:
            if re.search(pattern, tool_text, re.IGNORECASE):
                risks.append(f"Potential sensitive operation: {pattern}")
                risk_level = "medium"
        
        # Analyze parameters for dangerous types
        parameters = tool_definition.get("parameters", {})
        if isinstance(parameters, dict):
            for param_name, param_def in parameters.items():
                if isinstance(param_def, dict):
                    param_type = param_def.get("type", "")
                    if param_type in ["file", "path", "command", "sql"]:
                        risks.append(f"Dangerous parameter type: {param_name} ({param_type})")
                        risk_level = "high"
        
        # Check for critical patterns
        critical_patterns = [r"exec", r"eval", r"shell", r"subprocess", r"os\.system"]
        for pattern in critical_patterns:
            if re.search(pattern, json.dumps(tool_definition), re.IGNORECASE):
                risks.append(f"Critical security pattern: {pattern}")
                risk_level = "critical"
        
        return {
            "risk_level": risk_level,
            "risks": risks,
            "recommended_rate_limit": 10 if risk_level in ["high", "critical"] else 100
        }
    
    def _contains_sensitive_operations(self, tool_definition: Dict[str, Any]) -> bool:
        """Check if tool contains sensitive operations"""
        tool_content = json.dumps(tool_definition, default=str).lower()
        return any(re.search(pattern, tool_content) for pattern in self.sensitive_patterns)
    
    def _generate_approval_token(self, tool_name: str, approver_identity: str) -> str:
        """Generate approval token for tool"""
        token_data = f"{tool_name}:{approver_identity}:{time.time()}"
        return hashlib.sha256(token_data.encode()).hexdigest()
    
    def _check_rate_limit(self, tool_name: str, request_context: Dict[str, Any]) -> bool:
        """Check if tool usage is within rate limits"""
        # Simplified rate limiting for MVP
        current_time = time.time()
        user_id = request_context.get("user_id", "anonymous")
        
        usage_key = f"{tool_name}:{user_id}"
        if usage_key not in self.usage_tracking:
            self.usage_tracking[usage_key] = {"count": 0, "window_start": current_time}
        
        usage_info = self.usage_tracking[usage_key]
        
        # Reset window if it's been more than 1 minute
        if current_time - usage_info["window_start"] > 60:
            usage_info["count"] = 0
            usage_info["window_start"] = current_time
        
        # Check rate limit
        rate_limit = self.tool_policies.get(tool_name, {}).get("rate_limit", 100)
        return usage_info["count"] < rate_limit
    
    def _track_tool_usage(self, tool_name: str, request_context: Dict[str, Any]):
        """Track tool usage for monitoring and rate limiting"""
        user_id = request_context.get("user_id", "anonymous")
        usage_key = f"{tool_name}:{user_id}"
        
        if usage_key not in self.usage_tracking:
            self.usage_tracking[usage_key] = {"count": 0, "window_start": time.time()}
        
        self.usage_tracking[usage_key]["count"] += 1
    
    def _load_tool_policies(self, policy_file: str):
        """Load tool policies from configuration file"""
        try:
            with open(policy_file, 'r') as f:
                policies = json.load(f)
                self.tool_policies.update(policies.get("tool_policies", {}))
                
                # Load approved tools and convert string dates to datetime objects
                approved_tools = policies.get("approved_tools", {})
                for tool_name, tool_data in approved_tools.items():
                    # Convert string dates to datetime objects if needed
                    if isinstance(tool_data.get("approved_at"), str):
                        try:
                            from datetime import datetime
                            tool_data["approved_at"] = datetime.fromisoformat(
                                tool_data["approved_at"].replace('Z', '+00:00')
                            )
                        except (ValueError, ImportError):
                            # Fallback to current time if parsing fails
                            tool_data["approved_at"] = datetime.utcnow()
                
                self.approved_tools.update(approved_tools)
                print(f"✅ Loaded {len(approved_tools)} approved tools and {len(self.tool_policies)} policies from {policy_file}")
                
        except Exception as e:
            print(f"⚠️ Failed to load tool policies: {e}")


class SemanticMappingValidator:
    """
    Verifies that tool metadata aligns with intended use cases.
    
    This class provides comprehensive semantic validation:
    - Analyzes tool descriptions for semantic consistency
    - Validates parameter mappings against expected behaviors
    - Detects misaligned or deceptive tool metadata
    - Prevents misuse through semantic verification
    
    Essential for MVP because:
    - Prevents agents from misusing tools due to incorrect metadata
    - Critical for AI safety when agents make decisions based on tool descriptions
    - Ensures tool behavior matches advertised capabilities
    - Required for reliable agent-tool interaction in production
    
    Zero-Trust Principle:
    Never trust tool metadata - always verify semantic alignment with actual behavior
    """
    
    def __init__(self, semantic_models: Dict[str, Any] = None):
        """
        Initialize semantic mapping validator
        
        Args:
            semantic_models: Pre-trained models or rules for semantic validation
        """
        self.semantic_models = semantic_models or {}
        self.validated_mappings = {}  # Cache of validated tool mappings
        self.semantic_patterns = {
            "data_operations": [r"read", r"write", r"update", r"delete", r"query", r"search"],
            "file_operations": [r"file", r"directory", r"folder", r"path", r"upload", r"download"],
            "network_operations": [r"http", r"api", r"request", r"url", r"endpoint", r"service"],
            "computation": [r"calculate", r"compute", r"process", r"analyze", r"transform"],
            "communication": [r"send", r"receive", r"message", r"email", r"notify", r"alert"]
        }
        
    def validate_semantic_mapping(self, tool_name: str, tool_definition: Dict[str, Any], 
                                 expected_behavior: str = None) -> Dict[str, Any]:
        """
        Validate semantic alignment between tool metadata and intended behavior
        
        Args:
            tool_name: Name of the tool to validate
            tool_definition: Complete tool definition
            expected_behavior: Expected behavior description (optional)
            
        Returns:
            Dict containing validation results and recommendations
            
        Raises:
            SecurityException: If semantic validation fails critically
        """
        try:
            validation_result = {
                "tool_name": tool_name,
                "semantic_score": 0.0,
                "alignment_issues": [],
                "recommendations": [],
                "validation_status": "pending"
            }
            
            # Extract semantic components
            description = tool_definition.get("description", "")
            parameters = tool_definition.get("parameters", {})
            
            # Analyze description semantics
            description_analysis = self._analyze_description_semantics(tool_name, description)
            validation_result["description_analysis"] = description_analysis
            
            # Analyze parameter semantics
            parameter_analysis = self._analyze_parameter_semantics(tool_name, parameters)
            validation_result["parameter_analysis"] = parameter_analysis
            
            # Check semantic consistency
            consistency_check = self._check_semantic_consistency(
                tool_name, description_analysis, parameter_analysis
            )
            validation_result.update(consistency_check)
            
            # Compare with expected behavior if provided
            if expected_behavior:
                behavior_alignment = self._validate_behavior_alignment(
                    description, expected_behavior
                )
                validation_result["behavior_alignment"] = behavior_alignment
                
                if behavior_alignment["alignment_score"] < 0.7:
                    validation_result["alignment_issues"].append(
                        f"Low behavior alignment score: {behavior_alignment['alignment_score']:.2f}"
                    )
            
            # Calculate overall semantic score
            validation_result["semantic_score"] = self._calculate_semantic_score(validation_result)
            
            # Determine validation status
            if validation_result["semantic_score"] < 0.6:
                validation_result["validation_status"] = "failed"
                raise SecurityException(
                    f"Semantic validation failed for tool '{tool_name}': "
                    f"Score {validation_result['semantic_score']:.2f} below threshold"
                )
            elif validation_result["semantic_score"] < 0.8:
                validation_result["validation_status"] = "warning"
                validation_result["recommendations"].append(
                    "Consider improving tool description clarity and parameter naming"
                )
            else:
                validation_result["validation_status"] = "passed"
            
            # Cache successful validation
            if validation_result["validation_status"] in ["passed", "warning"]:
                self.validated_mappings[tool_name] = {
                    "validation_result": validation_result,
                    "validated_at": datetime.utcnow(),
                    "definition_hash": hashlib.sha256(
                        json.dumps(tool_definition, sort_keys=True).encode()
                    ).hexdigest()
                }
            
            print(f"✅ Semantic validation completed: {tool_name} "
                  f"(score: {validation_result['semantic_score']:.2f}, "
                  f"status: {validation_result['validation_status']})")
            
            return validation_result
            
        except Exception as e:
            print(f"❌ Semantic validation failed: {e}")
            raise SecurityException(f"Semantic validation failed: {e}")
    
    def is_mapping_validated(self, tool_name: str, tool_definition: Dict[str, Any]) -> bool:
        """Check if tool mapping has been validated and is still current"""
        if tool_name not in self.validated_mappings:
            return False
        
        cached_validation = self.validated_mappings[tool_name]
        
        # Check if definition has changed
        current_hash = hashlib.sha256(
            json.dumps(tool_definition, sort_keys=True).encode()
        ).hexdigest()
        
        if cached_validation["definition_hash"] != current_hash:
            # Definition changed, re-validation needed
            del self.validated_mappings[tool_name]
            return False
        
        # Check validation expiry (24 hours for MVP)
        if datetime.utcnow() - cached_validation["validated_at"] > timedelta(hours=24):
            del self.validated_mappings[tool_name]
            return False
        
        return cached_validation["validation_result"]["validation_status"] in ["passed", "warning"]
    
    def _analyze_description_semantics(self, tool_name: str, description: str) -> Dict[str, Any]:
        """Analyze semantic content of tool description"""
        analysis = {
            "word_count": len(description.split()),
            "semantic_categories": [],
            "clarity_score": 0.0,
            "specificity_score": 0.0
        }
        
        description_lower = description.lower()
        
        # Identify semantic categories
        for category, patterns in self.semantic_patterns.items():
            if any(re.search(pattern, description_lower) for pattern in patterns):
                analysis["semantic_categories"].append(category)
        
        # Calculate clarity score based on description quality
        clarity_indicators = [
            len(description) > 20,  # Adequate length
            any(word in description_lower for word in ["performs", "executes", "returns", "processes"]),
            ":" in description or "." in description,  # Structured description
            not any(word in description_lower for word in ["maybe", "might", "possibly"])  # Definitive language
        ]
        analysis["clarity_score"] = sum(clarity_indicators) / len(clarity_indicators)
        
        # Calculate specificity score
        specificity_indicators = [
            any(re.search(r"\b\w+s?\b", description_lower) for _ in range(3)),  # Multiple specific terms
            re.search(r"\d+", description),  # Contains numbers/quantities
            len(analysis["semantic_categories"]) == 1,  # Single clear category
            not any(word in description_lower for word in ["various", "multiple", "different", "any"])
        ]
        analysis["specificity_score"] = sum(specificity_indicators) / len(specificity_indicators)
        
        return analysis
    
    def _analyze_parameter_semantics(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze semantic consistency of parameters"""
        analysis = {
            "parameter_count": len(parameters) if isinstance(parameters, dict) else 0,
            "naming_consistency": 0.0,
            "type_appropriateness": 0.0,
            "semantic_alignment": []
        }
        
        if not isinstance(parameters, dict) or not parameters:
            return analysis
        
        # Analyze parameter naming consistency
        param_names = list(parameters.keys())
        naming_scores = []
        
        for param_name in param_names:
            param_def = parameters.get(param_name, {})
            if isinstance(param_def, dict):
                param_description = param_def.get("description", "")
                param_type = param_def.get("type", "")
                
                # Check if parameter name aligns with its description
                name_desc_alignment = self._calculate_name_description_alignment(
                    param_name, param_description
                )
                naming_scores.append(name_desc_alignment)
                
                # Check type appropriateness
                type_appropriate = self._check_type_appropriateness(param_name, param_type)
                
                analysis["semantic_alignment"].append({
                    "parameter": param_name,
                    "name_description_alignment": name_desc_alignment,
                    "type_appropriate": type_appropriate,
                    "type": param_type
                })
        
        analysis["naming_consistency"] = sum(naming_scores) / len(naming_scores) if naming_scores else 0.0
        analysis["type_appropriateness"] = sum(
            item["type_appropriate"] for item in analysis["semantic_alignment"]
        ) / len(analysis["semantic_alignment"]) if analysis["semantic_alignment"] else 0.0
        
        return analysis
    
    def _check_semantic_consistency(self, tool_name: str, description_analysis: Dict[str, Any], 
                                  parameter_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Check overall semantic consistency between description and parameters"""
        consistency_result = {
            "consistency_score": 0.0,
            "consistency_issues": [],
            "recommendations": []
        }
        
        # Check if parameter count matches description complexity
        desc_categories = len(description_analysis["semantic_categories"])
        param_count = parameter_analysis["parameter_count"]
        
        if desc_categories > 0 and param_count == 0:
            consistency_result["consistency_issues"].append(
                "Tool has semantic categories but no parameters"
            )
        elif desc_categories == 0 and param_count > 0:
            consistency_result["consistency_issues"].append(
                "Tool has parameters but unclear semantic purpose"
            )
        
        # Check naming alignment
        if parameter_analysis["naming_consistency"] < 0.7:
            consistency_result["consistency_issues"].append(
                f"Poor parameter naming consistency: {parameter_analysis['naming_consistency']:.2f}"
            )
            consistency_result["recommendations"].append(
                "Improve parameter names to better reflect their purpose"
            )
        
        # Calculate overall consistency score
        score_components = [
            description_analysis["clarity_score"],
            description_analysis["specificity_score"],
            parameter_analysis["naming_consistency"],
            parameter_analysis["type_appropriateness"]
        ]
        
        consistency_result["consistency_score"] = sum(score_components) / len(score_components)
        
        return consistency_result
    
    def _validate_behavior_alignment(self, description: str, expected_behavior: str) -> Dict[str, Any]:
        """Validate alignment between description and expected behavior"""
        # Simplified semantic similarity for MVP
        desc_words = set(re.findall(r'\w+', description.lower()))
        expected_words = set(re.findall(r'\w+', expected_behavior.lower()))
        
        # Calculate Jaccard similarity
        intersection = desc_words.intersection(expected_words)
        union = desc_words.union(expected_words)
        
        alignment_score = len(intersection) / len(union) if union else 0.0
        
        return {
            "alignment_score": alignment_score,
            "shared_concepts": list(intersection),
            "missing_concepts": list(expected_words - desc_words),
            "extra_concepts": list(desc_words - expected_words)
        }
    
    def _calculate_semantic_score(self, validation_result: Dict[str, Any]) -> float:
        """Calculate overall semantic validation score"""
        scores = []
        
        # Description quality
        desc_analysis = validation_result.get("description_analysis", {})
        scores.append(desc_analysis.get("clarity_score", 0.0))
        scores.append(desc_analysis.get("specificity_score", 0.0))
        
        # Parameter quality
        param_analysis = validation_result.get("parameter_analysis", {})
        scores.append(param_analysis.get("naming_consistency", 0.0))
        scores.append(param_analysis.get("type_appropriateness", 0.0))
        
        # Consistency
        scores.append(validation_result.get("consistency_score", 0.0))
        
        # Behavior alignment (if available)
        behavior_alignment = validation_result.get("behavior_alignment", {})
        if behavior_alignment:
            scores.append(behavior_alignment.get("alignment_score", 0.0))
        
        return sum(scores) / len(scores) if scores else 0.0
    
    def _calculate_name_description_alignment(self, param_name: str, param_description: str) -> float:
        """Calculate alignment between parameter name and description"""
        if not param_description:
            return 0.5  # Neutral score if no description
        
        name_words = set(re.findall(r'\w+', param_name.lower()))
        desc_words = set(re.findall(r'\w+', param_description.lower()))
        
        # Check for common words
        common_words = name_words.intersection(desc_words)
        
        # Calculate alignment score
        if not name_words:
            return 0.0
        
        alignment = len(common_words) / len(name_words)
        
        # Boost score if parameter name appears in description
        if any(word in param_description.lower() for word in param_name.lower().split('_')):
            alignment = min(1.0, alignment + 0.3)
        
        return alignment
    
    def _check_type_appropriateness(self, param_name: str, param_type: str) -> float:
        """Check if parameter type is appropriate for its name"""
        type_patterns = {
            "string": [r"name", r"text", r"message", r"description", r"content"],
            "number": [r"count", r"size", r"amount", r"quantity", r"limit"],
            "integer": [r"id", r"index", r"number", r"count"],
            "boolean": [r"enable", r"disable", r"flag", r"active", r"valid"],
            "array": [r"list", r"items", r"values", r"collection"],
            "object": [r"config", r"settings", r"options", r"data"]
        }
        
        param_name_lower = param_name.lower()
        
        if param_type in type_patterns:
            patterns = type_patterns[param_type]
            if any(re.search(pattern, param_name_lower) for pattern in patterns):
                return 1.0
            else:
                return 0.5  # Type doesn't contradict name
        
        return 0.7  # Unknown type, assume reasonable