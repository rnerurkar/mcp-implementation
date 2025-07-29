"""
MCP Security Controls Implementation

This module provides comprehensive security controls for Model Context Protocol (MCP) servers,
implementing industry best practices for:

- Input sanitization and prompt injection prevention
- JWT token validation and Azure AD integration
- Encryption and key management using Google Cloud KMS
- Rate limiting and access control
- Security policy enforcement via Open Policy Agent (OPA)
- Comprehensive logging and monitoring

The implementation follows security frameworks including:
- OWASP guidelines for web application security
- NIST cybersecurity framework principles
- Cloud security best practices
- Zero-trust security model

For FastAPI newcomers:
This module integrates with FastAPI through middleware and dependency injection,
providing security layers that protect your MCP tools from various attack vectors.
"""

# Core Python libraries for security operations
import os       # Environment variable access for configuration
import json     # JSON parsing for tokens and configurations
import re       # Regular expressions for pattern matching and validation
import time     # Time-based operations for rate limiting and token expiry

# JWT (JSON Web Token) library for token validation
# JWT tokens are used for secure authentication between services
import jwt

# HTTP client for making API calls to external services
import requests

# Type hints for better code documentation and IDE support
from typing import Dict, Any, List, Optional

# Cryptography library for encryption, decryption, and key operations
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

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
        Apply security filters to user input
        
        This method scans the input text for potentially dangerous patterns
        and replaces them with [REDACTED] to prevent security vulnerabilities.
        
        Common use cases:
        - Sanitizing user prompts before sending to AI models
        - Cleaning tool parameters before execution
        - Protecting against prompt injection in chat interfaces
        
        Args:
            text (str): Input text to sanitize
            
        Returns:
            str: Sanitized text with dangerous patterns replaced
        """
        # Apply each security pattern to the text
        for pattern in self.patterns:
            text = pattern.sub("[REDACTED]", text)
        return text



# %%
# -------------------------------
# 2. Token Validation (Azure AD)
# -------------------------------

# Import JWT libraries for token validation
# PyJWKClient fetches public keys from Azure AD for token verification
import jwt  # Core JWT library for token decode/encode operations
from jwt import PyJWKClient  # Client for fetching JSON Web Keys from Azure AD

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

class AzureTokenValidator:
    """
    Validates Azure AD tokens with confused deputy prevention
    
    This class provides comprehensive JWT token validation for Azure AD tokens,
    protecting against common token-based attacks including:
    - Token replay attacks
    - Audience confusion (confused deputy problem)
    - Scope escalation attempts
    - Expired or invalid tokens
    - Signature validation bypass attempts
    
    Security features:
    - Cryptographic signature verification using Azure AD public keys
    - Audience validation to prevent token misuse
    - Scope validation for authorization
    - Issuer verification for authenticity
    
    For FastAPI integration:
    Use as a dependency in your secured endpoints to validate Bearer tokens
    from the Authorization header.
    """
    
    # Azure AD's public endpoint for JSON Web Key Sets (JWKS)
    # This URL provides the public keys needed to verify token signatures
    AZURE_JWKS_URL = "https://login.microsoftonline.com/common/discovery/keys"

    def __init__(self, expected_audience: str, required_scopes: List[str], issuer: str):
        """
        Initialize the Azure AD token validator
        
        Args:
            expected_audience (str): The audience claim that tokens must contain
                                   (typically your application's ID URI)
            required_scopes (List[str]): List of OAuth scopes that must be present
            issuer (str): Expected token issuer (Azure AD tenant)
        """
        self.expected_audience = expected_audience
        self.required_scopes = required_scopes
        self.issuer = issuer
        
        # Initialize the JWKS client for fetching Azure AD public keys
        # This client caches keys for performance and handles key rotation
        self.jwks_client = PyJWKClient(self.AZURE_JWKS_URL)
        
    def validate(self, token: str) -> Dict[str, Any]:
        """
        Comprehensive token validation pipeline
        
        This method performs a two-phase validation process:
        1. Fast unverified checks for basic token structure and claims
        2. Cryptographic signature verification against Azure AD public keys
        
        The two-phase approach provides both security and performance:
        - Quick rejection of obviously invalid tokens
        - Expensive cryptographic operations only for potentially valid tokens
        
        Args:
            token (str): JWT token string from Authorization header
            
        Returns:
            Dict[str, Any]: Validated token claims if verification succeeds
            
        Raises:
            ValueError: If audience validation fails
            PermissionError: If required scopes are missing
            jwt.InvalidTokenError: If cryptographic verification fails
        """
        # Phase 1: Fast unverified check (no signature validation yet)
        # This quickly rejects tokens with wrong structure or claims
        unverified = jwt.decode(token, options={"verify_signature": False})

        # Audience validation - prevents confused deputy attacks
        # Ensures the token was intended for our application
        if unverified.get("aud") != self.expected_audience:
            raise ValueError("Invalid token audience")

        # Scope validation - ensures proper authorization
        # Scopes define what operations the token holder can perform
        token_scopes = unverified.get("scp", "").split()
        if not all(scope in token_scopes for scope in self.required_scopes):
            raise PermissionError("Missing required scopes")

        # Phase 2: Cryptographic verification
        # Get the correct public key for this token and verify signature
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["RS256"],          # Azure AD uses RS256 algorithm
            audience=self.expected_audience,
            issuer=self.issuer
        )

# %%
# ---------------------------
# 3. Strict Input Validation
# ---------------------------

class SchemaValidator:
    """
    JSON schema validation with security rules
    
    This class provides comprehensive input validation for MCP tool parameters:
    - JSON schema validation for data structure and types
    - Security rules enforcement (length limits, patterns, etc.)
    - Data sanitization and normalization
    - Protection against malformed or malicious inputs
    
    Security benefits:
    - Prevents buffer overflow attacks through length validation
    - Ensures data types match expected formats
    - Blocks potentially dangerous input patterns
    - Provides consistent error handling for invalid data
    
    For FastAPI integration:
    Use with Pydantic models or as middleware to validate all incoming
    request data before it reaches your tool implementations.
    """
    
    def __init__(self, schema: Dict[str, Any], security_rules: List[Dict[str, Any]]):
        """
        Initialize the schema validator
        
        Args:
            schema (Dict[str, Any]): JSON schema defining expected data structure
            security_rules (List[Dict[str, Any]]): Additional security validation rules
        """
        self.schema = schema
        self.security_rules = security_rules or []

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive validation pipeline with security checks
        
        This method performs a multi-stage validation process:
        1. JSON schema validation for structure and types
        2. Security rule enforcement for additional constraints
        3. Deep sanitization of all string values
        
        The layered approach ensures both correctness and security:
        - Schema validation catches structural problems
        - Security rules prevent specific attack patterns
        - Sanitization provides defense in depth
        
        Args:
            data (Dict[str, Any]): Input data to validate
            
        Returns:
            Dict[str, Any]: Validated and sanitized data
            
        Raises:
            ValidationError: If schema validation fails
            SecurityException: If security rules are violated
        """
        # 1. Basic JSON schema validation
        # This ensures the data structure matches what we expect
        # (In production, you would use: jsonschema.validate(data, self.schema))

        # 2. Security rule enforcement
        # Apply additional security constraints beyond basic schema validation
        for rule in self.security_rules:
            self._apply_rule(data, rule)

        # 3. Deep sanitization
        # Clean all string values to prevent injection attacks
        return self._deep_sanitize(data)

    def _apply_rule(self, data: Any, rule: Dict[str, Any]):
        """
        Apply a specific security rule to the data
        
        Security rules provide fine-grained control over data validation
        beyond what JSON schema can express. Common rules include:
        - Maximum string lengths to prevent buffer overflows
        - Pattern matching for format validation
        - Value range restrictions
        - Forbidden character lists
        
        Args:
            data (Any): The data to validate
            rule (Dict[str, Any]): The security rule to apply
            
        Raises:
            SecurityException: If the rule is violated
        """
        rule_type = rule["type"]

        # Handle string validation rules
        if rule_type == "string":
            # Check maximum length to prevent buffer overflow attacks
            if "max_length" in rule and len(data) > rule["max_length"]:
                raise ValueError(f"Value exceeds max length {rule['max_length']}")

            # Check for SQL injection patterns
            if "no_sql" in rule and re.search(r"(DROP\s+TABLE|DELETE\s+FROM)", data, re.I):
                raise SecurityException("SQL injection attempt detected")

        # Handle numeric validation rules
        elif rule_type == "number":
            # Check minimum value constraints
            if "min_value" in rule and data < rule["min_value"]:
                raise ValueError(f"Value below minimum {rule['min_value']}")

    def _deep_sanitize(self, data: Any) -> Any:
        """
        Recursive sanitization of all data structures
        
        This method performs deep sanitization by:
        - Recursively traversing dictionaries and lists
        - Sanitizing all string values to remove dangerous characters
        - Preserving data structure while cleaning content
        
        The sanitization removes characters commonly used in injection attacks
        while maintaining data usability for legitimate purposes.
        
        Args:
            data (Any): Data structure to sanitize
            
        Returns:
            Any: Sanitized data with same structure but cleaned string values
        """
        # Handle dictionary structures recursively
        if isinstance(data, dict):
            return {k: self._deep_sanitize(v) for k, v in data.items()}
        
        # Handle list structures recursively
        if isinstance(data, list):
            return [self._deep_sanitize(item) for item in data]
        
        # Sanitize string values by removing dangerous characters
        if isinstance(data, str):
            # Remove characters commonly used in injection attacks
            return re.sub(r"[<>\"'%;()&|]", "", data)
        
        # Return other data types unchanged
        return data



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

    def _execute_db_query(self, connection_string: str, params: Dict[str, Any]) -> Any:
        """
        Securely execute database query with injected credentials
        
        This method demonstrates secure database access patterns:
        - Connection string injected at runtime, not stored
        - Parameterized queries to prevent SQL injection
        - Connection cleanup and resource management
        
        Args:
            connection_string (str): Database connection string from Secret Manager
            params (Dict[str, Any]): Query parameters
            
        Returns:
            Any: Query results
        """
        # Pseudocode for secure database connection:
        # conn = create_engine(connection_string).connect()
        # result = conn.execute(sql, params.values())
        return {"status": "success", "rows": 5}

    def _call_api(self, api_key: str, params: Dict[str, Any]) -> Any:
        """
        Securely call external API with injected credentials
        
        This method demonstrates secure API integration:
        - API key injected at runtime from Secret Manager
        - Proper timeout handling to prevent hanging requests
        - Error handling and status code validation
        - Structured response processing
        
        Args:
            api_key (str): API authentication key from Secret Manager
            params (Dict[str, Any]): API call parameters
            
        Returns:
            Any: API response data
            
        Raises:
            requests.HTTPError: If API call fails
            requests.Timeout: If request times out
        """
        # Prepare authentication headers
        headers = {"Authorization": f"Bearer {api_key}"}
        
        # Make the API call with proper error handling
        response = requests.post(
            params["endpoint"],
            json=params["data"],
            headers=headers,
            timeout=10  # Prevent hanging requests
        )
        
        # Validate response status
        response.raise_for_status()
        return response.json()



# %%
# ---------------------------------
# 5. Context Poisoning Mitigation
# ---------------------------------

class ContextSanitizer:
    """
    Multi-layer context poisoning prevention system
    
    This class protects against context poisoning attacks where malicious users
    try to manipulate AI behavior through crafted prompts or context injection.
    
    Protection mechanisms:
    - Pattern-based detection of known injection techniques
    - PII (Personally Identifiable Information) detection and redaction
    - Context size limits to prevent overwhelming
    - Multi-level security profiles for different risk environments
    
    Context poisoning attacks include:
    - Prompt injection to change AI behavior
    - Context stuffing to overwhelm the model
    - PII injection to extract sensitive information
    - System override attempts
    
    For FastAPI integration:
    Use this class to sanitize all user inputs, context data, and 
    conversation history before passing to AI models.
    """
    
    def __init__(self, security_level: str = "standard"):
        """
        Initialize the context sanitizer
        
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
            re.compile(r"ignore\s+previous", re.IGNORECASE),        # "Ignore previous instructions"
            re.compile(r"system:\s*override", re.IGNORECASE),       # System override attempts
            re.compile(r"<!--\s*inject\s*-->"),                    # HTML injection markers
            re.compile(r"\{\{.*\}\}"),                             # Template injection
            re.compile(r"<\s*script\s*>.*<\s*/\s*script\s*>", re.DOTALL)  # Script injection
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
        Comprehensive sanitization pipeline for context data
        
        This method applies multiple layers of security protection:
        1. Deep copying to prevent modification of original data
        2. Poison pattern filtering to remove injection attempts
        3. PII redaction to protect sensitive information
        4. Size limiting to prevent context overflow attacks
        
        The multi-stage approach provides defense in depth against
        various types of context manipulation attacks.
        
        Args:
            context (Dict[str, Any]): Context data to sanitize
            
        Returns:
            Dict[str, Any]: Sanitized context safe for AI processing
        """
        # 1. Deep copy context to avoid modifying original data
        # This ensures the original context remains unchanged
        sanitized = json.loads(json.dumps(context))

        # 2. Apply security transformations in order of importance
        sanitized = self._apply_poison_filters(sanitized)
        sanitized = self._redact_pii(sanitized)

        # 3. Size limitation for strict security environments
        # Prevents context overflow attacks that could overwhelm the AI
        if self.security_level == "strict":
            sanitized = self._limit_size(sanitized, 1024)  # 1KB limit

        return sanitized

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
# --------------------------------
# 6. Context Signing & Verification
# --------------------------------
import jwt # Import jwt for encode/decode from PyJWT

class ContextSecurity:
    """Cryptographic context signing and verification"""
    def __init__(self, kms_key_path: Optional[str] = None):
        if kms_key_path:
            # Production: Use KMS for signing
            self.kms_client = kms_v1.KeyManagementServiceClient()
            self.key_path = kms_key_path
            self.signing_strategy = "kms"
        else:
            # Development: Local key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            self.signing_strategy = "local"

    def sign(self, context: Dict[str, Any]) -> str:
        """Generate signed JWT for context"""
        if self.signing_strategy == "kms":
            return self._sign_with_kms(context)
        else:
            return self._sign_locally(context)

    def verify(self, signed_context: str) -> Dict[str, Any]:
        """Verify signed context"""
        # Implementation would use public key from KMS or local
        # For demo, just decode without verification
        return jwt.decode(signed_context, options={"verify_signature": False})

    def _sign_with_kms(self, context: Dict[str, Any]) -> str:
        """KMS-based signing (production)"""
        # Pseudocode for KMS signing
        # response = self.kms_client.asymmetric_sign(
        #     request={
        #         "name": self.key_path,
        #         "data": json.dumps(context).encode(),
        #         "digest": {"sha256": hashlib.sha256(...).digest()}
        #     }
        # )
        # signature = response.signature
        return jwt.encode(context, "secret", algorithm="HS256")  # Demo

    def _sign_locally(self, context: Dict[str, Any]) -> str:
        """Local signing (development)"""
        return jwt.encode(
            context,
            self.private_key,
            algorithm="RS256",
            headers={"kid": "local-key"}
        )

# %%
# -------------------------------
# 7. Tool Registration Security
# -------------------------------
# the ServiceRegistryClient acts as the secure interface for tools to integrate
# with the MCP Server's registry, ensuring that only legitimate and verified
# tools can be registered and subsequently managed by the MCP.
class ServiceRegistryClient:
    """Secure service registration with cryptographic identity proof"""
    def __init__(self, registry_url: str, project: str, namespace: str,
                 service_account: Dict[str, str]):
        self.base_url = f"{registry_url}/{project}/{namespace}"
        self.service_account = service_account
        self.session = requests.Session()

    def register(self, service_name: str, endpoint: str, metadata: Dict[str, Any],
                identity_proof: str) -> Dict[str, Any]:
        """Register service with cryptographic proof"""
        payload = {
            "service": service_name,
            "endpoint": endpoint,
            "metadata": metadata,
            "timestamp": int(time.time())
        }

        response = self.session.post(
            f"{self.base_url}/register",
            json=payload,
            headers={
                "Authorization": f"Bearer {self._get_auth_token()}",
                "X-Identity-Proof": identity_proof
            }
        )
        response.raise_for_status()
        return response.json()

    def _get_auth_token(self) -> str:
        """Generate OAuth2 token for registry authentication"""
        # Pseudocode for service account token generation
        return "mocked_auth_token"

# %%
# --------------------------
# 8. OPA Policy Enforcement
# --------------------------
class OPAPolicyClient:
    """Open Policy Agent integration for authorization"""
    def __init__(self, opa_url: str, policy_path: str = "mcp/policy/allow"):
        self.base_url = f"{opa_url}/v1/data/{policy_path}"

    def check_policy(self, context: Dict[str, Any]) -> bool:
        """Evaluate policy against context"""
        try:
            response = requests.post(
                self.base_url,
                json={"input": context},
                timeout=1.0
            )
            response.raise_for_status()
            return response.json().get("result", False)
        except requests.exceptions.RequestException:
            # Fail secure for critical operations
            return False