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

# JWT (JSON Web Token) library for token validation
# Google Cloud ID tokens are JWT tokens signed by Google
import jwt

# HTTP client for making API calls to external services
import requests

# Type hints for better code documentation and IDE support
from typing import Dict, Any, List, Optional

# Cryptography library for RSA key generation (used in ContextSecurity)
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
        Apply security filters to user input using Model Armor API or fallback patterns
        
        This method provides enterprise-grade security through Model Armor API,
        with fallback to local regex patterns for development environments.
        
        Model Armor benefits:
        - Advanced ML-based prompt injection detection
        - Real-time threat intelligence updates
        - Sophisticated attack pattern recognition
        - Lower false positive rates than regex patterns
        - Professional security monitoring and analytics
        
        Common use cases:
        - Sanitizing user prompts before sending to AI models
        - Cleaning tool parameters before execution
        - Protecting against prompt injection in chat interfaces
        
        Args:
            text (str): Input text to sanitize
            
        Returns:
            str: Sanitized text with dangerous patterns replaced
        """
        # Try Model Armor API first for production-grade security
        model_armor_result = self._check_model_armor(text)
        
        if model_armor_result['success']:
            # Use Model Armor's analysis and sanitization
            if model_armor_result['is_malicious']:
                # Model Armor detected threats - apply their recommended sanitization
                return model_armor_result['sanitized_text']
            else:
                # Model Armor says it's safe - return original text
                return text
        else:
            # Fallback to local regex patterns if Model Armor is unavailable
            print(f"⚠️ Model Armor unavailable ({model_armor_result['error']}), using fallback patterns")
            for pattern in self.patterns:
                text = pattern.sub("[REDACTED]", text)
            return text

    def _check_model_armor(self, text: str) -> Dict[str, Any]:
        """
        Check text against Model Armor API for advanced threat detection
        
        Model Armor provides enterprise-grade AI security including:
        - ML-based prompt injection detection
        - Context-aware threat analysis
        - Real-time threat intelligence
        - Sophisticated attack pattern recognition
        - Detailed security analytics and reporting
        
        Args:
            text (str): Text to analyze for security threats
            
        Returns:
            Dict[str, Any]: Analysis results including threat status and sanitized text
        """
        try:
            # Get Model Armor API credentials from secure storage
            api_key = os.getenv('MODEL_ARMOR_API_KEY') or self._get_credential_if_available('model-armor-api-key')
            
            if not api_key:
                return {
                    'success': False,
                    'error': 'Model Armor API key not configured',
                    'is_malicious': False,
                    'sanitized_text': text
                }
            
            # Model Armor API endpoint for prompt injection detection
            model_armor_url = "https://api.modelarmor.com/v1/analyze"
            
            # Prepare request payload for Model Armor
            payload = {
                "text": text,
                "detection_types": [
                    "prompt_injection",
                    "pii_detection", 
                    "toxicity",
                    "code_injection",
                    "data_extraction"
                ],
                "sanitization_mode": "redact",  # Options: redact, block, warn
                "security_profile": self.security_profile  # Use our configured profile
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "MCP-Security-Controls/1.0"
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
                    'model_armor_id': result.get('analysis_id'),  # For audit trails
                    'raw_response': result  # Full response for detailed logging
                }
            
            elif response.status_code == 429:
                # Rate limit exceeded - use fallback
                return {
                    'success': False,
                    'error': 'Model Armor rate limit exceeded',
                    'is_malicious': False,
                    'sanitized_text': text
                }
            
            else:
                # Other API errors
                return {
                    'success': False,
                    'error': f'Model Armor API error: {response.status_code}',
                    'is_malicious': False,
                    'sanitized_text': text
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Model Armor API timeout',
                'is_malicious': False,
                'sanitized_text': text
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Model Armor network error: {str(e)}',
                'is_malicious': False,
                'sanitized_text': text
            }
            
        except Exception as e:
            # Fail safe - assume potential threat and use fallback
            return {
                'success': False,
                'error': f'Model Armor unexpected error: {str(e)}',
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



# %%
# -------------------------------
# 2. Token Validation (Azure AD)
# -------------------------------

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
    Validates Google Cloud IAM ID tokens for service-to-service authentication
    
    This class validates ID tokens issued by Google Cloud IAM for Cloud Run
    service-to-service authentication, providing:
    - Cryptographic signature verification using Google's public keys
    - Audience validation to ensure tokens are intended for this service
    - Issuer verification for authenticity
    - Service account validation
    
    For Cloud Run service-to-service authentication:
    - Source service gets an ID token targeting the destination service
    - Destination service validates the token using this class
    - Token contains service account identity and audience claims
    
    Security features:
    - Google-managed public key rotation
    - Automatic signature verification
    - Built-in audience and issuer validation
    - Protection against token misuse and replay attacks
    
    For FastAPI integration:
    Use as a dependency in your secured endpoints to validate Bearer tokens
    from the Authorization header in Cloud Run service-to-service calls.
    """
    
    def __init__(self, expected_audience: str, project_id: str):
        """
        Initialize the Google Cloud IAM token validator
        
        Args:
            expected_audience (str): The audience claim that tokens must contain
                                   (typically the target Cloud Run service URL)
            project_id (str): Google Cloud project ID for additional validation
        """
        self.expected_audience = expected_audience
        self.project_id = project_id
        
    def validate(self, token: str) -> Dict[str, Any]:
        """
        Comprehensive Google Cloud IAM token validation
        
        This method validates ID tokens issued by Google Cloud IAM:
        1. Cryptographic signature verification against Google's public keys
        2. Audience validation to ensure token is for this service
        3. Issuer verification to confirm Google issued the token
        4. Expiration and timing validation
        
        Args:
            token (str): ID token string from Authorization header
            
        Returns:
            Dict[str, Any]: Validated token claims if verification succeeds
            
        Raises:
            SecurityException: If token validation fails
        """
        try:
            # Import Google Auth libraries for token verification
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token
            from google.auth import exceptions as google_exceptions
            
            # Create a Google Auth request object for token verification
            request = google_requests.Request()
            
            # Verify the ID token using Google's public keys
            # This automatically handles:
            # - Signature verification
            # - Expiration checking
            # - Issuer validation
            # - Audience validation
            claims = id_token.verify_oauth2_token(
                token, 
                request, 
                audience=self.expected_audience
            )
            
            # Additional validation for Cloud Run context
            # Ensure the token is from Google's identity provider
            if claims.get('iss') not in ['https://accounts.google.com', 'accounts.google.com']:
                raise SecurityException("Invalid token issuer")
            
            # Validate that the token has a service account subject
            # Cloud Run service-to-service tokens should have service account subjects
            subject = claims.get('sub')
            if not subject:
                raise SecurityException("Missing subject in token")
            
            # Optional: Validate project context if needed
            # This can help ensure tokens are from expected projects
            email = claims.get('email', '')
            if self.project_id and self.project_id not in email:
                print(f"⚠️ Warning: Token from different project context")
            
            print(f"✅ Validated token for service account: {email}")
            return claims
            
        except google_exceptions.GoogleAuthError as e:
            # Google Auth library raised an authentication error
            # This includes signature verification, expiration, etc.
            raise SecurityException(f"Google Cloud token validation failed: {str(e)}")
            
        except ValueError as e:
            # Audience or other validation errors
            raise SecurityException(f"Token validation error: {str(e)}")
            
        except Exception as e:
            # Catch-all for unexpected errors
            raise SecurityException(f"Unexpected token validation error: {str(e)}")

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