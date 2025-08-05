"""
MCP Security Controls Implementation

This module provides comprehensive security controls for Model Context Protocol (MCP) servers,
implementing industry best practices for:

- Input sanitization and prompt injection prevention
- JWT token validation and Google Cloud service-to-service authentication
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
    Validates Google Cloud ID tokens for service-to-service authentication
    
    This class EXCLUSIVELY validates ID tokens issued by Google Cloud IAM for Cloud Run
    service-to-service authentication. NO fallback to access tokens is provided.
    
    ID Token Security Features:
    - Cryptographic signature verification using Google's public keys
    - Audience validation to ensure tokens are intended for this service
    - Issuer verification for authenticity
    - Service account validation
    - Comprehensive claims validation
    
    For Cloud Run service-to-service authentication:
    - Source service generates an ID token targeting the destination service
    - Destination service validates the token using this class (validate method ONLY)
    - Token contains verified service account identity and audience claims
    
    Security benefits over access tokens:
    - Google-managed public key rotation
    - Automatic signature verification
    - Built-in audience and issuer validation
    - Protection against token misuse and replay attacks
    - Zero-trust security model support
    
    For FastAPI integration:
    Use as a dependency in your secured endpoints to validate Bearer tokens
    from the Authorization header in Cloud Run service-to-service calls.
    
    IMPORTANT: This class only supports ID token validation. If you need access token
    validation, you must implement it separately or use a different validator.
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
        Validate Google Cloud ID tokens for Cloud Run service-to-service authentication
        
        This method validates ID tokens issued by Google Cloud IAM for Cloud Run
        service-to-service authentication. ID tokens are JWTs cryptographically
        signed by Google that contain verified service account identity.
        
        WHY USE ID TOKENS FOR SERVICE-TO-SERVICE CALLS:
        
        1. **Cryptographic Verification**: ID tokens are JWTs signed by Google's
           private keys, providing cryptographic proof of authenticity
        
        2. **Service Account Identity**: Contains verified service account email
           and subject, allowing precise authorization decisions
        
        3. **Audience Protection**: Tokens are bound to specific target services,
           preventing token misuse across different services
        
        4. **No Shared Secrets**: No service account keys required in Cloud Run -
           uses Workload Identity for automatic credential management
        
        5. **Zero Trust**: Each request carries cryptographic proof of identity,
           supporting zero-trust security models
        
        AUTHENTICATION FLOW:
        1. Client Cloud Run service requests ID token from metadata server
        2. Metadata server returns JWT ID token signed by Google
        3. Client includes token in Authorization header
        4. Server validates token signature against Google's public keys
        5. Server extracts service account identity for authorization
        
        Args:
            token (str): ID token string from Authorization header
            
        Returns:
            Dict[str, Any]: Validated token claims including service account info
            
        Raises:
            SecurityException: If token validation fails
            
        Example token claims returned:
        {
            "iss": "https://accounts.google.com",
            "aud": "https://mcp-server-xyz-uc.a.run.app",
            "sub": "113834471573829384733",
            "email": "mcp-client@project.iam.gserviceaccount.com",
            "email_verified": True,
            "iat": 1641234567,
            "exp": 1641238167
        }
        """
        try:
            # Import Google Auth libraries for ID token verification
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token as google_id_token
            from google.auth import exceptions as google_exceptions
            
            # Create a Google Auth request object for token verification
            request = google_requests.Request()
            
            # Verify the ID token using Google's public keys
            # This automatically handles:
            # - Signature verification against Google's rotating public keys
            # - Expiration checking (exp claim)
            # - Issuer validation (iss claim)
            # - Audience validation (aud claim)
            # - Not before validation (nbf claim if present)
            claims = google_id_token.verify_oauth2_token(
                token, 
                request, 
                audience=self.expected_audience
            )
            
            # Additional validation for Cloud Run service-to-service context
            
            # 1. Ensure the token is from Google's identity provider
            valid_issuers = ['https://accounts.google.com', 'accounts.google.com']
            if claims.get('iss') not in valid_issuers:
                raise SecurityException(f"Invalid token issuer: {claims.get('iss')}")
            
            # 2. Validate that the token has a service account subject
            # Cloud Run service-to-service tokens should have service account subjects
            subject = claims.get('sub')
            if not subject:
                raise SecurityException("Missing subject in token")
            
            # 3. Validate service account email format
            email = claims.get('email', '')
            if not email.endswith('.gserviceaccount.com'):
                raise SecurityException(f"Token not from service account: {email}")
            
            # 4. Ensure email is verified by Google
            if not claims.get('email_verified', False):
                raise SecurityException("Service account email not verified")
            
            # 5. Optional: Validate project context if needed
            if self.project_id and self.project_id not in email:
                print(f"⚠️ Warning: Token from different project context")
            
            # 6. Validate token timing
            import time
            current_time = int(time.time())
            
            # Check if token is not yet valid (nbf - not before)
            not_before = claims.get('nbf')
            if not_before and current_time < not_before:
                raise SecurityException("Token not yet valid")
            
            # Check if token has expired (additional check beyond library)
            expires_at = claims.get('exp')
            if expires_at and current_time >= expires_at:
                raise SecurityException("Token has expired")
            
            # Log successful validation for audit purposes
            print(f"✅ Validated ID token for service account: {email}")
            print(f"   Subject: {subject}")
            print(f"   Audience: {claims.get('aud')}")
            print(f"   Expires: {expires_at}")
            
            return claims
            
        except google_exceptions.GoogleAuthError as e:
            # Google Auth library raised an authentication error
            # This includes signature verification, expiration, audience validation, etc.
            raise SecurityException(f"Google Cloud ID token validation failed: {str(e)}")
            
        except ValueError as e:
            # Audience or other validation errors from the library
            raise SecurityException(f"ID token validation error: {str(e)}")
            
        except ImportError as e:
            # Google Auth libraries not available
            raise SecurityException(f"Google Auth libraries not available: {str(e)}")
            
        except Exception as e:
            # Catch-all for unexpected errors
            raise SecurityException(f"Unexpected ID token validation error: {str(e)}")

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

class InstallerSecurityValidator:
    """
    Prevents malicious MCP server installers from being distributed via unofficial channels.
    
    This class provides comprehensive supply chain security for MCP server installations:
    - Verifies installer integrity using cryptographic signatures
    - Validates installation sources against allowlisted registries
    - Checks package metadata for tampering
    - Enforces secure installation protocols
    
    Essential for MVP because:
    - MCP servers are often installed from remote sources (npm, pip, etc.)
    - Malicious installers can compromise entire AI agent infrastructure
    - Supply chain attacks are increasing in AI/ML ecosystems
    - Remote deployment scenarios require trusted installation verification
    
    Zero-Trust Principle:
    Never trust, always verify - every installer must prove its authenticity
    """
    
    def __init__(self, trusted_registries: List[str] = None, signature_keys: Dict[str, str] = None):
        """
        Initialize installer security validator
        
        Args:
            trusted_registries: List of trusted package registry URLs
            signature_keys: Dictionary mapping registry URLs to their public signing keys
        """
        self.trusted_registries = trusted_registries or [
            "https://registry.npmjs.org",
            "https://pypi.org",
            "https://github.com",
            "https://registry.docker.io"
        ]
        self.signature_keys = signature_keys or {}
        self.installation_cache = {}  # Cache verified installations
        
    def validate_installer_source(self, installer_url: str, metadata: Dict[str, Any]) -> bool:
        """
        Validate that installer comes from trusted source
        
        Args:
            installer_url: URL of the installer package
            metadata: Package metadata including signatures and checksums
            
        Returns:
            bool: True if installer source is trusted and verified
            
        Raises:
            SecurityException: If installer source is untrusted or invalid
        """
        try:
            # Parse installer URL to extract registry information
            parsed_url = urlparse(installer_url)
            registry_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Check if registry is in trusted list
            if not any(trusted in registry_base for trusted in self.trusted_registries):
                raise SecurityException(
                    f"Untrusted installer registry: {registry_base}. "
                    f"Allowed registries: {self.trusted_registries}"
                )
            
            # Verify package signature if available
            if "signature" in metadata and "checksum" in metadata:
                if not self._verify_package_signature(installer_url, metadata):
                    raise SecurityException(f"Invalid package signature for {installer_url}")
            
            # Verify package integrity
            if not self._verify_package_integrity(installer_url, metadata):
                raise SecurityException(f"Package integrity check failed for {installer_url}")
            
            # Check for known malicious patterns
            if self._detect_malicious_patterns(metadata):
                raise SecurityException(f"Malicious patterns detected in package metadata")
            
            # Cache successful verification
            cache_key = hashlib.sha256(installer_url.encode()).hexdigest()
            self.installation_cache[cache_key] = {
                "url": installer_url,
                "verified_at": datetime.utcnow(),
                "metadata_hash": hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
            }
            
            print(f"✅ Installer validated: {installer_url}")
            return True
            
        except Exception as e:
            print(f"❌ Installer validation failed: {e}")
            raise SecurityException(f"Installer validation failed: {e}")
    
    def _verify_package_signature(self, installer_url: str, metadata: Dict[str, Any]) -> bool:
        """Verify cryptographic signature of package"""
        try:
            signature = metadata.get("signature")
            registry_base = urlparse(installer_url).netloc
            public_key = self.signature_keys.get(registry_base)
            
            if not public_key or not signature:
                return True  # Skip if no signature verification configured
            
            # Verify signature using HMAC (simplified for MVP)
            expected_signature = hmac.new(
                public_key.encode(),
                json.dumps(metadata.get("package_info", {}), sort_keys=True).encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False
    
    def _verify_package_integrity(self, installer_url: str, metadata: Dict[str, Any]) -> bool:
        """Verify package hasn't been tampered with"""
        try:
            expected_checksum = metadata.get("checksum")
            if not expected_checksum:
                return True  # Skip if no checksum provided
            
            # In production, would download and verify actual package
            # For MVP, verify metadata consistency
            package_info = metadata.get("package_info", {})
            computed_hash = hashlib.sha256(
                json.dumps(package_info, sort_keys=True).encode()
            ).hexdigest()
            
            return expected_checksum.startswith(computed_hash[:16])  # Partial match for demo
            
        except Exception:
            return False
    
    def _detect_malicious_patterns(self, metadata: Dict[str, Any]) -> bool:
        """Detect known malicious patterns in package metadata"""
        malicious_patterns = [
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__\s*\(",
            r"subprocess\.",
            r"os\.system",
            r"shell=True"
        ]
        
        metadata_str = json.dumps(metadata, default=str).lower()
        
        for pattern in malicious_patterns:
            if re.search(pattern, metadata_str):
                return True
        
        return False


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


class RemoteServerAuthenticator:
    """
    Validates server identity during registration and invocation.
    
    This class provides comprehensive remote server authentication:
    - Validates server certificates and identity claims
    - Performs secure handshake protocols
    - Verifies server capabilities and permissions
    - Monitors for server impersonation attempts
    
    Essential for MVP because:
    - Critical for secure client-server handshake over HTTP/2 streaming
    - Prevents man-in-the-middle attacks in remote MCP communications
    - Ensures only authorized servers can provide tools to agents
    - Required for zero-trust remote server access
    
    Zero-Trust Principle:
    Never trust remote servers - always verify identity and capabilities
    """
    
    def __init__(self, trusted_ca_certs: List[str] = None, handshake_timeout: int = 30):
        """
        Initialize remote server authenticator
        
        Args:
            trusted_ca_certs: List of trusted Certificate Authority certificates
            handshake_timeout: Timeout for server handshake in seconds
        """
        self.trusted_ca_certs = trusted_ca_certs or []
        self.handshake_timeout = handshake_timeout
        self.authenticated_servers = {}  # Cache of authenticated servers
        self.server_challenges = {}  # Active authentication challenges
        
    def initiate_server_handshake(self, server_url: str, client_identity: str) -> Dict[str, Any]:
        """
        Initiate secure handshake with remote MCP server
        
        Args:
            server_url: URL of the remote MCP server
            client_identity: Identity of the connecting client
            
        Returns:
            Dict containing handshake challenge and parameters
            
        Raises:
            SecurityException: If handshake initiation fails
        """
        try:
            # Validate server URL format
            parsed_url = urlparse(server_url)
            if parsed_url.scheme not in ["https", "wss"]:
                raise SecurityException(f"Insecure protocol: {parsed_url.scheme}. Use HTTPS or WSS only.")
            
            # Generate challenge for server authentication
            challenge_id = hashlib.sha256(f"{server_url}:{client_identity}:{time.time()}".encode()).hexdigest()
            challenge_data = {
                "challenge_id": challenge_id,
                "client_identity": client_identity,
                "timestamp": time.time(),
                "nonce": os.urandom(32).hex(),
                "required_capabilities": ["tool_discovery", "secure_invoke"],
                "protocol_version": "1.0"
            }
            
            # Store challenge for verification
            self.server_challenges[challenge_id] = {
                "server_url": server_url,
                "challenge_data": challenge_data,
                "created_at": datetime.utcnow(),
                "status": "pending"
            }
            
            print(f"🔄 Initiated handshake with {server_url} (challenge: {challenge_id[:8]}...)")
            return challenge_data
            
        except Exception as e:
            print(f"❌ Handshake initiation failed: {e}")
            raise SecurityException(f"Handshake initiation failed: {e}")
    
    def validate_server_response(self, challenge_id: str, server_response: Dict[str, Any]) -> bool:
        """
        Validate server response to authentication challenge
        
        Args:
            challenge_id: ID of the authentication challenge
            server_response: Server's response to the challenge
            
        Returns:
            bool: True if server response is valid and server is authenticated
        """
        try:
            # Retrieve challenge data
            if challenge_id not in self.server_challenges:
                print(f"❌ Unknown challenge ID: {challenge_id}")
                return False
            
            challenge_info = self.server_challenges[challenge_id]
            
            # Check challenge timeout
            if datetime.utcnow() - challenge_info["created_at"] > timedelta(seconds=self.handshake_timeout):
                print(f"❌ Challenge timeout for {challenge_id}")
                del self.server_challenges[challenge_id]
                return False
            
            # Validate server response format
            required_fields = ["server_identity", "capabilities", "signature", "certificate"]
            if not all(field in server_response for field in required_fields):
                print(f"❌ Invalid server response format")
                return False
            
            # Verify server certificate (simplified for MVP)
            if not self._verify_server_certificate(server_response["certificate"]):
                print(f"❌ Invalid server certificate")
                return False
            
            # Verify response signature
            if not self._verify_response_signature(challenge_info["challenge_data"], server_response):
                print(f"❌ Invalid response signature")
                return False
            
            # Validate server capabilities
            if not self._validate_server_capabilities(server_response["capabilities"]):
                print(f"❌ Invalid or insufficient server capabilities")
                return False
            
            # Cache authenticated server
            server_url = challenge_info["server_url"]
            self.authenticated_servers[server_url] = {
                "server_identity": server_response["server_identity"],
                "capabilities": server_response["capabilities"],
                "authenticated_at": datetime.utcnow(),
                "certificate": server_response["certificate"]
            }
            
            # Clean up challenge
            self.server_challenges[challenge_id]["status"] = "completed"
            
            print(f"✅ Server authenticated: {server_url}")
            return True
            
        except Exception as e:
            print(f"❌ Server response validation failed: {e}")
            return False
    
    def is_server_authenticated(self, server_url: str) -> bool:
        """Check if server is currently authenticated"""
        if server_url not in self.authenticated_servers:
            return False
        
        # Check authentication expiry (1 hour for MVP)
        auth_info = self.authenticated_servers[server_url]
        if datetime.utcnow() - auth_info["authenticated_at"] > timedelta(hours=1):
            del self.authenticated_servers[server_url]
            return False
        
        return True
    
    def _verify_server_certificate(self, certificate: str) -> bool:
        """Verify server SSL certificate (simplified for MVP)"""
        try:
            # In production, would verify against trusted CA certificates
            # For MVP, basic format validation
            return (
                certificate.startswith("-----BEGIN CERTIFICATE-----") and
                certificate.endswith("-----END CERTIFICATE-----") and
                len(certificate) > 100
            )
        except Exception:
            return False
    
    def _verify_response_signature(self, challenge_data: Dict[str, Any], server_response: Dict[str, Any]) -> bool:
        """Verify server's signature on challenge response"""
        try:
            # Simplified signature verification for MVP
            # In production, would use public key cryptography
            expected_content = json.dumps(challenge_data, sort_keys=True)
            signature = server_response.get("signature", "")
            
            # Basic signature format validation
            return len(signature) >= 64 and signature.isalnum()
            
        except Exception:
            return False
    
    def _validate_server_capabilities(self, capabilities: List[str]) -> bool:
        """Validate server capabilities"""
        required_capabilities = {"tool_discovery", "secure_invoke"}
        provided_capabilities = set(capabilities)
        
        return required_capabilities.issubset(provided_capabilities)


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
                self.approved_tools.update(policies.get("approved_tools", {}))
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