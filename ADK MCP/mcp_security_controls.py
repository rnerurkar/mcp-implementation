# %%
# To install dependencies, run the following command in your terminal:
# pip install PyJWT requests cryptography google-cloud-secret-manager google-cloud-kms fastapi
# %%
"""
MCP Security Controls Implementation
Comprehensive security implementation following MCP documentation
"""

# -*- coding: utf-8 -*-
import os
import json
import re
import time
import jwt
import requests
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from google.cloud import secretmanager, kms_v1

# %%
# ----------------------------
# 1. Input/Output Sanitization
# ----------------------------
class InputSanitizer:
    """OWASP-recommended prompt injection prevention"""
    def __init__(self, security_profile: str = "default"):
        self.patterns = self._load_patterns(security_profile)

    def _load_patterns(self, profile: str) -> List[re.Pattern]:
        """Load patterns based on security profile"""
        base_patterns = [
            r"ignore\s+previous",
            r"system:\s*override",
            r"<!--\s*inject\s*-->",
            r"\{\{.*\}\}",
            r";\s*DROP\s+TABLE",
            r"<\s*script\s*>",
            r"eval\s*\(",
            r"document\.cookie"
        ]

        if profile == "strict":
            base_patterns.extend([
                r"http[s]?://",  # URLs
                r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Phone numbers
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # Emails
            ])

        return [re.compile(p, re.IGNORECASE) for p in base_patterns]

    def sanitize(self, text: str) -> str:
        """Apply security filters to user input"""
        for pattern in self.patterns:
            text = pattern.sub("[REDACTED]", text)
        return text



# %%
# -------------------------------
# 2. Token Validation (Azure AD)
# -------------------------------
# Import jwk for PyJWKClient
import jwt # Ensure jwt is imported for decode/encode
from jwt import PyJWKClient

class SecurityException(Exception):
    """Custom exception for security-related errors."""
    pass

class AzureTokenValidator:
    """Validates Azure AD tokens with confused deputy prevention"""
    AZURE_JWKS_URL = "https://login.microsoftonline.com/common/discovery/keys"

    def __init__(self, expected_audience: str, required_scopes: List[str], issuer: str):
        # Access PyJWKClient from the imported jwk module
        self.expected_audience = expected_audience
        self.required_scopes = required_scopes
        self.issuer = issuer
        self.jwks_client = PyJWKClient(self.AZURE_JWKS_URL)
        
    def validate(self, token: str) -> Dict[str, Any]:
        """Full token validation pipeline"""
        # Phase 1: Fast unverified check
        unverified = jwt.decode(token, options={"verify_signature": False})

        # Audience validation
        if unverified.get("aud") != self.expected_audience:
            raise ValueError("Invalid token audience")

        # Scope validation
        token_scopes = unverified.get("scp", "").split()
        if not all(scope in token_scopes for scope in self.required_scopes):
            raise PermissionError("Missing required scopes")

        # Phase 2: Cryptographic verification
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["RS256"],
            audience=self.expected_audience,
            issuer=self.issuer
        )

# %%
# ---------------------------
# 3. Strict Input Validation
# ---------------------------
class SchemaValidator:
    """JSON schema validation with security rules"""
    def __init__(self, schema: Dict[str, Any], security_rules: List[Dict[str, Any]]):
        self.schema = schema
        self.security_rules = security_rules or []

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validation pipeline with security checks"""
        # 1. Basic JSON schema validation
        # (In production: jsonschema.validate(data, self.schema))

        # 2. Security rule enforcement
        for rule in self.security_rules:
            self._apply_rule(data, rule)

        # 3. Deep sanitization
        return self._deep_sanitize(data)

    def _apply_rule(self, data: Any, rule: Dict[str, Any]):
        """Apply security rule to data"""
        rule_type = rule["type"]

        if rule_type == "string":
            if "max_length" in rule and len(data) > rule["max_length"]:
                raise ValueError(f"Value exceeds max length {rule['max_length']}")

            if "no_sql" in rule and re.search(r"(DROP\s+TABLE|DELETE\s+FROM)", data, re.I):
                raise SecurityException("SQL injection attempt detected")

        elif rule_type == "number":
            if "min_value" in rule and data < rule["min_value"]:
                raise ValueError(f"Value below minimum {rule['min_value']}")

    def _deep_sanitize(self, data: Any) -> Any:
        """Recursive sanitization"""
        if isinstance(data, dict):
            return {k: self._deep_sanitize(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self._deep_sanitize(item) for item in data]
        if isinstance(data, str):
            return re.sub(r"[<>\"'%;()&|]", "", data)
        return data



# %%
# ----------------------------
# 4. Secure Credential Handling
# ----------------------------
class CredentialManager:
    """Secure credential retrieval using GCP Secret Manager"""
    def __init__(self, project_id: str):
        self.client = secretmanager.SecretManagerServiceClient()
        self.project_id = project_id

    def get_credential(self, secret_id: str, version: str = "latest") -> str:
        """Retrieve credential with zero exposure"""
        name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
        response = self.client.access_secret_version(name=name)
        return response.payload.data.decode("UTF-8")

    def get_credentials(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """Execute tool with injected credentials"""
        # Example: Fetch credentials based on tool type
        creds = self.get_credential(f"{tool_name}-credentials")
        return creds
        # Implementation would vary by tool type
        #if tool_name == "database":
        #    return self._execute_db_query(creds, params)
        #elif tool_name == "api":
        #    return self._call_api(creds, params)
        #elif tool_name == "hello":
            # Hello tool execution logic
        #    return {"status": "success", "message": params.values()}
        #else:
         #   raise ValueError(f"Unknown tool: {tool_name}")

    def _execute_db_query(self, connection_string: str, params: Dict[str, Any]) -> Any:
        """Securely execute database query"""
        # Pseudocode for database connection
        # conn = create_engine(connection_string).connect()
        # result = conn.execute(sql, params.values())
        return {"status": "success", "rows": 5}

    def _call_api(self, api_key: str, params: Dict[str, Any]) -> Any:
        """Securely call external API"""
        headers = {"Authorization": f"Bearer {api_key}"}
        response = requests.post(
            params["endpoint"],
            json=params["data"],
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return response.json()



# %%
# ---------------------------------
# 5. Context Poisoning Mitigation
# ---------------------------------
class ContextSanitizer:
    """Multi-layer context poisoning prevention"""
    def __init__(self, security_level: str = "standard"):
        self.poison_patterns = self._load_poison_patterns()
        self.pii_patterns = self._load_pii_patterns()
        self.security_level = security_level

    def _load_poison_patterns(self) -> List[re.Pattern]:
        return [
            re.compile(r"ignore\s+previous", re.IGNORECASE),
            re.compile(r"system:\s*override", re.IGNORECASE),
            re.compile(r"<!--\s*inject\s*-->"),
            re.compile(r"\{\{.*\}\}"),
            re.compile(r"<\s*script\s*>.*<\s*/\s*script\s*>", re.DOTALL)
        ]

    def _load_pii_patterns(self) -> List[re.Pattern]:
        return [
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
            re.compile(r"\b\d{4} \d{4} \d{4} \d{4}\b"),  # Credit card
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")  # Email
        ]

    def sanitize(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitization pipeline"""
        # 1. Deep copy context
        sanitized = json.loads(json.dumps(context))

        # 2. Apply security transformations
        sanitized = self._apply_poison_filters(sanitized)
        sanitized = self._redact_pii(sanitized)

        # 3. Size limitation
        if self.security_level == "strict":
            sanitized = self._limit_size(sanitized, 1024)  # 1KB limit

        return sanitized

    def _apply_poison_filters(self, data: Any) -> Any:
        """Recursive poisoning filter"""
        if isinstance(data, dict):
            return {k: self._apply_poison_filters(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self._apply_poison_filters(item) for item in data]
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